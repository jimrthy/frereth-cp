(ns frereth-cp.message
  "Translation of curvecpmessage.c

  This is really a generic buffer program

  The \"parent\" child/server reads/writes to pipes that this provides,
  in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns.

  I keep wanting to think of this as a simple transducer and just
  skip the buffering pieces, but they (and the flow control) are
  really the main point."
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.from-child :as from-child]
            [frereth-cp.message.from-parent :as from-parent]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.to-child :as to-child]
            [frereth-cp.message.to-parent :as to-parent]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.executor :as exec]
            ;; This next reference should go away
            ;; Except...I *am* using it as part of
            ;; aleph. And, really, what alternatives
            ;; are available?
            ;; (agents and core.async seem to be the
            ;; best)
            [manifold.stream :as strm])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def max-child-buffer-size
  "Maximum message blocks from parent to child that we'll buffer before dropping

  must be power of 2 -- DJB"
  64)

(def write-from-parent-timeout
  "milliseconds before we give up on writing a packet from parent to child"
  5000)

(def write-from-child-timeout
  "milliseconds before we give up on writing a packet from child to parent"
  5000)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal API

;;;; Q: what else is in the reference implementation?
;;;; A:
;;;; 186-654 main
;;;          186-204 boilerplate

;;;          260-263 set up some globals
;;;          264-645 main event loop
;;;          645-651 wait on children to exit
;;;          652-653 exit codes

;;; 264-645 main event loop
;;; 263-269: exit if done
;;; 271-306: Decide what and when to poll, based on global state

;;; This next piece seems like it deserves a prominent place.
;;; But, really, it needs to be deeply hidden from the end-programmer.
;;; I want it to be easy for me to change out and swap around, but
;;; that means no one else should ever really even need to know that
;;; it happens (no matter how vital it obviously is)
;;; 307-318: Poll for incoming data
;;;     317 XXX: keepalives

;;;
;;;
;;;
;;;  634-643: try closing pipe to child: (DJB)
;;;           Well, maybe. If we're done with it

;;; 444-609 handle this message if it's comprehensible: (DJB)
;;; (in more depth)
;;;         445-450: boilerplate
;;;         452-453: short-circuiting
;;;         455: extract ID
;;;         456-542: loop over range(blocknum)
;;;                  This looks like the "real" Chicago algorithm
;;;         544-560: Call acknowledged() several times
;;;                  This is for several byte ranges in the incoming message
;;;                  0 to the 8-byte offset starting at byte 8
;;;                  Then we have pairs of start/stop offsets
;;;                  where each start is from the previous stop
;;;                  This seems a bit tedious/inefficient, esp. since
;;;                  lines 396-401 seem to ignore everything except
;;;                  the blockid[pos] at position 8 (aka 0) and then
;;;                  positions 46 and 48.
;;;                  Those are really the length at position 38 and initial
;;;                  offset at position 40, thanks to starting the send
;;;                  with length/16 at offset 7.
;;;        589-593: increment the receivebytes count
;;;        595: never acknowledge a pure acknowledgment (DJB)
;;;             This short-circuits if something extracts to 0
;;;             (looks like this is the first of the message structure,
;;;             which would be the message ID)
;;;        597: /* XXX: delay acknowledgments */ (DJB)
;;;        598-608: Looks like this just ACKs everything
;;;                 Evidence:
;;;        606: /* XXX: incorporate selective acknowledgents */ (DJB)

;;; 456-542: Loop over (range blocknum)
;;; (getting into details)

(s/fdef start-event-loops!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn start-event-loops!
  "This still needs to set up timers...which are going to be interesting.
;;;          205-259 fork child
"
  [{:keys [::specs/callbacks]
    :as state}]
  ;; At its heart, the reference implementation message event
  ;; loop is driven by a poller.
  ;; That checks for input on:
  ;; fd 8 (from the parent)
  ;; tochild[1] (to child)
  ;; fromchild[0] (from child)
  ;; and a timeout (based on the messaging state).

  ;; I want to keep any sort of deferred/async details
  ;; as well-hidden as possible.
  ;; This is a boundary piece that almost seems tailor-made.
  ;; Although I really do need to figure out what makes sense
  ;; as "buffer size."
  ;; And it might make a lot of sense to spread it farther
  ;; than I'm using it now to try to take advantage of
  ;; the transducer capabilities.
  ;; By the same token, it's very tempting to just use
  ;; a core.async channel instead.
  ;; The only reason I'm not now is that I already have
  ;; access to manifold thanks to aleph, and I don't want
  ;; to restart my JVM to update build.boot to get access
  ;; to core.async.
  (assoc state
         ;; This covers line 260
         ::specs/recent (System/nanoTime)))

(s/fdef trigger-io
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn trigger-io
  [{{:keys [::specs/->child]} ::specs/incoming
    :as state}]
  (log/debug "Triggering I/O")
  ;; I think I've figured out the problem with my
  ;; echo test:
  ;; After we deliver a message to the child,
  ;; we end up back here. It (presumably)
  ;; sends a block to the parent and then
  ;; tries to process another from-parent
  ;; message.
  ;; There's still a message in the child
  ;; buffer (because apparently that didn't
  ;; get cleaned out), but it there is no
  ;; incoming message for it to handle.
  ;; So we're calling (->child nil)

  (let [state
        (-> state
            (assoc ::specs/recent (System/nanoTime))
            ;; This doesn't seem to be working
            ;; FIXME: Start back here.
            ;; Q: What are the odds that I've screwed up
            ;; the state nesting again?
            to-parent/maybe-send-block!)
        state (or (from-parent/try-processing-message! state)
                  state)]
    (to-child/forward! ->child state)
    ;; At the end of the main ioloop in the refernce
    ;; implementation, there's a block that closes the pipe
    ;; to the child if we're done.
    ;; I think the point is that we'll quit polling on
    ;; that and start short-circuiting out of the blocks
    ;; that might do the send, once we've hit EOF
    ;; Q: is there anything sensible I can do here to
    ;; produce the same effect?
    ))

(s/fdef trigger-from-child
        :args (s/cat :state ::specs/state
                     :array-o-bytes bytes?)
        :ret ::specs/state)
(defn trigger-from-child
  [state array-o-bytes]
  (log/debug "trigger-from-child: Received a" (class array-o-bytes))
  (trigger-io
   (if (from-child/room-for-child-bytes? state)
     (do
       (log/debug "There is room for another message")
       (from-child/child-consumer state array-o-bytes))
     ;; trigger-io does some state management, even
     ;; if we discard the buffer
     state)))

(defn trigger-from-parent
  "Message block arrived from parent. We have work to do."
  ;; TODO: Move as much of this as possible into from-parent
  ;; The only reason I haven't already moved the whole thing
  ;; is that we need to use to-parent to send the ACK, and I'd
  ;; really rather not introduce dependencies between those namespaces
  [{{:keys [::specs/->child]} ::specs/incoming
    :as state}
   ^bytes buf]
  (when-not ->child
    (throw (ex-info "Missing ->child"
                    {::callbacks (::specs/callbacks state)})))
  ;; This is basically an iteration of the top-level
  ;; event-loop handler from main().
  ;; I can skip the pieces that only relate to reading
  ;; from the child, because I'm using an active callback
  ;; approach, and this was triggered by a block of
  ;; data coming from the parent.

  (let [ready-to-ack (-> state
                         ;; Q: Are the next 2 lines worth their own functions?
                         (assoc-in [::specs/incoming ::specs/parent->buffer] buf)
                         ;; This one really seems so, since I'm calling it
                         ;; in at least 3 different places now
                         (assoc ::specs/recent (System/nanoTime))
                         ;; This is about sending from the child to parent
                         ;; (No, that isn't why we're here, but it doesn't
                         ;; hurt to check whether another block is
                         ;; sendable)
                         to-parent/maybe-send-block!
                         ;; Next obvious piece is the "try receiving messages:"
                         ;; block.
                         ;; But I've already changed the order of operations by
                         ;; doing that up front in parent->, which is what called
                         ;; this.
                         ;; Now that I'm going back through the big-picture items,
                         ;; that decision seems less valid than it did when I was
                         ;; staring at each tree in the forest.
                         ;; It probably doesn't matter, but I've dealt with enough
                         ;; subtleties in the original code that I'm very nervous
                         ;; about that "probably"
                         ;; OTOH, this leaves everything that follows pleasingly
                         ;; duplicated (and ripe for refactoring) with trigger-from-timer
                         ;; and trigger-from-child
                         )]
    (log/info "Getting ready to start trying to process the message we just received from parent:\n"
              ready-to-ack)
    (if-let [primed (from-parent/try-processing-message! ready-to-ack)]
      (do
        (log/debug "Message processed. Trying to forward to child")
        (to-child/forward! ->child primed))
      (do
        ;; The message from parent to child was garbage.
        ;; Discard.
        ;; Q: Does this make sense?
        ;; It leaves our "global" state updated in a way that left us unable
        ;; to send earlier. That isn't likely to get fixed the next time
        ;; through the event loop.
        ;; (I'm hitting this because I'm sending a gibberish message that
        ;; needs to be discarded)
        (throw (RuntimeException. "How does DJB really handle this discard?"))
        ready-to-ack))))

(defn trigger-from-timer
  [state]
  (trigger-io state))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef initial-state
        :args (s/cat :parent-callback ::specs/->parent
                     :child-callback ::specs/->child
                     ;; Q: What's the difference to spec that this
                     ;; argument is optional?
                     :want-ping ::specs/want-ping)
        :ret ::specs/state-agent)
(defn initial-state
  "Put together an initial state that's ready to start!"
  ([parent-callback
    child-callback
    want-ping]
   (agent {::specs/flow-control {::specs/last-doubling 0
                                 ::specs/last-edge 0
                                 ::specs/last-speed-adjustment 0
                                 ;; Seems vital, albeit undocumented
                                 ::specs/n-sec-per-block K/sec->n-sec
                                 ::specs/rtt 0
                                 ::specs/rtt-average 0
                                 ::specs/rtt-deviation 0
                                 ::specs/rtt-highwater 0
                                 ::specs/rtt-lowwater 0
                                 ::specs/rtt-phase false
                                 ::specs/rtt-seen-older-high false
                                 ::specs/rtt-seen-older-low false
                                 ::specs/rtt-seen-recent-high false
                                 ::specs/rtt-seen-recent-low false
                                 ::specs/rtt-timeout K/sec->n-sec}
           ::specs/incoming {::specs/->child child-callback
                             ::specs/->child-buffer []
                             ::specs/gap-buffer (to-child/build-gap-buffer)
                             ::specs/receive-bytes 0
                             ::specs/receive-eof false
                             ::specs/receive-total-bytes 0
                             ::specs/receive-written 0
                             }
           ::specs/outgoing {::specs/blocks []
                             ::specs/earliest-time 0
                             ::specs/last-block-time 0
                             ::specs/last-panic 0
                             ;; Peers started as servers start out
                             ;; with standard-max-block-length instead.
                             ;; TODO: Account for that
                             ::specs/max-block-length K/initial-max-block-length
                             ::specs/next-message-id 1
                             ::specs/->parent parent-callback
                             ::specs/send-acked 0
                             ;; Q: Does this make any sense at all?
                             ;; It isn't ever going to change, so I might
                             ;; as well just use the hard-coded value
                             ;; in constants and not waste the extra time/space
                             ;; sticking it in here.
                             ;; That almost seems like premature optimization,
                             ;; but this approach seems like serious YAGNI.
                             ::specs/send-buf-size K/send-byte-buf-size
                             ::specs/send-bytes 0
                             ::specs/send-eof false
                             ::specs/send-eof-acked false
                             ::specs/send-eof-processed false
                             ::specs/send-processed 0
                             ::specs/total-blocks 0
                             ::specs/total-block-transmissions 0
                             ::specs/want-ping want-ping}

           ;; In the original, this is a local in main rather than a global
           ;; Q: Is there any difference that might matter to me, other
           ;; than being allocated on the stack instead of the heap?
           ;; (Assuming globals go on the heap. TODO: Look that up)
           ;; Ironically, this may be one of the few pieces that counts
           ;; as "global", since it really is involved whether we're
           ;; talking about incoming/outgoing buffer management or
           ;; flow control.
           ::specs/recent 0}))
  ([parent-callback child-callback]
   (initial-state parent-callback child-callback false)))

(s/fdef start!
        :args (s/cat :state ::specs/state-agent)
        :ret ::specs/state-agent)
(defn start!
  ([state-agent timeout]
   (send state-agent start-event-loops!)
   (if (await-for timeout state-agent)
     state-agent
     (throw (ex-info "Starting failed"
                     {::problem (agent-error state-agent)}))))
  ([state-agent]
   (start! state-agent 250)))

(defn halt!
  [state]
  ;; TODO: Surely there's something
  state)

(s/fdef child->
        :args (s/cat :state-agent ::specs/state-agent
                     :buf ::specs/buf)
        :ret ::specs/state-agent)
(defn child->
  "Read bytes from a child buffer...if we have room

The only real question seems to be what happens
when that buffer overflows.

In the original, that buffer is really just an
anonymous pipe between the processes, so there
should be quite a lot of room.

According to the pipe(7) man page, linux provides
16 \"pages\" of buffer space. So 64K, if the page
size is 4K. At least, it has since 2.6.11.

Prior to that, it was limited to 4K.

;;;  319-336: Maybe read bytes from child
"
  [state-agent
   buf]
  ;; I'm torn about send vs. send-off here.
  ;; This very well *could* take a measurable amount
  ;; of time, and we could wind up with a ton of threads
  ;; if there's a lot of data flowing back and forth.
  ;; Note that the client count isn't a direct factor here,
  ;; since each client should receive its own agent.
  ;; This is something to watch and measure.
  ;; Go with send for now, since it's recommended for
  ;; CPU- (as opposed to IO-) bound actions.
  ;; And I don't think there's anything here that
  ;; could block.
  ;; Except for those actual pesky sends to the
  ;; child/parent, which are specifically forbidden
  ;; from blocking.
  (send state-agent trigger-from-child buf))

(s/fdef parent->
        :args (s/cat :state ::specs/state-agent
                     :buf bytes?)
        :ret ::specs/state-agent)
(defn parent->
  "Receive a byte array from parent

  411-435: try receiving messages: (DJB)

  The parent is going to call this. It should trigger
  the pieces that naturally fall downstream and lead
  to writing the bytes to the child.

  It's replacing one of the polling triggers that
  set off the main() event loop. Need to account for
  that fundamental strategic change"
  [state-agent
   ^bytes buf]
;;;           From parent (over watch8)
;;;           417-433: for loop from 0-bytes read
;;;                    Copies bytes from incoming message buffer to message[][]
  (let [incoming-size (count buf)]
    (when (= 0 incoming-size)
      ;; This is supposed to kill the entire process
      ;; TODO: Be more graceful
      (throw (AssertionError. "Bad Message")))

    ;; Reference implementation is really reading bytes from
    ;; a stream.
    ;; It reads the first byte to get the length of the block,
    ;; pulls the next byte from the stream, calculates the stream
    ;; length, double-checks for failure conditions, and then copies
    ;; the bytes into the last spot in the global message array
    ;; (assuming that array/buffer hasn't filled up waiting for the
    ;; client to process it).

    ;; I'm going to take a simpler and easier approach, at least for
    ;; the first pass.
    ;; Note that I've actually taken 2 approaches that, really, are
    ;; mutually exclusive.
    ;; trigger-from-parent is expecting to have a ::->child-buffer key
    ;; that's really a vector that we can just conj onto.
    (let [{{:keys [::specs/->child-buffer]} ::specs/incoming} state-agent]
      (if (< (count ->child-buffer) max-child-buffer-size)
        (let [previously-buffered-message-bytes (reduce + 0
                                                    (map (fn [^bytes buf]
                                                           (count buf))
                                                         ->child-buffer))]
          ;; Probably need to do something with previously-buffered-message-bytes.
          ;; Definitely need to check the number of bytes that have not
          ;; been forwarded along yet.
          ;; However, the reference implementation does not.
          ;; Then again...it's basically a self-enforcing
          ;; 64K buffer, so maybe it's already covered, and I just wasted
          ;; CPU cycles calculating it.
          (if (<= K/max-msg-len incoming-size)
            ;; See comments in child-> re: send vs. send-off
            (send state-agent trigger-from-parent buf)
            (do
              (log/warn (str "Child buffer overflow\n"
                             "Incoming message is " incoming-size
                             " / " K/max-msg-len))
              state-agent)))
        state-agent))))
