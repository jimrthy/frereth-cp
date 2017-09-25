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
            ;; most likely)
            [manifold.stream :as strm]
            [overtone.at-at :as at-at])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def default-agent-start-timeout
  "Milliseconds to wait for agent to finish startup sequence"
  250)

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

(defn choose-next-scheduled-time
  [{{:keys [::specs/n-sec-per-block
            ::specs/rtt-timeout]} ::specs/flow-control
    {:keys [::specs/->child-buffer
            ::specs/gap-buffer]} ::specs/incoming
    {:keys [::specs/blocks
            ::specs/earliest-time
            ::specs/last-block-time
            ::specs/send-bytes
            ::specs/send-eof
            ::specs/send-eof-processed
            ::specs/send-processed
            ::specs/want-ping]} ::specs/outgoing
    :keys [::specs/message-loop-name
           ::specs/recent]
    :as state}]
  ;; I should be able to just completely bypass this if there's
  ;; more new data pending.
  ;; TODO: Figure out how to make that work
  #_(throw (RuntimeException. "Start here"))
  ;; Bigger issue:
  ;; This scheduler is so aggressive at waiting for an initial
  ;; message from the child that it takes 10 ms for that agent
  ;; send to actually get through the queue
  (let [min-resend-time (+ last-block-time n-sec-per-block)
        _ (log/debug (str message-loop-name
                          ": Minimum resend time: " min-resend-time
                          " which is " n-sec-per-block
                          ;; last-block-time causes problems.
                          ;; Up until the point I've sent my
                          ;; last block, it basically progresses
                          ;; linearly up to 1907725432157608
                          ;; (for tonight's debug session).
                          ;; Then it jumps down to
                          ;; 1907725404755660, which leaves
                          ;; me with negative delays, because
                          ;; I'm trying to send the next send
                          ;; in the past.
                          ;; And doing this every millisecond
                          ;; leads to its own set of problems.
                          ;; FIXME: Start back here.
                          " nanoseconds after " last-block-time))
        default-next (+ recent (utils/seconds->nanos 60))
        _ (log/debug (str message-loop-name
                          ": Default +1 minute: "
                          default-next
                          " from "
                          recent))
        ;; Lines 286-289
        _ (log/debug (str message-loop-name ": Scheduling based on want-ping value '" want-ping "'"))
        next-based-on-ping (if want-ping
                             ;; Go with the assumption that this matches wantping 1 in the original
                             ;; I think the point there is for the
                             ;; client to give the server 1 second to start up
                             (if (= want-ping ::specs/second-1)
                               (+ recent utils/seconds->nanos 1)
                               (min default-next min-resend-time))
                             default-next)
        _ (log/debug (str message-loop-name
                          ": Based on ping settings, adjusted next time to: "
                          next-based-on-ping))
        ;; Lines 290-292
        next-based-on-eof (if (and (< (count blocks) K/max-outgoing-blocks)
                                   (if send-eof
                                     (not send-eof-processed)
                                     (< send-processed send-bytes)))
                            (min next-based-on-ping min-resend-time)
                            next-based-on-ping)
        _ (log/debug (str message-loop-name
                          ": Due to EOF status: "
                          next-based-on-eof))
        ;; Lines 293-296
        rtt-resend-time (+ earliest-time rtt-timeout)
        next-based-on-earliest-block-time (if (and (not= 0 earliest-time)
                                                   (> rtt-resend-time
                                                      min-resend-time))
                                            (min next-based-on-eof rtt-resend-time)
                                            next-based-on-eof)
        _ (log/debug (str message-loop-name
                          ": Adjusted for RTT: "
                          next-based-on-earliest-block-time))
        ;; There's one last caveat, from 298-300:
        ;; It all swirls around watchtochild, which gets set up
        ;; between lines 276-279.
        ;; It's convoluted enough that I don't want to try to dig into it tonight
        watch-to-child "There's a lot involved in this decision"
        based-on-closed-child (if (and (not= 0 (+ (count gap-buffer)
                                                  (count ->child-buffer)))
                                       (nil? watch-to-child))
                                0
                                next-based-on-earliest-block-time)
        _ (log/debug (str message-loop-name
                          ": After adjusting for closed/ignored child watcher: "
                          based-on-closed-child))
        ;; Lines 302-305
        actual-next (max based-on-closed-child recent)]
    actual-next))

(declare trigger-from-timer)
(defn schedule-next-timeout!
  [{:keys [::specs/message-loop-name
           ::specs/recent]
    {:keys [::specs/next-action
            ::specs/schedule-pool]
     :as flow-control} ::specs/flow-control
    :as state}
   state-agent]
  {:pre [recent]}
  (log/debug (str message-loop-name ": Top of scheduler"))
  (if (not= next-action ::completed)
    (do
      (let [actual-next (choose-next-scheduled-time state)
            now (System/nanoTime)
            ;; It seems like it would make more sense to have the delay happen from
            ;; "now" instead of "recent"
            ;; Doing that throws lots of sand into the gears.
            ;; Stick with this approach for now, because it *does*
            ;; match the reference implementation.
            ;; Although, really, it seems very incorrect.
            scheduled-delay (- actual-next recent)
            _ (log/debug (str message-loop-name
                              ": Initially calculated scheduled delay: "
                              scheduled-delay
                              " nanoseconds after "
                              recent
                              " vs. "
                              now))
            delta-nanos (max 0 scheduled-delay)
            delta (inc (utils/nanos->millis delta-nanos))
            next-action (at-at/after delta
                                     (fn []
                                       (send-off state-agent (partial trigger-from-timer state-agent)))
                                     schedule-pool
                                     :desc "Periodic wakeup")]
        (log/debug (str message-loop-name
                        ": Timer set to trigger in "
                        (float delta)
                        " ms (vs "
                        (float (utils/nanos->millis scheduled-delay))
                        " scheduled)"))
        (-> state
            (assoc-in [::specs/flow-control ::specs/next-action] next-action))))
    (do
      (log/debug (str message-loop-name ": 'next-action' flagged complete."))
      state)))

(s/fdef start-event-loops!
        :args (s/cat :state-agent ::specs/state-agent
                     :state ::specs/state)
        :ret ::specs/state)
(defn start-event-loops!
  "This still needs to set up timers...which are going to be interesting.
;;;          205-259 fork child
"
  [state-agent
   state]
  ;; At its heart, the reference implementation message event
  ;; loop is driven by a poller.
  ;; That checks for input on:
  ;; fd 8 (from the parent)
  ;; tochild[1] (to child)
  ;; fromchild[0] (from child)
  ;; and a timeout (based on the messaging state).
  (let [recent (System/nanoTime)]
    (-> state
        (assoc
         ;; This covers line 260
         ::specs/recent recent)
        (schedule-next-timeout! state-agent))))

(s/fdef trigger-io
        :args (s/cat :state-agent ::specs/state-agent
                     :state ::specs/state)
        :ret ::specs/state)
(defn trigger-io
  [state-agent
   {{:keys [::specs/->child]} ::specs/incoming
    {:keys [::specs/next-action]} ::specs/flow-control
    :keys [::specs/message-loop-name]
    :as state}]
  (log/debug (str message-loop-name ": Triggering I/O"))
  (when (not= next-action ::completed)
    ;; It would be nice to have a way to check
    ;; whether this is what triggered us. If
    ;; so, there's no reason to stop it.
    ;; Go with the assumption that this is
    ;; light-weight enough that it doesn't matter.
    (at-at/stop next-action)
    (log/debug (str message-loop-name ": Current next action cancelled")))
  (let [state
        (as-> state state
            (assoc state ::specs/recent (System/nanoTime))
            (to-parent/maybe-send-block! state)
            ;; The message from parent to child was garbage.
            ;; Discard.
            ;; Q: Does this make sense?
            ;; It leaves our "global" state updated in a way that left us unable
            ;; to send earlier. That isn't likely to get fixed the next time
            ;; through the event loop.
            ;; (I'm hitting this because I'm sending a gibberish message that
            ;; needs to be discarded)

            ;; It seems like I should be able to skip this if we got triggered
            ;; by anything except an incoming message from the parent.
            ;; That is misleading. We still need to cope with any messages
            ;; from the parent that haven't been written to the child yet.
            ;; And, realistically, we *should* cope with message blocks that
            ;; have only partially been written
            (or (from-parent/try-processing-message! state)
                state)
            (to-child/forward! ->child state))]
    ;; At the end of the main ioloop in the refernce
    ;; implementation, there's a block that closes the pipe
    ;; to the child if we're done.
    ;; I think the point is that we'll quit polling on
    ;; that and start short-circuiting out of the blocks
    ;; that might do the send, once we've hit EOF
    ;; Q: What can I do here to
    ;; produce the same effect?

    ;; If the child sent a big batch of data to go out
    ;; all at once, don't waste time setting up a timeout
    ;; scheduler. The poll in the original would have
    ;; returned immediately anyway.
    ;; Except that n-sec-per-block puts a hard limit on how
    ;; fast we can send.
    (comment
      (let [unsent-blocks-from-child? (from-child/blocks-not-sent? state)]
        (if unsent-blocks-from-child?
          (recur state)
          (schedule-next-timeout! state))))
    (log/debug (str message-loop-name ": Scheduling next timeout"))
    (schedule-next-timeout! state state-agent)))

(s/fdef trigger-from-child
        :args (s/cat :state-agent ::specs/state-agent
                     :state ::specs/state
                     :array-o-bytes bytes?)
        :ret ::specs/state)
(defn trigger-from-child
  [state-agent
   {{:keys [::specs/send-bytes]
     :as outgoing} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}
   array-o-bytes]
  (log/debug (str "trigger-from-child: "
                  message-loop-name
                  ": Received a "
                  (class array-o-bytes)
                  "\nSent stream address: "
                  send-bytes))
  (when-not send-bytes
    (log/error (str message-loop-name
                    ": Missing ::specs/send-bytes under"
                    (keys outgoing)
                    "inside"
                    (keys state)
                    "\na.k.a.\n"
                    state)))
  (trigger-io
   state-agent
   (if (from-child/room-for-child-bytes? state)
     (do
       (log/debug (str message-loop-name ": There is room for another message"))
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
  [state-agent
   {{:keys [::specs/->child]} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}
   ^bytes buf]
  (when-not ->child
    (throw (ex-info "Missing ->child"
                    {::callbacks (::specs/callbacks state)})))
  (log/info (str message-loop-name ": Incoming from parent"))
  ;; This is basically an iteration of the top-level
  ;; event-loop handler from main().
  ;; I can skip the pieces that only relate to reading
  ;; from the child, because I'm using an active callback
  ;; approach, and this was triggered by a block of
  ;; data coming from the parent.

  ;; However, there *is* the need to handle packets that the
  ;; child has buffered up to send to the parent.
  (trigger-io state-agent
              (assoc-in state [::specs/incoming ::specs/parent->buffer] buf)))

(defn trigger-from-timer
  [state-agent
   {:keys [::specs/message-loop-name]
    :as state}]
  (log/debug (str message-loop-name ": I/O triggered by timer"))
  ;; I keep thinking that I need to check data arriving from
  ;; the child, but the main point to this logic branch is
  ;; to resend an outbound block that hasn't been ACK'd yet.
  (trigger-io state-agent state))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef initial-state
        :args (s/cat :human-name ::specs/message-loop-name
                     :parent-callback ::specs/->parent
                     :child-callback ::specs/->child
                     ;; Q: What's the difference to spec that this
                     ;; argument is optional?
                     :want-ping ::specs/want-ping)
        :ret ::specs/state-agent)
(defn initial-state
  "Put together an initial state that's ready to start!"
  ([human-name
    parent-callback
    child-callback
    server?]
   (agent {::specs/flow-control {::specs/last-doubling 0
                                 ::specs/last-edge 0
                                 ::specs/last-speed-adjustment 0
                                 ;; Seems vital, albeit undocumented
                                 ::specs/n-sec-per-block K/sec->n-sec
                                 ::specs/next-action nil
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
                                 ::specs/rtt-timeout K/sec->n-sec
                                 ::specs/schedule-pool (at-at/mk-pool)}
           ::specs/incoming {::specs/->child child-callback
                             ::specs/->child-buffer []
                             ::specs/gap-buffer (to-child/build-gap-buffer)
                             ::specs/receive-bytes 0
                             ::specs/receive-eof false
                             ::specs/receive-total-bytes 0
                             ::specs/receive-written 0}
           ::specs/outgoing {::specs/blocks []
                             ::specs/earliest-time 0
                             ::specs/last-block-time 0
                             ::specs/last-panic 0
                             ;; Peers started as servers start out
                             ;; with standard-max-block-length instead.
                             ;; TODO: Account for that
                             ::specs/max-block-length (if server?
                                                        K/standard-max-block-length
                                                        K/initial-max-block-length)
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
                             ::specs/want-ping (if server?
                                                 false
                                                 ;; TODO: Add option for a
                                                 ;; client that started before the
                                                 ;; server, meaning that it waits
                                                 ;; for 1 second at a time before
                                                 ;; trying to send the next
                                                 ;; message
                                                 ::specs/immediate)}

           ::specs/message-loop-name human-name
           ;; In the original, this is a local in main rather than a global
           ;; Q: Is there any difference that might matter to me, other
           ;; than being allocated on the stack instead of the heap?
           ;; (Assuming globals go on the heap. TODO: Look that up)
           ;; Ironically, this may be one of the few pieces that counts
           ;; as "global", since it really is involved whether we're
           ;; talking about incoming/outgoing buffer management or
           ;; flow control.
           ::specs/recent 0}))
  ([human-name parent-callback child-callback]
   (initial-state human-name parent-callback child-callback false)))

(s/fdef start!
        :args (s/cat :state ::specs/state-agent)
        :ret ::specs/state-agent)
(defn start!
  ([state-agent timeout]
   (send state-agent (partial start-event-loops! state-agent))
   (if (await-for timeout state-agent)
     state-agent
     (throw (ex-info "Starting failed"
                     {::problem (agent-error state-agent)}))))
  ([state-agent]
   (start! state-agent default-agent-start-timeout)))

(defn close!
  "Flush buffer and send EOF"
  [state-agent]
  ;; Actually, I don't think there's any "flush buffer" concept
  ;; Though there probably should be
  (throw (RuntimeException. "Q: How should this work?")))

(defn halt!
  [state-agent]
  (let [{{:keys [::specs/next-action]
          :as flow-control} ::specs/flow-control
         :as state} @state-agent]
    (when next-action
      (log/info "Stopping scheduler")
      (at-at/stop next-action))
    (update-in state [::specs/flow-control ::specs/next-action]
               (constantly ::completed))))

(s/fdef child->
        :args (s/cat :state-agent ::specs/state-agent
                     :array-o-bytes bytes?)
        :ret ::specs/state-agent)
(defn child->
  "Read bytes from a child buffer...if we have room"
  ;; The only real question seems to be what happens
  ;; when that buffer overflows.

  ;; In the original, that buffer is really just an
  ;; anonymous pipe between the processes, so there
  ;; should be quite a lot of room.

  ;; According to the pipe(7) man page, linux provides
  ;; 16 \"pages\" of buffer space. So 64K, if the page
  ;; size is 4K. At least, it has since 2.6.11.

  ;; Prior to that, it was limited to 4K.

;;;  319-336: Maybe read bytes from child
  [state-agent
   array-o-bytes]
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
  (let [state @state-agent
        {{:keys [::specs/next-action]} ::specs/flow-control
         :keys [::specs/message-loop-name]} state]
    (log/debug (str message-loop-name
                    ": Incoming message from child to\n"
                    state))
    (when next-action
      ;; Altering the agent's state outside the agent like this
      ;; is wrong on pretty much every level.
      ;; But I'm seeing at least 1 timer loop go through before
      ;; this can, and that's wasting 9-10 ms.
      (log/info (str message-loop-name ": cancelling I/O timer"))
      (at-at/stop next-action))
    (send state-agent (partial trigger-from-child state-agent) array-o-bytes)))

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
          (if (<= incoming-size K/max-msg-len)
            ;; See comments in child-> re: send vs. send-off
            (send state-agent (partial trigger-from-parent state-agent) buf)
            (do
              (log/warn (str "Child buffer overflow\n"
                             "Incoming message is " incoming-size
                             " / " K/max-msg-len))
              state-agent)))
        state-agent))))
