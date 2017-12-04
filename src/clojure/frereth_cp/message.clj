(ns frereth-cp.message
  "Translation of curvecpmessage.c

  This is really a generic buffer program

  The \"parent\" child/server reads/writes to pipes that this provides,
  in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns.

  I keep wanting to think of this as a simple transducer and just
  skip the buffering pieces, but they (and the flow control) are
  really the main point."
  (:require [clojure.pprint :refer (cl-format)]
            [clojure.spec.alpha :as s]
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
            [manifold.stream :as strm])
  (:import [clojure.lang ExceptionInfo IDeref PersistentQueue]
           [io.netty.buffer ByteBuf Unpooled]
           [java.io IOException PipedInputStream PipedOutputStream]
           java.util.concurrent.TimeoutException))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def child-buffer-timeout
  "How long might we block child->"
  ;; This is far too long. Unfortunately, my event loop
  ;; is currently very slow.
  1000)

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
;;; Specs

(s/def ::source-tags #{::child-> ::parent-> ::query-state})
(s/def ::input (s/tuple ::source-tags bytes?))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal API

(defn build-un-ackd-blocks
  []
  (sorted-set-by (fn [x y]
                   (let [x-time (::specs/time x)
                         y-time (::specs/time y)]
                     (if (= x-time y-time)
                       ;; Assume that we never have multiple messages with the
                       ;; same timestamp.
                       ;; We do hit this case when disj is trying to
                       ;; remove an existing block.
                       0
                       (if (< x-time y-time)
                         -1
                         1))))))

;;;; Q: what else is in the reference implementation?
;;;; A: Lots. Scattered around quite a bit now
;;;; 186-654 main
;;;          186-204 boilerplate

;;;          260-263 set up some globals
;;;          264-645 main event loop
;;;          645-651 wait on children to exit
;;;          652-653 exit codes

;;; 264-645 main event loop
;;;     263-269: exit if done
;;;     271-306: Decide what and when to poll, based on global state

;;; This next piece seems like it deserves a prominent place.
;;; But, really, it needs to be deeply hidden from the end-programmer.
;;; I want it to be easy for me to change out and swap around, but
;;; that means no one else should ever really even need to know that
;;; it happens (no matter how vital it obviously is)
;;;     307-318: Poll for incoming data
;;;         317 XXX: keepalives

;;;     444-609 handle this message if it's comprehensible: (DJB)
;;;     (in more depth)
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

;;;     634-643: try closing pipe to child: (DJB)
;;;         Well, maybe. If we're done with it

(s/fdef trigger-output
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        :ret ::specs/state)
(defn trigger-output
  [{:keys [::specs/to-child]
    :as io-handle}
   {{:keys [::specs/next-action]} ::specs/flow-control
    :keys [::specs/message-loop-name]
    :as state}]
  (let [prelog (utils/pre-log message-loop-name)]
    ;; I have at least 1 unit test that receives input
    ;; from parent, forwards that to child, then
    ;; echoes it back.
    ;; Then it calls trigger-output, doesn't find
    ;; anything ready to go, loops back to polling
    ;; for events, finds the message the child
    ;; just queued, and starts over.
    ;; It's very tempting to try to account for
    ;; that scenario here, but it would involve
    ;; enough extra stateful contortions (we'd
    ;; have to peek
    (log/debug prelog "Possibly sending message to parent")
    ;; This is a scenario when it seems like it would
    ;; be nice to be able to peek into io-handle's stream.
    ;; If a message from the child just got buffered, it
    ;; would be nice to move it from there into the outbound
    ;; queue.
    ;; Actually, there's probably a useful clue right there:
    ;; It would be nice to have 1 queue for the outer API,
    ;; which is what schedule-next-event! is looping around.
    ;; And then multiple queues for the specifics, like
    ;; incoming from child vs. parent vs. a timeout triggering
    ;; a resend.
    ;; Maybe in a future version.

    ;; It doesn't seem to make any sense to call this if
    ;; we were triggered by a message coming in from
    ;; the parent.

    ;; Even if there pending blocks are ready to
    ;; send, outgoing messages are throttled by
    ;; the flow-control logic.

    ;; Likewise, there isn't a lot of sense in
    ;; calling it from the child, due to the same
    ;; throttling issues.

    ;; This really only makes sense when the
    ;; timer triggers to let us know that it's
    ;; OK to send a new message.

    ;; *However*:
    ;; The timeout on that may completely change
    ;; when the child schedules another send,
    ;; or a message arrives from parent to
    ;; update the RTT.

    ;; I've seen this happen: child sends two
    ;; messages in quick succession. We refuse
    ;; to send the second until the first gets
    ;; an ACK. Once the ACK does arrive, then
    ;; this can send the second without going
    ;; through the scheduling process again.
    ;; At the moment, that part's slow enough
    ;; for this to be a noticeable win.
    (to-parent/maybe-send-block! io-handle
                                 (assoc state
                                        ::specs/recent
                                        (System/nanoTime)))))

(s/fdef trigger-from-child
        :args (s/cat :io-handle ::specs/io-handle
                     :callback (s/fspec :args (s/cat :state ::specs/state)
                                        :ret ::specs/state)
                     :accepted? dfrd/deferrable?
                     :state ::specs/state)
        :ret ::specs/state)
(defn trigger-from-child
  [io-handle
   callback
   ^IDeref accepted?
   {{:keys [::specs/strm-hwm]
     :as outgoing} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}]
  {:pre [callback]}
  (let [prelog (utils/pre-log message-loop-name)]
    (log/info prelog
              "trigger-from-child"
              "\nSent stream address:"
              strm-hwm)
    (deliver accepted? true)
    (let [state' (callback state)]
      ;; TODO: check whether we can do output now.
      ;; It's pointless to call this if we just have
      ;; to wait for the timer to expire.
      (trigger-output io-handle state'))))

(s/fdef trigger-from-parent
        :args (s/cat :io-handle ::specs/io-handle
                     :array-o-bytes bytes?
                     :specs/state ::specs/state)
        :ret ::specs/state)
(defn trigger-from-parent
  "Message block arrived from parent. Agent has been handed work"
  ;; TODO: Move as much of this as possible into from-parent
  ;; The only reason I haven't already moved the whole thing
  ;; is that we need to use to-parent to send the ACK, and I'd
  ;; really rather not introduce dependencies between those namespaces
  [{:keys [::specs/to-child
           ::specs/message-loop-name]
    :as io-handle}
   ^bytes message
   {{:keys [::specs/->child-buffer]} ::specs/incoming
    {:keys [::specs/client-waiting-on-response]} ::specs/flow-control
    :as state}]
  (let [prelog (utils/pre-log message-loop-name)]
    (when-not to-child
      (throw (ex-info (str prelog
                           "Missing to-child")
                      {::detail-keys (keys io-handle)
                       ::top-level-keys (keys state)
                       ::details state})))

    (log/debug prelog "Incoming from parent")

    ;; This is an important side-effect that permanently converts the
    ;; "mode" of the i/o loop that's pulling bytes from the child's
    ;; output pipe.
    ;; Now that we've gotten a response back, we can switch from
    ;; initiate packets to message packets, which effectively doubles
    ;; the signal bandwidth.
    (when-not (realized? client-waiting-on-response)
      (deliver client-waiting-on-response true))

;;;           From parent (over watch8)
;;;           417-433: for loop from 0-bytes read
;;;                    Copies bytes from incoming message buffer to message[][]
    (let [incoming-size (count message)]
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

      ;; trigger-from-parent is expecting to have a ::->child-buffer key
      ;; that's really a vector that we can just conj onto.
      (when-not state
        (log/warn prelog
                  ;; They're about to get worse
                  "nil state. Things went sideways recently"))

      (if (< (count ->child-buffer) max-child-buffer-size)
        ;; Q: Will ->child-buffer ever have more than one array?
        ;; It would be faster to skip the map/reduce
        ;; TODO: Try switching to the reducers version instead, to
        ;; run this in parallel
        (let [previously-buffered-message-bytes (reduce + 0
                                                        (map (fn [^bytes buf]
                                                               (try
                                                                 (count buf)
                                                                 (catch UnsupportedOperationException ex
                                                                   (throw (ex-info (str prelog
                                                                                        "Parent sent a "
                                                                                        (class buf)
                                                                                        " which isn't a B]")
                                                                                   {::cause ex})))))
                                                             ->child-buffer))]
          (log/debug prelog
                     "Have"
                     previously-buffered-message-bytes
                     "bytes in"
                     (count ->child-buffer)
                     " child buffers; possibly processing")
          ;; Probably need to do something with previously-buffered-message-bytes.
          ;; Definitely need to check the number of bytes that have not
          ;; been forwarded along yet.
          ;; However, the reference implementation does not.
          ;; Then again...it's basically a self-enforcing
          ;; 64K buffer, so maybe it's already covered, and I just wasted
          ;; CPU cycles calculating it.
          (if (<= incoming-size K/max-msg-len)
            (do
              ;; It's tempting to move as much as possible from here
              ;; into the (now defunct) agent handler.
              ;; That impulse seems wrong. Based on preliminary numbers,
              ;; any filtering I can do outside an an agent send is a win.
              ;; TODO: Now that the manifold version is working, revisit
              ;; that decision.
              (log/debug prelog
                         "Message is small enough. Look back here")
              ;; This is basically an iteration of the top-level
              ;; event-loop handler from main().
              ;; I can skip the pieces that only relate to reading
              ;; from the child, because I'm using an active callback
              ;; approach, and this was triggered by a block of
              ;; data coming from the parent.

              ;; However, there *is* the need to handle packets that the
              ;; child has buffered up to send to the parent.

              ;; Except that we can't do this here/now. That part's
              ;; limited by the flow-control logic (handled by the
              ;; timer) and the callbacks arriving from the child.
              ;; It seems like we probably should cancel/reschedule,
              ;; since whatever ACK just arrived might adjust the RTT
              ;; logic.
              (try
                (let [pre-processed (from-parent/try-processing-message!
                                     io-handle
                                     (assoc-in state
                                               [::specs/incoming ::specs/parent->buffer]
                                               message))
                      state' (to-child/forward! io-handle (or pre-processed
                                                            state))]
                  ;; This will update recent.
                  ;; In the reference implementation, that happens immediately
                  ;; after trying to read from the child.
                  ;; Q: Am I setting up any problems for myself by waiting
                  ;; this long?
                  ;; i.e. Is it worth doing that at the top of the trigger
                  ;; functions instead?
                  (trigger-output io-handle state'))
                (catch ExceptionInfo ex
                  (log/error ex
                             (str prelog
                                  "Details:\n"
                                  (utils/pretty (.getData ex)))))
                (catch RuntimeException ex
                  (log/error ex
                             prelog
                             "Trying to cope with a message arriving from parent"))))
            (do
              ;; This is actually pretty serious.
              ;; All sorts of things had to go wrong for us to get here.
              ;; TODO: More extensive error handling.
              ;; Actually, should probably add an optional client-supplied
              ;; error handler for situations like this
              (log/warn prelog
                        (str "Message too large\n"
                             "Incoming message is " incoming-size
                             " / " K/max-msg-len)))))
        (do
          ;; TODO: Need a way to apply back-pressure
          ;; to child
          (log/warn prelog
                    (str "Child buffer overflow\n"
                         "Have " (count ->child-buffer)
                         "/"
                         max-child-buffer-size
                         " messages buffered. Wait!")))))))

(defn trigger-from-timer
  [io-handle
   {:keys [::specs/message-loop-name]
    :as state}]
  ;; It's really tempting to move this to to-parent.
  ;; But (at least in theory) it could also trigger
  ;; output to-child.
  ;; So leave it be for now.
  (log/debug (utils/pre-log message-loop-name) "I/O triggered by timer")
  ;; I keep thinking that I need to check data arriving from
  ;; the child, but the main point to this logic branch is
  ;; to resend an outbound block that hasn't been ACK'd yet.
  (trigger-output io-handle state))

(s/fdef choose-next-scheduled-time
        :args (s/cat :state ::specs/state)
        :ret nat-int?)
(defn choose-next-scheduled-time
  [{{:keys [::specs/n-sec-per-block
            ::specs/rtt-timeout]} ::specs/flow-control
    {:keys [::specs/->child-buffer
            ::specs/gap-buffer]} ::specs/incoming
    {:keys [::specs/ackd-addr
            ::specs/earliest-time
            ::specs/last-block-time
            ::specs/send-eof
            ::specs/un-sent-blocks
            ::specs/un-ackd-blocks
            ::specs/want-ping]
     :as outgoing} ::specs/outgoing
    :keys [::specs/message-loop-name
           ::specs/recent]
    :as state}]
  ;;; This amounts to lines 286-305

  ;; I should be able to just completely bypass this if there's
  ;; more new data pending.
  ;; TODO: Figure out how to make that work

  ;; Bigger issue:
  ;; This scheduler is so aggressive at waiting for an initial
  ;; message from the child that it takes 10 ms for the agent
  ;; send about it to actually get through the queue
  ;; Spinning around fast-idling while I'm doing nothing is
  ;; stupid.
  ;; And it winds up scheduling into the past, which leaves
  ;; this triggering every millisecond.
  ;; We can get pretty good turn-around time in memory,
  ;; but this part...actually, if we could deliver a message
  ;; and get an ACK in the past, that would be awesome.
  ;; TODO: Be smarter about the timeout.
  (let [now (System/nanoTime)
        ;; TODO: Switch to the alt version using cond->
        ;; But first, see whether the performance diffence
        ;; goes away if I just eliminate all the logging
        min-resend-time (+ last-block-time n-sec-per-block)
        prelog (utils/pre-log message-loop-name)
        default-next (+ recent (utils/seconds->nanos 60))  ; by default, wait 1 minute
        ;; Lines 286-289
        next-based-on-ping (case want-ping
                             ::specs/false default-next
                             ::specs/immediate (min default-next min-resend-time)
                             ;; Go with the assumption that this matches wantping 1 in the original
                             ;; I think the point there is for the
                             ;; client to give the server 1 second to start up
                             ::specs/second-1 (+ recent (utils/seconds->nanos 1)))
        ;; Lines 290-292
        ;; Q: What is the actual point to this?
        ;; (the logic seems really screwy, but that's almost definitely
        ;; a lack of understanding on my part)
        ;; A: There are at least 3 different moving parts involved here
        ;; 1. Are there unsent blocks that need to be sent?
        ;; 2. Do we have previously sent blocks that might need to re-send?
        ;; 3. Have we sent an un-ACK'd EOF?
        un-ackd-count (count un-ackd-blocks)
        un-sent-count(count un-sent-blocks)
        send-eof-processed (to-parent/send-eof-buffered? outgoing)
        ;; Strange things happen once EOF gets set. This goes into
        ;; a much tighter loop, but we can't send messages that
        ;; quickly.
        ;; FIXME: Do a better job coordinating the scheduling.
        next-based-on-eof (if (and (< (+ un-ackd-count
                                         un-sent-count)
                                      K/max-outgoing-blocks)
                                   (if (not= ::specs/false send-eof)
                                     (not send-eof-processed)
                                     (< 0 un-sent-count)))
                            (min next-based-on-ping min-resend-time)
                            next-based-on-ping)
        ;; Lines 293-296
        rtt-resend-time (+ earliest-time rtt-timeout)
        ;; In the reference implementation, 0 for a block's time
        ;; means it's been ACK'd.
        ;; => if earliest-time for all blocks is 0, they've all been
        ;; ACK'd.
        ;; This is another place where I'm botching that.
        ;; I've started relying on a ::ackd? flag in each block
        ;; instead.
        ;; But calculating earliest-time based on that isn't working
        ;; the way I expect/want.
        next-based-on-earliest-block-time (if (and (not= 0 un-ackd-count)
                                                   (> rtt-resend-time
                                                      min-resend-time))
                                            (min next-based-on-eof rtt-resend-time)
                                            next-based-on-eof)
        ;; There's one last caveat, from 298-300:
        ;; It all swirls around watchtochild, which gets set up
        ;; between lines 276-279.
        ;; It's convoluted enough that I don't want to try to dig into it tonight
        ;; It looks like the key to this is whether the pipe to the child
        ;; is still open.
        ;; Note that switching to PipedI/OStreams should have made this easier.
        ;; Or possibly more complex, since there isn't a (closed?) method.
        ;; Basic point:
        ;; If there are incoming messages, but the pipe to child is closed,
        ;; short-circuit so we can exit.
        ;; TODO: figure out a good way to replicate this.
        watch-to-child "FIXME: Is there a good way to test for this?"
        based-on-closed-child (if (and (not= 0 (+ (count gap-buffer)
                                                  (count ->child-buffer)))
                                       (nil? watch-to-child))
                                0
                                next-based-on-earliest-block-time)
        ;; Lines 302-305
        actual-next (max based-on-closed-child recent)
        mid1-time (System/nanoTime)
        log-message (cl-format nil
                               (str "Minimum send time: ~:d\n"
                                    "which is ~:d nanoseconds\n"
                                    "after last block time ~:d.\n"
                                    "Recent was ~:d ns in the past")
                               min-resend-time
                               n-sec-per-block
                               ;; I'm calculating last-block-time
                               ;; incorrectly, due to a misunderstanding
                               ;; about the name.
                               ;; It should really be the value of
                               ;; recent, set immediately after
                               ;; I send a block to parent.
                               last-block-time
                               (- now recent))
        log-message (str log-message (cl-format nil
                                                "\nDefault +1 minute: ~:d from ~:d\nScheduling based on want-ping value ~a"
                                                default-next
                                                recent
                                                want-ping))
        log-message (str log-message (cl-format nil
                                                "\nBased on ping settings, adjusted next time to: ~:d"
                                                next-based-on-ping))
        log-message (str log-message
                         "\nEOF/unsent criteria:\nun-ackd-count: "
                         un-ackd-count
                         "\nun-sent-count: "
                         un-sent-count
                         "\nsend-eof: "
                         send-eof
                         "\nsend-eof-processed: "
                         send-eof-processed
                         (cl-format nil
                                    "\nDue to EOF status: ~:d"
                                    next-based-on-eof))
        log-message (str log-message
                     (cl-format nil
                                "\nAdjusted for RTT: ~:d"
                                next-based-on-earliest-block-time))
        log-message (str log-message
                         (cl-format nil
                                    "\nAfter [pretending to] adjusting for closed/ignored child watcher: ~:d"
                                    based-on-closed-child))
        mid2-time (System/nanoTime)
        un-ackd-count (count un-ackd-blocks)
        alt (cond-> default-next
              (= want-ping ::specs/second-1) (+ recent (utils/seconds->nanos 1))
              (= want-ping ::specs/immediate) (min min-resend-time)
              ;; If the outgoing buffer is not full
              ;; And:
              ;;   If sendeof, but not sendeofprocessed
              ;;   else (!sendeof):
              ;;     if there are buffered bytes that have not been sent yet
              (let [un-sent-count(count un-sent-blocks)]
                (and (< (+ un-ackd-count
                           un-sent-count)
                        K/max-outgoing-blocks)
                     (if (not= ::specs/false send-eof)
                       (not send-eof-processed)
                       (< 0 un-sent-count)))) (min min-resend-time)
              (and (not= 0 un-ackd-count)
                   (>= rtt-resend-time
                       min-resend-time)) (min rtt-resend-time))
        end-time (System/nanoTime)]
    (log/debug prelog "Scheduling considerations\n" log-message)
    (when-not (= actual-next alt)
      (log/warn prelog
                "Scheduling Mismatch!"))
    (log/debug prelog
               ;; alt approach seems ~4 orders of magnitude
               ;; faster.
               ;; Q: Is that due to reduced logging?
               (cl-format nil (str "Calculating next scheduled time took"
                                   " ~:d nanoseconds and calculated ~:d."
                                   "\nBuilding the messages about this took ~:d nanoseconds"
                                   "\nAlt approach took ~:d and calculated ~:d")
                          (- mid1-time now)
                          actual-next
                          (- mid2-time mid1-time)
                          (- end-time mid2-time)
                          alt))
    actual-next))

(declare schedule-next-timeout!)
(defn action-trigger
  [{:keys [::actual-next
           ::delta_f
           ::scheduling-time]
    :as timing-details}
   {:keys [::specs/message-loop-name]
    :as io-handle}
   state
   ;; This is a variant that consists of a [tag callback] pair
   ;; It's tempting to destructure this here.
   ;; That makes the code a little more concise,
   ;; and easier to read. But it also makes
   ;; error handling more difficult.
   ;; I've had enough trouble getting and keeping
   ;; this correct that I want to retain this more
   ;; verbose approach, at least until the entire
   ;; thing settles down a bit.
   ;; Besides, I don't actually know what's in
   ;; success until I check the tag.
   ;; So I could destructure it here as [tag & args],
   ;; then destructure args later. But that makes
   ;; it less obviously a win.
   success]
  (let [prelog (utils/pre-log message-loop-name)  ; might be on a different thread
        fmt (str "Awakening event loop that was sleeping for ~:d ms "
                 "after ~:d at ~:d\n"
                 "at ~:d because: ~a")
        now (System/nanoTime)
        ;; Line 337
        ;; Doing this now instead of after trying to receive data from the
        ;; child seems like a fairly significant change from the reference
        ;; implementation.
        ;; TODO: Compare with other higher-level implementations
        ;; TODO: Ask cryptographers and protocol experts whether this is
        ;; a choice I'll really regret
        state (assoc state ::specs/recent now)]
    (log/debug prelog
               (cl-format nil
                          fmt
                          delta_f
                          scheduling-time
                          actual-next
                          now
                          success))
    (let [tag (try (first success)
                   (catch IllegalArgumentException ex
                     (log/error ex
                                prelog
                                "Should have been a variant")
                     ::no-op))
          updater
          ;; Q: Is this worth switching to something like core.match or a multimethod?
          (case tag
            ::specs/child-> (let [[_ callback ack] success]
                              (partial trigger-from-child io-handle callback ack))
            ::drained (do (log/warn prelog
                                    ;; Actually, this seems like a strong argument for
                                    ;; having a pair of streams. Child could still have
                                    ;; bytes to send to the parent after the latter's
                                    ;; stopped sending, or vice versa.
                                    ;; I'm pretty sure the complexity I haven't finished
                                    ;; translating stems from that case.
                                    ;; TODO: Another piece to revisit once the basics
                                    ;; work.
                                    "Stream closed. Surely there's more to do")
                          (constantly nil))
            ::parent-> (partial trigger-from-parent
                                io-handle
                                (second success))
            ::no-op identity
            ;; This can throw off the timer, since we're basic the delay on
            ;; the delta from recent (which doesn't change) rather than now.
            ;; But we're basing the actual delay from now, which does change.
            ;; e.g. If the scheduled delay is 980 ms, and someone triggers a
            ;; query-state that takes 20 ms after 20 ms, the new delay will
            ;; still be 980 ms rather than the 940 that would have been
            ;; appropriate.
            ;; Q: What's the best way to avoid this?
            ::query-state (fn [state]
                            (if-let [dst (second success)]
                              (deliver dst state)
                              (log/warn prelog "state-query request missing required deferred"))
                            state)
            ::timed-out (do
                          (log/debug prelog
                                     (cl-format nil
                                                "Timer for ~:d ms after ~:d timed out. Re-triggering Output"
                                                delta_f
                                                scheduling-time))
                          (partial trigger-from-timer io-handle)))]
      (when (not= tag ::drained)
        (log/debug prelog "Processing event:" tag)
        ;; At the end of the main ioloop in the refernce
        ;; implementation, there's a block that closes the pipe
        ;; to the child if we're done.
        ;; I think the point is that we'll quit polling on
        ;; that and start short-circuiting out of the blocks
        ;; that might do the send, once we've hit EOF
        ;; Q: What can I do here to
        ;; produce the same effect?
        ;; TODO: Worry about that once the basic idea works.

        ;; If the child sent a big batch of data to go out
        ;; all at once, don't waste time setting up a timeout
        ;; scheduler. The poll in the original would have
        ;; returned immediately anyway.
        ;; Except that n-sec-per-block puts a hard limit on how
        ;; fast we can send.
        (let [start (System/nanoTime)
              ;; TODO: Break these pieces into something
              ;; like the interceptor-chain idea. They should
              ;; return a value that includes a key for a
              ;; seq of functions to run to perform the
              ;; side-effects.
              ;; I'd still have to call updater, get
              ;; that updating seq, and update the state
              ;; to recurse.

              ;; I'd prefer to do these next two
              ;; pieces in a single step.

              ;; TODO: Read up on Executors. I could wind up
              ;; with really nasty interactions now that I
              ;; don't have an agent to keep this single-
              ;; threaded.
              ;; Actually, it should be safe as written.
              ;; Just be sure to keep everything synchronized
              ;; around takes from the i/o handle. (Not
              ;; needing to do that manually is
              ;; a great reason to not introduce a second
              ;; one for bytes travelling the other direction)
              state' (try (updater state)
                          (catch ExceptionInfo ex
                            (log/error ex
                                       (str
                                        prelog
                                        "Running updater failed.\nDetails:\n"
                                        (.getData ex))))
                          (catch RuntimeException ex
                            (log/error ex
                                       prelog
                                       "Running updater failed")
                            ;; The eternal question in this scenario:
                            ;; Fail fast, or hope we can keep limping
                            ;; along?
                            ;; TODO: Add prod vs. dev environment options
                            ;; to give the caller control over what
                            ;; should happen here.
                            ;; (Note that, either way, it really should
                            ;; include a callback to some
                            ;; currently-undefined status updater
                            (comment state)))
              mid (System/nanoTime)
              ;; This is taking a ludicrous amount of time.
              ;; Q: How much should I blame on logging?
              _ (schedule-next-timeout! io-handle state')
              end (System/nanoTime)]
          (log/debug prelog
                     (cl-format nil
                                (str
                                 "Handling ~a event took ~:d nanoseconds\n"
                                 "Scheduling next timeout took ~:d  nanoseconds")
                                tag
                                (- mid start)
                                (- end mid)))
          nil)))))

;;; I really want to move schedule-next-timeout! to flow-control.
;;; But it has a circular dependency with trigger-from-timer.
;;; Which...honestly also belongs in there.
;;; trigger-from-parent and trigger-from-child do not
;;; (from-parent and from-child seem like much better
;;; locations).
;;; Q: How much more badly would this break things?
;;; TODO: Find out.

(s/fdef schedule-next-timeout!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        :ret any?)
;;; This was originally just for setting up a
;;; timeout trigger to signal an agent to try
;;; (re-)sending any pending i/o.
;;; It's gotten repurposed since then, and
;;; probably needs a rename (TODO:).
;;; TODO: Definitely needs some refactoring to trim
;;; it down to a reasonable size.

;;; TODO: Possible alt approach: use atoms with
;;; add-watch. That opens up a different can of
;;; worms, in terms of synchronizing the flow-control
;;; section and "trigger-output" semantics. And
;;; it takes me back to Square One in terms of
;;; handling the timer. But it's tempting.
(defn schedule-next-timeout!
  [{:keys [::specs/->parent
           ::specs/child-output-loop
           ::specs/child-input-loop
           ::specs/to-child
           ::specs/message-loop-name
           ::specs/stream]
    :as io-handle}
   {:keys [::specs/recent]
    {:keys [::specs/receive-eof
            ::specs/receive-total-bytes
            ::specs/receive-written]} ::specs/incoming
    {:keys [::specs/send-eof-acked]} ::specs/outgoing
    :as state}]
  {:pre [recent]}
  (let [{{:keys [::specs/next-action]
          :as flow-control} ::specs/flow-control} state
        prelog (utils/pre-log message-loop-name)
        now (System/nanoTime)]
    (log/debug prelog
               (cl-format nil
                          "Top of scheduler at ~:d"
                          now))
    (if (not (strm/closed? stream))
      ;; TODO: Reframe this logic around
      ;; whether child-input-loop and
      ;; child-output-loop have been realized
      ;; instead.
      (if (and send-eof-acked
               (not= receive-eof ::specs/false)
               (= receive-written receive-total-bytes))
        (log/warn (str prelog
                       "Main ioloop is done."
                       "\nsend-eof-acked: " send-eof-acked
                       "\nreceive-eof: " receive-eof
                       "\nreceive-written: " receive-written
                       "\nreceive-total-bytes: " receive-total-bytes
                       "\nExiting"))
        ;; TODO: add a debugging step that stores state and the
        ;; calculated time so I can just look at exactly what I have
        ;; when everything goes sideways
        (let [actual-next (choose-next-scheduled-time state)
              ;; It seems like it would make more sense to have the delay happen from
              ;; "now" instead of "recent"
              ;; Doing that throws lots of sand into the gears.
              ;; Stick with this approach for now, because it *does*
              ;; match the reference implementation.
              ;; It seems very incorrect, but it also supplies an adjustment
              ;; for the time it took this event loop iteration to process.
              ;; Q: Is that fair/accurate?
              scheduled-delay (- actual-next recent)
              ;; Make sure that at least it isn't negative
              ;; (I keep running across bugs that have issues with this,
              ;; and it wreaks havoc with my REPL)
              delta-nanos (max 0 scheduled-delay)
              delta (if (< delta-nanos 0)
                      0
                      (inc (utils/nanos->millis delta-nanos)))
              ;; For printing
              delta_f (float delta)
              next-action (strm/try-take! stream [::drained] delta_f [::timed-out])]
          (log/debug prelog
                     (cl-format nil
                                "Initially calculated scheduled delay: ~:d nanoseconds after ~:d vs. ~:d"
                                scheduled-delay
                                recent
                                now))
          (dfrd/on-realized next-action
                            (partial action-trigger
                                     {::actual-next actual-next
                                      ::delta_f delta_f
                                      ::scheduling-time now}
                                     io-handle
                                     state)
                            (fn [failure]
                              (log/error failure
                                         prelog
                                         (cl-format nil
                                                    "~a: Waiting on some I/O to happen in timeout ~:d ms after ~:d"
                                                    delta_f
                                                    now))
                              (strm/close! io-handle)))
          (log/debug prelog
                     (cl-format nil
                                "Set timer to trigger in ~:d ms (vs ~:d scheduled) on ~a"
                                delta_f
                                (float (utils/nanos->millis scheduled-delay))
                                stream))))
      (log/warn prelog "I/O Handle closed"))
    ;; Don't rely on the return value of a function called for side-effects
    nil))

(s/fdef start-event-loops!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        :ret any?)
;;; TODO: This next lineno reference needs to move elsewhere.
;;; Although, really, it isn't even applicable any more.
;;; Caller provides ->parent and ->child callbacks for us
;;; to interact. Forking and pipe interactions are an
;;; abstraction that just don't fit.
;;;          205-259 fork child
(defn start-event-loops!
  [{:keys [::specs/->child
           ::specs/message-loop-name]
    :as io-handle}
   state]
  ;; At its heart, the reference implementation message event
  ;; loop is driven by a poller.
  ;; That checks for input on:
  ;; fd 8 (from the parent)
  ;; tochild[1] (to child)
  ;; fromchild[0] (from child)
  ;; and a timeout (based on the messaging state).
  (let [recent (System/nanoTime)]
    ;; This is nowhere near as exciting as I
    ;; expect every time I look at it

    ;; This covers line 260
    ;; Although it seems a bit silly to do it here
    (let [state (assoc state
                       ::specs/recent recent)
          child-output-loop (from-child/start-child-monitor! state io-handle)
          child-input-loop (to-child/start-parent-monitor! io-handle ->child)]
      (log/debug (utils/pre-log message-loop-name)
                 "Child monitor thread should be running now. Scheduling next ioloop timeout")
      (schedule-next-timeout! (assoc io-handle
                                     ::specs/child-output-loop child-output-loop
                                     ::specs/child-input-loop child-input-loop)
                              state))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef initial-state
        :args (s/cat :human-name ::specs/message-loop-name
                     ;; Q: What (if any) is the difference to spec that this
                     ;; argument is optional?
                     :want-ping ::specs/want-ping
                     :opts ::specs/state)
        :ret ::specs/state)
(defn initial-state
  "Put together an initial state that's ready to start!"
  ([human-name
    server?
    {{:keys [::specs/pipe-to-child-size]
      :or {pipe-to-child-size K/k-64}
      :as incoming} ::specs/incoming
     {:keys [::specs/pipe-from-child-size]
      :or {pipe-from-child-size K/k-64}
      :as outgoing} ::specs/outgoing
     :as opts}]
   (let [prelog (utils/pre-log human-name)]
     (log/debug prelog
                "Building state for initial loop based around options:\n"
                (utils/pretty opts)
                "Specifically, that translated into these overrides:\n"
                (utils/pretty {::->child-size pipe-to-child-size
                               ::child->size pipe-from-child-size})
                "Based around\n"
                (utils/pretty incoming)
                "and\n"
                (utils/pretty outgoing))
     (let [pending-client-response (promise)]
       (when server?
         (deliver pending-client-response ::never-waited))
       {::specs/flow-control {::specs/client-waiting-on-response pending-client-response
                              ::specs/last-doubling 0
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
        ::specs/incoming {::specs/->child-buffer []
                          ::specs/contiguous-stream-count 0
                          ::specs/gap-buffer (to-child/build-gap-buffer)
                          ::specs/pipe-to-child-size pipe-to-child-size
                          ::specs/receive-eof ::specs/false
                          ::specs/receive-total-bytes 0
                          ::specs/receive-written 0
                          ;; Note that the reference implementation
                          ;; tracks receivebytes instead of the
                          ;; address.
                          ::specs/strm-hwm -1}
        ::specs/outgoing {::specs/ackd-addr 0
                          ::specs/earliest-time 0
                          ;; Start with something that's vaguely sane to
                          ;; avoid 1-ms idle spin waiting for first
                          ;; incoming message
                          ::specs/last-block-time (System/nanoTime)
                          ::specs/last-panic 0
                          ;; Peers started as servers start out
                          ;; with standard-max-block-length instead.
                          ;; TODO: This needs to be replaced with a
                          ;; promise named client-waiting-on-response
                          ;; (used in message/start-child-monitor!)
                          ;; that we can use as a flag to control this
                          ;; directly instead of handling the state
                          ;; management this way.
                          ::specs/max-block-length (if server?
                                                     K/standard-max-block-length
                                                     ;; TODO: Refactor/rename this to
                                                     ;; initial-client-max-block-length
                                                     K/max-bytes-in-initiate-message)
                          ::specs/next-message-id 1
                          ::specs/pipe-from-child-size pipe-from-child-size
                          ;; Q: Does this make any sense at all?
                          ;; It isn't ever going to change, so I might
                          ;; as well just use the hard-coded value
                          ;; in constants and not waste the extra time/space
                          ;; sticking it in here.
                          ;; That almost seems like premature optimization,
                          ;; but this approach seems like serious YAGNI.
                          ::specs/send-buf-size K/send-byte-buf-size
                          ::specs/send-eof ::specs/false
                          ::specs/send-eof-acked false
                          ::specs/strm-hwm 0
                          ::specs/total-blocks 0
                          ::specs/total-block-transmissions 0
                          ::specs/un-ackd-blocks (build-un-ackd-blocks)
                          ::specs/un-sent-blocks PersistentQueue/EMPTY
                          ::specs/want-ping (if server?
                                              ::specs/false
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
        ::specs/recent 0})))
  ([human-name]
   (initial-state human-name {} false)))

(s/fdef start!
        :args (s/cat :state ::specs/state
                     :parent-callback ::specs/->parent
                     :child-callback ::specs/->child)
        :ret ::specs/io-handle)
(defn start!
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/pipe-from-child-size]
     :or {pipe-from-child-size K/k-64}
     :as outgoing} ::specs/outgoing
    {:keys [::specs/pipe-to-child-size]
     :as incoming
     :or {pipe-to-child-size K/k-64}} ::specs/incoming
    :as state}
   parent-cb
   ;; I'd like to provide the option to build your own
   ;; input loop.
   ;; It seems like this would really need to be a function that
   ;; takes the PipedInputStream and builds a future that contains
   ;; the loop.
   ;; It wouldn't be bad to write, but it doesn't seem worthwhile
   ;; just now.
   child-cb]
  (let [prelog (utils/pre-log message-loop-name)]
    (log/debug prelog
               "Starting an I/O loop.\nSize of pipe from child:"
               pipe-from-child-size
               "\nSize of pipe to child:"
               pipe-to-child-size)
    (let [;; TODO: Need to tune and monitor this execution pool
          ;; c.f. ztellman's dirigiste
          ;; For starters, I probably at least want the option to
          ;; use an instrumented executor.
          ;; Actually, that should probably be the default.
          executor (exec/utilization-executor 0.9 (utils/get-cpu-count))
          s (strm/stream)
          s (strm/onto executor s)
          ;; Q: Is there any meaningful difference between
          ;; using PipedIn-/Out-putStream pairs vs ByteArrayIn-/Out-putStreams?
          from-child (PipedOutputStream.)
          ;; Note that this really doesn't match up with reference
          ;; implementation.
          ;; This is more like the size of the buffer in the pipe
          ;; from the child to this buffering process.
          ;; Which is something that's baked into the operating
          ;; system...it seems like it's somewhere in the vicinity
          ;; of 16K.
          ;; This is *totally* distinct from our send-buf-size,
          ;; which is really all about the outgoing bytes we have pending,
          ;; either in the un-ackd or un-sent queues.
          ;; Still, this is a starting point.
          child-out (PipedInputStream. from-child pipe-from-child-size)
          to-child (PipedOutputStream.)
          ;; This has the same caveats as the buffer size for
          ;; child-out, except that I'm just picking a named
          ;; constant that's in the same general vicinity as
          ;; the size the reference implementation uses for
          ;; the message buffer. I think that's where he
          ;; stashes those.
          child-in (PipedInputStream. to-child pipe-to-child-size)
          ;; If I go with this approach, it seems like
          ;; I really need similar pairs for writing data
          ;; back out.
          io-handle {::specs/->child child-cb
                     ::specs/->parent parent-cb
                     ;; This next piece really doesn't make
                     ;; any sense, at this stage of the game.
                     ;; For the first pass, the child should
                     ;; read from child-in as fast as possible.
                     ;; I can add a higher-level wrapper around
                     ;; that later with this kind of callback
                     ;; interface.
                     ;; On one hand, having a higher level
                     ;; abstraction like this hides an implementation
                     ;; detail and seems a little nicer to not need
                     ;; to implement yourself.
                     ;; On the other, how many people would prefer
                     ;; to just use the raw stream directly?
                     ::specs/from-child from-child
                     ::specs/child-out child-out
                     ::specs/pipe-from-child-size pipe-from-child-size
                     ::specs/to-child to-child
                     ::specs/child-in child-in
                     ::specs/executor executor
                     ::specs/message-loop-name message-loop-name
                     ::specs/stream s}]
      (start-event-loops! io-handle state)
      (log/info prelog
                (cl-format nil
                           "Started an event loop:\n~a"
                           s))
      io-handle)))

(s/fdef halt!
        :args (s/cat :io-handle ::specs/io-handle)
        :ret any?)
(defn halt!
  [{:keys [::specs/message-loop-name
           ::specs/stream
           ::specs/from-child
           ::specs/child-out
           ::specs/to-child
           ::specs/child-in]
    :as io-handle}]
  (log/info (utils/pre-log message-loop-name) "I/O Loop Halt Requested")
  (strm/close! stream)
  (doseq [pipe [from-child
                child-out
                to-child
                child-in]]
    (.close pipe)))

(s/fdef get-state
        :args (s/cat :io-handle ::specs/io-handle
                     :time-out any?)
        :ret (s/or :success ::specs/state
                   :timed-out any?)
        ;; If this timed out, should return the supplied
        ;; time-out paremeter (or ::timed-out, if none).
        ;; Otherwise, the requested state.
        ;; TODO: Verify that this spec does what I expect.
        :fn (fn [{:keys [:args :ret]}]
              (if-let [failed (:timed-out ret)]
                (= failed (:time-out args))
                (:success ret))))
(defn get-state
  "Synchronous equivalent to deref"
  ([{:keys [::specs/message-loop-name
            ::specs/stream]}
    timeout
    failure-signal]
   (log/debug
    (utils/pre-log message-loop-name)
    "Submitting get-state query to"
    stream)
   (let [state-holder (dfrd/deferred)
         req (strm/try-put! stream [::query-state state-holder] timeout)]
     (dfrd/on-realized req
                       (fn [success]
                         (log/debug
                          (utils/pre-log message-loop-name)
                          "Submitted get-state query:" success))
                       (fn [failure]
                         (log/error failure
                                    (utils/pre-log message-loop-name)
                                    "Submitting state query")
                         (deliver state-holder failure)))
     (deref state-holder timeout failure-signal)))
  ([stream-holder]
   (get-state stream-holder 500 ::timed-out)))

(s/fdef child->!
        :args (s/cat :io-handle ::specs/io-handle
                     :array-o-bytes (s/or :message bytes?
                                          :eof #(instance? Throwable %)))
        ;; Truthy on success
        ;; TODO: Flip the meaning here.
        ;; Have it return (s/nilabl nat-int?) instead.
        ;; nil meas success.
        ;; An integer indicates how many bytes we *could*
        ;; have buffered.
        :ret boolean?)
(defn child->!
  ;; TODO: Add a capturing version of this and parent->!
  ;; that can store inputs for later playback.
  ;; Although, really, that's only half the equation.
  ;; The client-provided callbacks really need to support
  ;; this also.
  ;; And this is mostly about side-effects, so time
  ;; is a vital implicit input.
  "Send bytes from a child buffer...if we have room"
  ;; Child should neither know nor care that netty is involved,
  ;; so a ByteBuf really isn't appropriate here.
  ;; Much better to just just accept a byte array.
  ;; A clojure vector of bytes would generally be better than that.
  ;; A clojure object that we could just serialize to either
  ;; EDN, transit, or Fressian seems
  ;; like it would be best.
  ;; Of course, we should allow the byte array for apps that
  ;; want/need to do their own serialization.
  ;; And it's important to remember that, like TCP, this is meant
  ;; to be a streaming protocol.
  ;; So the higher-level options don't make sense at this level.
  ;; Though it seems like it would be nice to generally be able
  ;; to just hand the message to a serializer and have it handle
  ;; the streaming.

;;;  319-336: Maybe read bytes from child
  [{:keys [::specs/child-out
           ::specs/from-child
           ::specs/message-loop-name
           ::specs/pipe-from-child-size]
    :as io-handle}
   array-o-bytes]
  (let [prelog (utils/pre-log message-loop-name)]
    (log/debug prelog
               "Top of child->!")
    (when-not from-child
      (throw (ex-info (str prelog "Missing PipedOutStream from child inside io-handle")
                      {::io-handle io-handle})))
    (let [buffer-space (- pipe-from-child-size (.available child-out))
          n (count array-o-bytes)]
      ;; It seems like it would be nice to be able to block here, based
      ;; on how many bytes we really have buffered internally.
      ;; At this point, we're really in the equivalent of the
      ;; reference implementation's "real" child process.
      ;; All it has is a pipe that we promise to never block.
      ;; Although we might send back "try again later"
      ;; responses.
      (log/debug prelog
                 "Trying to send"
                 n
                 "bytes from child; have buffer space for"
                 buffer-space)
      (if (< buffer-space n)
        (do
          (log/warn "Tried to write"
                    n
                    "bytes, but only have room for"
                    buffer-space
                    "\nRefusing to block")
          ;; TODO: Add an optional parameter to allow blocking.
          ;; TODO: Adjust the meaning of this return value.
          ;; Anything numeric should be the buffer space available
          ;; (indicating failure).
          ;; Which means falsey really should indicate success,
          ;; which is ugly.
          nil)
        (do
          (.write from-child array-o-bytes 0 n)
          ;; Note that avoiding this flush is potentially a good
          ;; reason to avoid this wrapper function.
          ;; It probably makes sense usually, but it won't always.
          (.flush from-child)
          (log/debug prelog "child-> buffered" n "bytes")
          true)))))

(s/fdef parent->!
        :args (s/cat :io-handle ::specs/io-handle
                     :buf bytes?)
        :ret any?)
(defn parent->!
  "Receive a byte array from parent

  411-435: try receiving messages: (DJB)

  The parent is going to call this. It should trigger
  the pieces that naturally fall downstream and lead
  to writing the bytes to the child.

  It's replacing one of the polling triggers that
  set off the main() event loop. Need to account for
  that fundamental strategic change"
  [{:keys [::specs/message-loop-name
           ::specs/stream]
    :as io-handle}
   ^bytes array-o-bytes]
  ;; Note that it doesn't make sense to use the
  ;; same kind of interface as child->.
  ;; It's already coping with distinct individual
  ;; message packets from the parent.
  ;; It should eventually combine them into a PipedStream
  ;; to forward along to the child, but a lot of processing
  ;; needs to happen first.
  (let [prelog (utils/pre-log message-loop-name)]
    (try
      (log/info prelog
                "Top of parent->!")
      (let [success
            (strm/put! stream [::parent-> array-o-bytes])]
        (log/debug prelog "Parent put!. Setting up on-realized handler")
        (dfrd/on-realized success
                          (fn [x]
                            ;; Note that reusing prelog here would be a mistake,
                            ;; since this really should happen on a different thread
                            (log/debug (utils/pre-log message-loop-name)
                                       "Buffered bytes from parent, triggered from\n"
                                       prelog))
                          (fn [x]
                            (log/warn (utils/pre-log message-loop-name)
                                      "Failed to buffer bytes from parent, triggered from\n"
                                      prelog)))
        (log/debug prelog "returning from parent->")
        nil)
      (catch Exception ex
        (log/error ex prelog "Sending message to parent failed")))))

(s/fdef child-close!
        :args (s/cat :io-handle ::io-handle)
        :ret any?)
(defn child-close!
  "Notify parent that child is done sending"
  [{:keys [::specs/from-child]
    :as io-handle}]
  (assert from-child (str "Missing from-child among\n"
                          (keys io-handle)))
  ;; The only stream that makes sense to close this way
  ;; is the one from the child.
  ;; The other side, really, controls when it sends EOF.
  ;; Once the final byte has been sent to child, that
  ;; code should control closing that pipe pair.

  ;; The child-monitor loop should handle this
  ;; detail
  (comment (child-> io-handle ::specs/normal))
  (.close from-child))
