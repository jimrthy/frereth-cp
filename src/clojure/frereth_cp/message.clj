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
  (:import clojure.lang.PersistentQueue
           [io.netty.buffer ByteBuf Unpooled]
           java.util.concurrent.TimeoutException))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def child-buffer-timeout
  "How long might we block child->"
  ;; This is far too long. Unfortunately, my event loop
  ;; is currently very slow.
  1000)

(def event-loop-buffer-size
  "Q: How many event requests can we queue?"
  ;; TODO: Play with this number
  ;; It probably shouldn't be hard-coded. This
  ;; makes more sense as a knob that clients can
  ;; adjust.
  ;; They obviously *can*, by altering the root
  ;; binding. But that's a messy thing to do.
  16)

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
  [{:keys [::specs/->child
           ::specs/message-loop-name]
    :as io-handle}
   {{:keys [::specs/next-action]} ::specs/flow-control
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
    (log/debug prelog "Triggering Output")
    (let [state
          ;; This is a scenario when it seems like it would
          ;; be nice to be able to peek into io-handle's stream.
          ;; If a message from the parent has been buffered, it
          ;; would be nice to move it from there into the outbound
          ;; queue.
          ;; Actually, there's probably a useful clue right there:
          ;; It would be nice to have 1 queue for the outer API,
          ;; which is what schedule-next-event! is looping around.
          ;; And then multiple queues for the specifics, like
          ;; incoming from child vs. parent vs. a timeout triggering
          ;; a resend.
          ;; Maybe in a future version.
          (as-> state state
            (assoc state ::specs/recent (System/nanoTime))
            ;; It doesn't make any sense to call this if
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
            (to-parent/maybe-send-block! io-handle state))]
      state)))

(s/fdef trigger-from-child
        :args (s/cat :io-handle ::specs/io-handle
                     :array-o-bytes bytes?
                     :accepted? dfrd/deferrable?
                     :state ::specs/state)
        :ret ::specs/state)
(defn trigger-from-child
  [io-handle
   ^bytes array-o-bytes
   accepted?        ; for side-effects/modifications. Eww.
   {{:keys [::specs/strm-hwm]
     :as outgoing} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}]
  {:pre [array-o-bytes]}
  (let [prelog (utils/pre-log message-loop-name)]
    (log/info prelog
              "trigger-from-child\nSending"
              (count array-o-bytes)
              "bytes\nSent stream address:"
              strm-hwm)
    (let [state' (if (from-child/room-for-child-bytes? state)
                   (do
                     (deliver accepted? true)
                     (log/debug prelog
                                "There is room for another message")
                     (let [result (from-child/consume-from-child state array-o-bytes)]
                       result))
                   ;; trigger-output does some state management, even
                   ;; if we discard the incoming bytes because our
                   ;; buffer is full.
                   ;; TODO: Need a way to signal the child to
                   ;; try again shortly
                   ;; (this seems like a fairly ugly implementation flaw)
                   ;; Reference implementation does not have this weakness.
                   ;; If the buffer's too full, it just refuses to pull
                   ;; more bytes.
                   ;; Which means the child will eventually start getting
                   ;; EAGAIN failures.
                   ;; In order to make that work, this really needs to
                   ;; happen in child->! (which really means that its
                   ;; return value needs to be meaningful).
                   ;; That really means that it has to start by asking the
                   ;; Actor for its state. Which currently isn't exactly
                   ;; efficient.
                   (do
                     ;; TODO: Should probably hints to the client to help
                     ;; it solve the problem.
                     (deliver accepted? false)
                     (log/error prelog
                                "Discarding incoming bytes")
                     state))]
      ;; TODO: check whether we can do output now.
      ;; It's pointless to call this if we just have
      ;; to wait for the timer to expire.
      (let [state'' (trigger-output
                     io-handle
                     state')]
        state''))))

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
  [{:keys [::specs/->child
           ::specs/message-loop-name]
    :as io-handle}
   ^bytes message
   {{:keys [::specs/->child-buffer]} ::specs/incoming
    :as state}]
  (let [prelog (utils/pre-log message-loop-name)]
    (when-not ->child
      (throw (ex-info (str prelog
                           "Missing ->child")
                      {::detail-keys (keys io-handle)
                       ::top-level-keys (keys state)
                       ::details state})))

    (log/debug prelog "Incoming from parent")

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
        ;; TODO: Try switching to the reducers version instead
        (let [previously-buffered-message-bytes (reduce + 0
                                                        (map (fn [^bytes buf]
                                                               (count buf))
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
              ;; TODO: As soon as the manifold version is working, revisit
              ;; that decision.
              (log/debug prelog
                         "Message is small enough. Passing along to stream to handle")
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
                      state' (to-child/forward! ->child (or pre-processed
                                                            state))]
                  ;; This will update recent.
                  ;; In the reference implementation, that happens immediately
                  ;; after trying to read from the child.
                  ;; Q: Am I setting up any problems for myself by waiting
                  ;; this long?
                  ;; i.e. Is it worth doing that at the top of the trigger
                  ;; functions instead?
                  (trigger-output io-handle state'))
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

(defn choose-next-scheduled-time
  [{{:keys [::specs/n-sec-per-block
            ::specs/rtt-timeout]} ::specs/flow-control
    {:keys [::specs/->child-buffer
            ::specs/gap-buffer]} ::specs/incoming
    {:keys [::specs/ackd-addr
            ::specs/earliest-time
            ::specs/last-block-time
            ::specs/send-eof
            ::specs/send-eof-processed
            ::specs/un-sent-blocks
            ::specs/un-ackd-blocks
            ::specs/want-ping]} ::specs/outgoing
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
        default-next (+ recent (utils/seconds->nanos 60))  ; by default, wait 1 minute
        log-message (str log-message (cl-format nil
                                                "\nDefault +1 minute: ~:d from ~:d\nScheduling based on want-ping value '~a'"
                                                default-next
                                                recent
                                                want-ping))
        ;; Lines 286-289
        next-based-on-ping (case want-ping
                             ::specs/false default-next
                             ::specs/immediate (min default-next min-resend-time)
                             ;; Go with the assumption that this matches wantping 1 in the original
                             ;; I think the point there is for the
                             ;; client to give the server 1 second to start up
                             ::specs/second-1 (+ recent (utils/seconds->nanos 1)))
        log-message (str log-message (cl-format nil
                                                "\nBased on ping settings, adjusted next time to: ~:d"
                                                next-based-on-ping))
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
        next-based-on-eof (if (and (< (+ un-ackd-count
                                         un-sent-count)
                                      K/max-outgoing-blocks)
                                   (if (not= ::specs/false send-eof)
                                     (not send-eof-processed)
                                     (< 0 un-sent-count)))
                            (min next-based-on-ping min-resend-time)
                            next-based-on-ping)
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
        log-message (str log-message
                     (cl-format nil
                                "\nAdjusted for RTT: ~:d"
                                next-based-on-earliest-block-time))
        ;; There's one last caveat, from 298-300:
        ;; It all swirls around watchtochild, which gets set up
        ;; between lines 276-279.
        ;; It's convoluted enough that I don't want to try to dig into it tonight
        ;; It looks like the key to this is whether the pipe to the child
        ;; is still open.
        watch-to-child "There's a lot involved in this decision"
        based-on-closed-child (if (and (not= 0 (+ (count gap-buffer)
                                                  (count ->child-buffer)))
                                       (nil? watch-to-child))
                                0
                                next-based-on-earliest-block-time)
        log-message (str log-message
                         (cl-format nil
                                    "\nAfter [pretending to] adjusting for closed/ignored child watcher: ~:d"
                                    based-on-closed-child))
        ;; Lines 302-305
        actual-next (max based-on-closed-child recent)
        mid-time (System/nanoTime)
        un-ackd-count (count un-ackd-blocks)
        alt (cond-> default-next
              (= want-ping ::specs/second-1) (do (+ recent (utils/seconds->nanos 1)))
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
              (and (not= un-ackd-count)
                   (>= rtt-resend-time min-resend-time)) (min rtt-resend-time))
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
                                   "\nAlt approach took ~:d and calculated ~:d")
                          (- mid-time now)
                          actual-next
                          (- end-time mid-time)
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
   success]
  (let [prelog (utils/pre-log message-loop-name)  ; might be on a different thread
        fmt (str "Interrupting event loop waiting for ~:d ms "
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
            ::child-> (partial trigger-from-child io-handle (second success) (nth success 2))
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
                          (catch RuntimeException ex
                            (log/error ex "Running updater failed")
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
           ::specs/->child
           ::specs/message-loop-name
           ::specs/stream]
    :as io-handle}
   {:keys [::specs/recent]
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
      (do
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
  [io-handle state]
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
    (let [state (assoc state ::specs/recent recent)]
      (schedule-next-timeout! io-handle state))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef initial-state
        :args (s/cat :human-name ::specs/message-loop-name
                     ;; Q: What (if any) is the difference to spec that this
                     ;; argument is optional?
                     :want-ping ::specs/want-ping)
        :ret ::specs/state)
(defn initial-state
  "Put together an initial state that's ready to start!"
  ([human-name
    server?]
   {::specs/flow-control {::specs/last-doubling 0
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
                      ::specs/receive-eof ::specs/false
                      ::specs/receive-total-bytes 0
                      ::specs/receive-written 0
                      ;; Note that the reference implementation
                      ;; tracks receivebytes instead of the
                      ;; address.
                      ::specs/strm-hwm -1}
    ::specs/outgoing {::specs/earliest-time 0
                      ;; Start with something that's vaguely sane to
                      ;; avoid 1-ms idle spin waiting for first
                      ;; incoming message
                      ::specs/last-block-time (System/nanoTime)
                      ::specs/last-panic 0
                      ;; Peers started as servers start out
                      ;; with standard-max-block-length instead.
                      ;; TODO: Account for that
                      ::specs/max-block-length (if server?
                                                 K/standard-max-block-length
                                                 ;; TODO: Refactor/rename this to
                                                 ;; initial-client-max-block-length
                                                 K/initial-max-block-length)
                      ::specs/next-message-id 1
                      ::specs/ackd-addr 0
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
                      ::specs/send-eof-processed false
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
    ::specs/recent 0})
  ([human-name]
   (initial-state human-name false)))

(s/fdef start!
        :args (s/cat :state ::specs/state
                     :parent-callback ::specs/->parent
                     :child-callback ::specs/->child)
        :ret ::specs/io-handle)
(defn start!
  [{:keys [::specs/message-loop-name]
    :as state}
   parent-cb
   child-cb]
  ;; This function is probably pointless now.
  ;; Except as a wrapper abstraction, in case it
  ;; turns out that I need to do more.
  ;; Once this all settles down, if this is still
  ;; this minimalist, refactor the start-event-loops!
  ;; functionality into here to avoid the pointless
  ;; indirection.
  ;; TODO: That.
  (let [
        ;; TODO: Need to tune and monitor this execution pool
        ;; c.f. ztellman's dirigiste
        executor (exec/utilization-executor 0.9 (utils/get-cpu-count))
        ;; This approach was a mistake.
        ;; By default, executors run in a thread pool that's based
        ;; around either
        ;; 1. unbounded thread count
        ;; 2. unbounded queues
        ;; Specifically, the docs warn that, if you implement your
        ;; own thread pool, you really need to do the same.
        ;;s (strm/stream event-loop-buffer-size identity executor)
        s (strm/stream)
        s (strm/onto executor s)
        io-handle {::specs/->parent parent-cb
                   ::specs/->child child-cb
                   ::specs/executor executor
                   ::specs/message-loop-name message-loop-name
                   ::specs/stream s}]
    (start-event-loops! io-handle state)
    (log/info (utils/pre-log message-loop-name)
              (cl-format nil
                         "Started an event loop with buffer size ~d:\n~a"
                   event-loop-buffer-size
                   s))
    io-handle))

(s/fdef close!
        :args (s/cat :state ::state-wrapper)
        :ret any?)
(defn close!
  "Flush buffer and send EOF"
  [state]
  ;; Actually, I don't think there's any "flush buffer" concept.
  ;; Though there probably should be.
  ;; TODO: This needs to send a signal to the stream
  ;; telling it which direction got closed.
  ;; I obviously need to put more time/effort into this
  (throw (RuntimeException. "Q: How should this work?")))

(s/fdef halt!
        :args (s/cat :io-handle ::specs/io-handle)
        :ret any?)
(defn halt!
  [{:keys [::specs/message-loop-name
           ::specs/stream]
    :as io-handle}]
  (log/info (utils/pre-log message-loop-name) "Halting")
  (strm/close! stream))

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
  [{:keys [::specs/message-loop-name
           ::specs/stream]
    :as io-handle}
   array-o-bytes]
  (let [prelog (utils/pre-log message-loop-name)]
    (log/debug prelog
               "Top of child->!\n")
    (when-not stream
      (throw (ex-info (str prelog "Missing stream inside io-handle")
                      {::io-handle io-handle})))
    (when (strm/closed? stream)
      (throw (RuntimeException. (str prelog "Can't write to a closed stream"))))
    (let [success (dfrd/deferred)
          ;; TODO: Add a deferred parameter here to indicate success/failure.
          ;; Then block this thread by calling deref and returns that value.
          ;; Handler should fulfill that deferred based on whether it has
          ;; room to buffer the message or not.
          ]
      (strm/put! stream [::child-> array-o-bytes success])
      (let [buffered? (deref success child-buffer-timeout ::timed-out)
            success (and buffered?
                         (not= buffered? ::timed-out))]
        (when (= ::timed-out buffered?)
          ;; This is mainly a problem because it means we blocked
          ;; the sending thread for a ridiculously long time.
          ;; TODO: Add an arity that allows sender to supply something
          ;; that's deliverable so it can decide how much blockage is acceptable.
          (log/warn "Timed out trying to buffer bytes from child"))
        (log/debug prelog "returning from child->")
        success))))

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

  (let [prelog (utils/pre-log message-loop-name)]
    (log/info prelog
              "Top of parent->!")
    (let [success
          (strm/put! stream [::parent-> array-o-bytes])]
      (log/debug prelog "Parent put!. Setting up on-realized handler")
      (dfrd/on-realized success
                        (fn [x]
                          (log/debug (utils/pre-log message-loop-name)
                                     "Buffered bytes from parent, triggered from\n"
                                     prelog))
                        (fn [x]
                          (log/warn (utils/pre-log message-loop-name)
                                    "Failed  to buffer bytes from parent, triggered from\n"
                                    prelog))))
    (log/debug prelog "returning from parent->")
    nil))
