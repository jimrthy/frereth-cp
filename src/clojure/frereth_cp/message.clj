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
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.specs :as shared-specs]
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

(s/def ::action-timing-details (s/keys :req [::actual-next
                                             ::delta_f
                                             ::scheduling-time]))
(s/def ::next-action-time nat-int?)
(s/def ::source-tags #{::child-> ::parent-> ::query-state})
(s/def ::input (s/tuple ::source-tags bytes?))
(s/def ::action-tag #{::specs/child->
                      ::drained
                      ::no-op
                      ::parent->
                      ::query-state
                      ::timed-out})
;; Q: How do I spec these out?
;; Since we really have 0, 1, or 2 arguments
;; A: s/or seems like the most likely approach.
;; TODO: Nail this down
(s/def ::next-action (s/tuple ::action-tag))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal API

(s/fdef build-un-ackd-blocks
        :args (s/cat :log-state ::log/state
                     :logger ::log/logger)
        :ret ::specs/un-ackd-blocks)
(defn build-un-ackd-blocks
  [{:keys [::log/logger]
    log-state ::log/state}]
  (sorted-set-by (fn [x y]
                   (try
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
                           1)))
                     (catch NullPointerException ex
                       (let [log-state (log/exception log-state
                                                       ex
                                                       ::build-un-ackd-blocks
                                                       "Comparing time"
                                                       {::lhs x
                                                        ::rhs y})]
                         (log/flush-logs! logger log-state))
                       (throw ex))))))

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
  (let [state (update state
                      ::log/state
                      #(log/debug %
                                  ::trigger-output
                                  "Possibly sending message to parent"
                                  {::specs/message-loop-name message-loop-name}))]
    ;; I have at least 1 unit test that receives input
    ;; from parent, forwards that to child, then
    ;; echoes it back.
    ;; Then it calls trigger-output, doesn't find
    ;; anything ready to go, loops back to polling
    ;; for events, finds the message the child
    ;; just queued, and starts over.
    ;; It's very tempting to try to account for
    ;; that scenario here, but it would involve
    ;; enough extra stateful contortions.

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
  (let [state (update state
                      ::log/state
                      #(log/info %
                                 ::trigger-from-child
                                 "Sent stream address"
                                 {::specs/strm-hwm strm-hwm
                                  ::specs/message-loop-name message-loop-name}))]
    (deliver accepted? true)
    (let [state' (callback state)]
      (assert (::specs/outgoing state') "Callback threw away outgoing")
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
  "Message block arrived from parent. Work triggered by ioloop"
  ;; TODO: Move as much of this as possible into from-parent
  ;; The only reason I haven't already moved the whole thing
  ;; is that we need to use to-parent to send the ACK, and I'd
  ;; really rather not introduce dependencies between those namespaces
  [{:keys [::log/logger
           ::specs/message-loop-name]
    :as io-handle}
   ^bytes message
   {{:keys [::specs/->child-buffer]} ::specs/incoming
    {:keys [::specs/client-waiting-on-response]} ::specs/flow-control
    log-state ::log/state
    :as state}]
  (let [log-state (log/debug log-state
                             ::trigger-from-parent
                             "Incoming from parent")]

    ;; This is an important side-effect that permanently converts the
    ;; "mode" of the i/o loop that's pulling bytes from the child's
    ;; output pipe.
    ;; Now that we've gotten a response back, we can switch from
    ;; initiate packets to message packets, which effectively doubles
    ;; the signal bandwidth.
    (when-not (realized? client-waiting-on-response)
      (deliver client-waiting-on-response false))

;;;           From parent (over watch8)
;;;           417-433: for loop from 0-bytes read
;;;                    Copies bytes from incoming message buffer to message[][]
    (let [incoming-size (count message)]
      (when (= 0 incoming-size)
        (log/flush-logs! logger log-state)
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

      ;; trigger-from-parent! is expecting to have a ::->child-buffer key
      ;; that's really a vector that we can just conj onto.
      (when-not state
        ;; Q: Why aren't I just using log-state?
        (let [logs (log/warn (log/init (::log/context log-state)
                                       (::log/lamport log-state))
                              ::trigger-from-parent
                              ;; They're about to get worse
                              "nil state. Things went sideways recently")]
          (log/flush-logs! logger logs)))

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
                                                                   (let [prelog (utils/pre-log message-loop-name)]
                                                                     (throw (ex-info (str prelog
                                                                                          "Parent sent a "
                                                                                          (class buf)
                                                                                          " which isn't a B]")
                                                                                     {::cause ex}))))))
                                                             ->child-buffer))
              log-state (log/debug log-state
                                   ::trigger-from-parent
                                   "possibly processing"
                                   {::bytes-buffered previously-buffered-message-bytes
                                    ::buffer-count (count ->child-buffer)})]
          ;; Probably need to do something with previously-buffered-message-bytes.
          ;; Definitely need to check the number of bytes that have not
          ;; been forwarded along yet.
          ;; However, the reference implementation does not.
          ;; Then again...it's basically a self-enforcing
          ;; 64K buffer, so maybe it's already covered, and I just wasted
          ;; CPU cycles calculating it.
          (if (<= incoming-size K/max-msg-len)
            (let
              ;; It's tempting to move as much as possible from here
              ;; into the (now defunct) agent handler.
              ;; That impulse seems wrong. Based on preliminary numbers,
              ;; any filtering I can do outside an an agent send is a win.
              ;; TODO: Now that the manifold version is working, revisit
              ;; that decision.
                [log-state (log/debug log-state
                                      ::trigger-from-parent
                                      "Message is small enough. Look back here")
                 state (-> state
                           (assoc ::log/state log-state)
                           (assoc-in [::specs/incoming ::specs/parent->buffer]
                                     message))]
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
                ;; This is a prime example of something that should
                ;; be queued up to be called for side-effects.
                ;; TODO: Split those out and make that happen.
                (as-> (from-parent/try-processing-message!
                       io-handle
                       state) state'
                  (to-child/forward! io-handle state')

                  ;; This will update recent.
                  ;; In the reference implementation, that happens immediately
                  ;; after trying to read from the child.
                  ;; Q: Am I setting up any problems for myself by waiting
                  ;; this long?
                  ;; i.e. Is it worth doing that at the top of the trigger
                  ;; functions instead?
                  (trigger-output io-handle state'))
                (catch ExceptionInfo ex
                  (let [log-state (log/exception log-state
                                                 ex
                                                 ::trigger-from-parent
                                                 "Forwarding failed"
                                                 (.getData ex))]
                    (assoc state ::log/state log-state)))
                (catch RuntimeException ex
                  (let [msg "Trying to cope with a message arriving from parent"]
                    (update state
                            ::log/state
                            #(log/exception %
                                            ex
                                            ::trigger-from-parent
                                            msg))))))
            ;; This is actually pretty serious.
            ;; All sorts of things had to go wrong for us to get here.
            ;; TODO: More extensive error handling.
            ;; Actually, should probably add an optional client-supplied
            ;; error handler for situations like this
            (assoc state
                   ::log/state
                   (log/warn log-state
                             ::trigger-from-parent
                             "Incoming message too large"
                             {::incoming-size incoming-size
                              ::maximum-allowed K/max-msg-len}))))
        ;; TODO: Need a way to apply back-pressure
        ;; to child
        (assoc state
               ::log/state
               (log/warn log-state
                         ::trigger-from-parent
                         "Child buffer overflow\nWait!"
                         {::incoming-buffer-size (count ->child-buffer)
                          ::max-allowed max-child-buffer-size}))))))

(defn trigger-from-timer
  [io-handle
   {:keys [::specs/message-loop-name]
    :as state}]
  ;; It's really tempting to move this to to-parent.
  ;; But (at least in theory) it could also trigger
  ;; output to-child.
  ;; So leave it be for now.

  ;; I keep thinking that I need to check data arriving from
  ;; the child, but the main point to this logic branch is
  ;; to resend an outbound block that hasn't been ACK'd yet.
  (trigger-output io-handle (update state
                                    ::log/state
                                    #(log/debug %
                                                ::trigger-from-timer
                                                "I/O triggered by timer"
                                                {::specs/message-loop-name message-loop-name}))))

(s/fdef condensed-choose-next-scheduled-time
        :args (s/cat :outgoing ::specs/outgoing
                     :state ::specs/state
                     :to-child-done? ::specs/to-child-done?)
        :ret (s/keys :req [::next-action-time
                           ::log/state]))
(defn condensed-choose-next-scheduled-time
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
    log-state ::log/state
    :as state}
   to-child-done?]
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
        min-resend-time (+ last-block-time n-sec-per-block)
        un-ackd-count (count un-ackd-blocks)
        un-sent-count(count un-sent-blocks)
        default-next (+ recent (utils/seconds->nanos 60))  ; by default, wait 1 minute
        send-eof-processed (to-parent/send-eof-buffered? outgoing)
        rtt-resend-time (+ earliest-time rtt-timeout)
        next-time
        (cond-> default-next
          ;; The first clause is weird. 1 second is always going to happen more
          ;; quickly than the 1 minute initial default.
          ;; Sticking with the min pattern because of the way the threading macro works
          (= want-ping ::specs/second-1) (min (+ recent (utils/seconds->nanos 1)))
          (= want-ping ::specs/immediate) (min min-resend-time)
          ;; If the outgoing buffer is not full
          ;; And:
          ;;   If sendeof, but not sendeofprocessed
          ;;   else (!sendeof):
          ;;     if there are buffered bytes that have not been sent yet

          ;; Lines 290-292
          ;; Q: What is the actual point to this?
          ;; (the logic seems really screwy, but that's almost definitely
          ;; a lack of understanding on my part)
          ;; A: There are at least 3 different moving parts involved here
          ;; 1. Are there unsent blocks that need to be sent?
          ;; 2. Do we have previously sent blocks that might need to re-send?
          ;; 3. Have we sent an un-ACK'd EOF?
          (and (< (+ un-ackd-count
                     un-sent-count)
                  K/max-outgoing-blocks)
               (if (not= ::specs/false send-eof)
                 (not send-eof-processed)
                 (< 0 un-sent-count))) (min min-resend-time)
          ;; Lines 293-296
          (and (not= 0 un-ackd-count)
               (> rtt-resend-time
                  min-resend-time)) (min rtt-resend-time)
          ;; There's one last caveat, from 298-300:
          ;; It all swirls around watchtochild, which gets set up
          ;; between lines 276-279.
          ;; Basic point:
          ;; If there are incoming messages, but the pipe to child is closed,
          ;; short-circuit so we can exit.
          ;; That seems like a fairly major error condition.
          ;; Q: What's the justification?
          ;; Hypothesis: It's based around the basic idea of
          ;; being lenient about accepting garbage.
          ;; This seems like the sort of garbage that would be
          ;; worth capturing for future analysis.
          ;; Then again...if extra UDP packets arrive out of order,
          ;; it probably isn't all *that* surprising.
          ;; Still might be worth tracking for the sake of security.
          (and (not= 0 (+ (count gap-buffer)
                          (count ->child-buffer)))
               ;; This looks backward. It isn't.
               ;; If there are bytes to forward to the
               ;; child, and the pipe is still open, then
               ;; try to send them.
               ;; However, the logic *is* broken:
               ;; The check for gap-buffer really needs
               ;; to be based around closed gaps
               (not (realized? to-child-done?))) 0)]
    ;; Lines 302-305
    {::next-action-time (max recent next-time)
     ::log/state log-state}))

(s/fdef choose-next-scheduled-time
        :args (s/cat :outgoing ::specs/outgoing
                     :state ::specs/state
                     :to-child-done? ::specs/to-child-done?)
        :ret (s/keys :req [::next-action-time
                           ::log/state]))
(defn choose-next-scheduled-time
  [{{:keys [::specs/n-sec-per-block
            ::specs/rtt-timeout]
     :as flow-control} ::specs/flow-control
    {:keys [::specs/->child-buffer
            ::specs/gap-buffer]} ::specs/incoming
    {:keys [::specs/earliest-time
            ::specs/last-block-time
            ::specs/send-eof
            ::specs/un-sent-blocks
            ::specs/un-ackd-blocks
            ::specs/want-ping]
     :as outgoing} ::specs/outgoing
    :keys [::specs/message-loop-name
           ::specs/recent]
    log-state ::log/state
    :as state}
   to-child-done?]
  {:pre [state
         outgoing
         last-block-time
         flow-control
         n-sec-per-block]}
  ;;; This amounts to lines 286-305

  ;; I should be able to just completely bypass this if there's
  ;; more new data pending.
  ;; TODO: Figure out how to make that work

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
        next-based-on-earliest-block-time (if (and (not= 0 un-ackd-count)
                                                   (> rtt-resend-time
                                                      min-resend-time))
                                            (min next-based-on-eof rtt-resend-time)
                                            next-based-on-eof)
        ;; There's one last caveat, from 298-300:
        ;; It all swirls around watchtochild, which gets set up
        ;; between lines 276-279.
        ;; Basic point:
        ;; If there are incoming messages, but the pipe to child is closed,
        ;; short-circuit so we can exit.
        ;; That seems like a fairly major error condition.
        ;; Q: What's the justification?
        ;; Hypothesis: It's based around the basic idea of
        ;; being lenient about accepting garbage.
        ;; This seems like the sort of garbage that would be
        ;; worth capturing for future analysis.
        ;; Then again...if extra UDP packets arrive out of order,
        ;; it probably isn't all *that* surprising.
        ;; Still might be worth tracking for the sake of security.
        based-on-closed-child (if (and (not= 0 (+ (count gap-buffer)
                                                  (count ->child-buffer)))
                                       (not (realized? to-child-done?)))
                                ;; This looks backward. It isn't.
                                ;; If there are bytes to forward to the
                                ;; child, and the pipe is still open, then
                                ;; try to send them.
                                ;; However, the logic *is* broken:
                                ;; The check for gap-buffer really needs
                                ;; to be based around closed gaps
                                0
                                next-based-on-earliest-block-time)
        ;; Lines 302-305
        actual-next (max based-on-closed-child recent)
        mid1-time (System/nanoTime)
        ;; TODO: Just build log-message in one fell swoop instead
        ;; of all these individual steps.
        ;; Give the JIT something to work with.
        log-message (cl-format nil
                               (str "Minimum resend time: ~:d\n"
                                    "which is ~:d nanoseconds\n"
                                    "after last block time ~:d.\n"
                                    "Recent was ~:d ns in the past\n"
                                    "rtt-timeout: ~:d\n"
                                    "earliest -time: ~:d")
                               min-resend-time
                               n-sec-per-block
                               ;; I'm calculating last-block-time
                               ;; incorrectly, due to a misunderstanding
                               ;; about the name.
                               ;; It should really be the value of
                               ;; recent, set immediately after
                               ;; I send a block to parent.
                               last-block-time
                               (- now recent)
                               rtt-timeout
                               earliest-time)
        log-message (str log-message (cl-format nil
                                                "\nDefault +1 minute: ~:d from recent: ~:d\nScheduling based on want-ping value ~a"
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
                                (long next-based-on-earliest-block-time)))
        log-message (str log-message
                         (cl-format nil
                                    "\nAfter adjusting for closed/ignored child watcher: ~:d"
                                    (long based-on-closed-child)))
        end-time (System/nanoTime)
        log-state (log/debug log-state
                             ::choose-next-scheduled-time
                             (str "Scheduling considerations\n"
                                  log-message))]
    {::next-action-time actual-next
     ::log/state log-state}))

(declare schedule-next-timeout!)
(s/fdef action-trigger
        :args (s/cat :timing-details ::action-timing-details
                     :io-handle ::specs/io-handle
                     :state ::specs/state
                     :log-state-atom ::shared-specs/atom
                     :next-action ::next-action)
        :ret any?)
(defn action-trigger
  [{:keys [::actual-next
           ::delta_f
           ::scheduling-time]
    :as timing-details}
   {:keys [::specs/message-loop-name]
    :as io-handle}
   {:keys [::specs/outgoing]
    :as state}
   log-state-atom
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
   next-action]
  {:pre [outgoing]}
  (let [now (System/nanoTime)  ; It's tempting to just use millis, but that throws off recent
        ;; Line 337
        ;; Doing this now instead of after trying to receive data from the
        ;; child seems like a fairly significant change from the reference
        ;; implementation.
        ;; TODO: Compare with other higher-level implementations
        ;; TODO: Ask cryptographers and protocol experts whether this is
        ;; a choice I'll really regret
        state (assoc state ::specs/recent now)
        log-state @log-state-atom
        ;; This is used during exception handling
        prelog (utils/pre-log message-loop-name)  ; might be on a different thread
        fmt (str "Awakening event loop that was sleeping for ~g ms "
                 "after ~:d at ~:d\n"
                 "at ~:d because: ~a")
        log-state (try
                    (log/debug log-state
                               ::action-trigger
                               (cl-format nil
                                          fmt
                                          delta_f
                                          scheduling-time
                                          (or actual-next -1)
                                          now
                                          next-action)
                               {::specs/message-loop-name message-loop-name})
                    (catch NullPointerException ex
                      (log/exception log-state
                                     ex
                                     ::action-trigger
                                     "Error building the event loop Awakening message"
                                     {::delta_f delta_f
                                      ::scheduling-time scheduling-time
                                      ::actual-next actual-next
                                      ::now now
                                      ::next-action next-action
                                      ::trigger-details prelog
                                      ::specs/message-loop-name message-loop-name}))
                    (catch NumberFormatException ex
                      (log/exception log-state
                                     ex
                                     ::action-trigger
                                     "Error formatting the event loop Awakening message"
                                     {::delta_f delta_f
                                      ::scheduling-time scheduling-time
                                      ::actual-next actual-next
                                      ::now now
                                      ::next-action next-action
                                      ::trigger-details prelog
                                      ::specs/message-loop-name message-loop-name})))
        [tag
         log-state] (try
                      [(first next-action) log-state]
                      (catch IllegalArgumentException ex
                        [::no-op
                         (log/exception log-state
                                        ex
                                        ::action-trigger
                                        "Should have been a variant"
                                        {::trigger-details prelog
                                         ::specs/message-loop-name message-loop-name})]))
        ;; TODO: Really should add something like an action ID to the state
        ;; to assist in tracing the action. flow-control seems like a very
        ;; likely place to put it.
        updater (case tag
                  ;; Q: Is this worth switching to something like core.match or a multimethod?
                  ::specs/child-> (let [[_ callback ack] next-action]
                                    (partial trigger-from-child io-handle callback ack))
                  ::drained (fn [{log-state ::log/state
                                  :as state}]
                              ;; Actually, this seems like a strong argument for
                              ;; having a pair of streams. Child could still have
                              ;; bytes to send to the parent after the latter's
                              ;; stopped sending, or vice versa.
                              ;; I'm pretty sure the complexity I haven't finished
                              ;; translating stems from that case.
                              ;; TODO: Another piece to revisit once the basics
                              ;; work.
                              (update state
                                      ::log/state
                                      #(log/warn %
                                                 ::action-trigger
                                                 "Stream closed. Surely there's more to do"
                                                 {::trigger-details prelog
                                                  ::specs/message-loop-name message-loop-name})))
                  ::no-op identity
                  ;; Q: Shouldn't this be from the specs ns?
                  ::parent-> (partial trigger-from-parent
                                      io-handle
                                      (second next-action))
                  ;; This can throw off the timer, since we're basing the delay on
                  ;; the delta from recent (which doesn't change) rather than now.
                  ;; But we're basing the actual delay from now, which does change.
                  ;; e.g. If the scheduled delay is 980 ms, and someone triggers a
                  ;; query-state that takes 20 ms after 20 ms, the new delay will
                  ;; still be 980 ms rather than the 940 that would have been
                  ;; appropriate.
                  ;; Q: What's the best way to avoid this?
                  ;; Updating recent seems obvious, but also dubious.
                  ;; Decrementing the delay seems like something the scheduler
                  ;; should handle.
                  ::query-state (fn [state]
                                  (if-let [dst (second next-action)]
                                    (do
                                      (deliver dst state)
                                      state)
                                    (update state
                                            ::log/state
                                            #(log/warn %
                                                       ::action-trigger
                                                       "state-query request missing required deferred"
                                                       {::trigger-details prelog
                                                        ::specs/message-loop-name message-loop-name}))))
                  ::timed-out (fn [state]
                                (trigger-from-timer io-handle
                                                    (update state
                                                            ::log/state
                                                            #(log/debug %
                                                                        "Re-triggering Output due to timeout"
                                                                        (assoc timing-details
                                                                               ::trigger-details prelog
                                                                               ::specs/message-loop-name message-loop-name))))))
        state (assoc state
                     ::log/state
                     (log/debug log-state
                                ::action-trigger
                                "Processing event"
                                {::tag tag
                                 ::specs/message-loop-name message-loop-name}))
        ;; At the end of the main ioloop in the reference
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
        start (System/currentTimeMillis)
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

        state (update state
                      ::log/state
                      #(log/warn %
                                 ::action-trigger
                                 "Trying to run updater because of"
                                 {::tag tag}))

        state' (try (updater state)
                    (catch ExceptionInfo ex
                      (update state
                              ::log/state
                              #(log/exception %
                                              ex
                                              ::action-trigger
                                              "Running updater failed"
                                              {::details (.getData ex)
                                               ::specs/message-loop-name message-loop-name})))
                    (catch RuntimeException ex
                      ;; The eternal question in this scenario:
                      ;; Fail fast, or hope we can keep limping
                      ;; along?
                      ;; TODO: Add prod vs. dev environment options
                      ;; to give the caller control over what
                      ;; should happen here.
                      ;; (Note that, either way, it really should
                      ;; include a callback to some
                      ;; currently-undefined status updater
                      (comment state)
                      (update state
                              ::log/state
                              #(log/exception %
                                              ex
                                              ::action-trigger
                                              "Running updater: low-level failure"
                                              {::specs/message-loop-name message-loop-name}))))
        state' (update state'
                       ::log/state
                       #(log/warn %
                                  ::action-trigger
                                  "Updater returned"
                                  (dissoc state' ::log/state)))
        _ (assert (::specs/outgoing state') (str "After updating for " tag))
        my-logs (::log/state state')
        forked-logs (log/fork my-logs)
        mid (System/currentTimeMillis)
        ;; This is taking a ludicrous amount of time.
        ;; Q: How much should I blame on logging?
        _ (schedule-next-timeout! io-handle (assoc state'
                                                   ::log/state
                                                   forked-logs))
        end (System/currentTimeMillis)
        my-logs (log/debug  my-logs
                            ::action-trigger
                            "Handled a triggered action"
                            {::tag tag
                             ::handling-ms (- mid start)
                             ::rescheduling-ms (- end mid)
                             ::specs/message-loop-name message-loop-name})]
    (reset! log-state-atom
            (log/flush-logs! (::log/logger io-handle)
                             my-logs)))
  nil)

(comment
  (let [delta_f ##Inf,
        scheduling-time 8820859844762393,
        actual-next nil
        now 8820859845124380
        success [:frereth-cp.message/query-state ::whatever]
        fmt (str "Awakening event loop that was sleeping for ~g ms "
                 "after ~:d at ~:d\n"
                 "at ~:d because: ~a")]
    (cl-format nil
               fmt
               delta_f #_1.0
               scheduling-time
               (or actual-next -1)
               now
               success)))

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

;; FIXME: Don't make this a global
(def fast-spins (atom 0))
;;; TODO: Possible alt approach: use atoms with
;;; add-watch. That opens up a different can of
;;; worms, in terms of synchronizing the flow-control
;;; section and "trigger-output" semantics. And
;;; it takes me back to Square One in terms of
;;; handling the timer. But it's tempting.
(defn schedule-next-timeout!
  [{:keys [::log/logger
           ::specs/->parent
           ::specs/child-output-loop
           ::specs/child-input-loop
           ::specs/to-child
           ::specs/to-child-done?
           ::specs/message-loop-name
           ::specs/stream]
    :as io-handle}
   {:keys [::specs/recent]
    ;; Q: Do I care about this next-action?
    {:keys [::specs/next-action]
     :as flow-control} ::specs/flow-control
    {:keys [::specs/receive-eof
            ::specs/receive-total-bytes
            ::specs/receive-written]} ::specs/incoming
    {:keys [::specs/send-eof-acked]
     :as outgoing} ::specs/outgoing
    log-state ::log/state
    :as state}]
  {:pre [recent
         outgoing]}
  ;; This really keeps going with the "queue up side-effects" idea
  (let [;; Note that the caller called this shortly before.
        ;; So calling it again this quickly seems like
        ;; a waste of ~30-ish nanoseconds.
        now (System/nanoTime)
        log-state (log/debug log-state
                             ::schedule-next-timeout!
                             "Top of scheduler"
                             {::now now})]
    (if (not (strm/closed? stream))
      (let [{actual-next ::next-action-time
             log-state ::log/state
             :as original-scheduled}
            ;; TODO: Reframe this logic around
            ;; whether child-input-loop and
            ;; child-output-loop have been realized
            ;; instead.
            (if (and send-eof-acked
                     (not= receive-eof ::specs/false)
                     (= receive-written receive-total-bytes))
              {::next-action-time nil
               ;; Note that we can't *really* exit until
               ;; the caller closes the stream.
               ;; After all, unit tests want/need to
               ;; examine the final system state (which
               ;; means calling into this loop)
               ::log/state (log/warn log-state
                                     ::schedule-next-timeout!
                                     "Main ioloop is done. Idling."
                                     {::specs/message-loop-name message-loop-name
                                      ::specs/receive-eof receive-eof
                                      ::specs/receive-written receive-written
                                      ::specs/receive-total-bytes receive-total-bytes
                                      ::specs/send-eof-acked send-eof-acked})}
              (choose-next-scheduled-time (assoc state
                                                 ::log/state
                                                 log-state)
                                          to-child-done?))
            mid-time (System/nanoTime)
            ;; TODO: Try calling this one first, on the off-chance that ordering
            ;; makes a difference in performance. It's quite possible that the
            ;; first pass does something that sets the CPU cache up to blaze through
            ;; the second.
            {alt-next ::next-action-time
             alt-log-state ::log/state} (condensed-choose-next-scheduled-time (assoc state
                                                                                     ::log/state log-state)
                                                                              to-child-done?)
            scheduling-finished (System/nanoTime)]
        (when (not= alt-next actual-next)
          ;; This will get duplicate garbage entries into the logs, but it really
          ;; shouldn't ever happen.
          ;; It's really just here as a guard before I ditch the original
          ;; slow implementation completely.
          (log/flush-logs! logger (log/warn log-state
                                            ::schedule-next-timeout
                                            "Scheduler mismatch"
                                            {::original actual-next
                                             ::fast-alternative alt-next
                                             ::original-ns (- mid-time now)
                                             ::alt-ns (- scheduling-finished mid-time)
                                             ::state (dissoc state ::log/state
                                                            ::to-child-done? to-child-done?)})))
        (let [{:keys [::delta_f
                      ::next-action]
               log-state ::log/state}
              (if actual-next
                ;; TODO: add an optional debugging step that stores state and the
                ;; calculated time so I can just look at exactly what I have
                ;; when everything goes sideways
                (let [;; It seems like it would make more sense to have the delay happen from
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
                      delta (inc (utils/nanos->millis delta-nanos))
                      ;; For printing
                      delta_f (float delta)
                      log-state (log/debug log-state
                                           ::schedule-next-timeout!
                                           "Setting timer to trigger after an initially calculated scheduled delay"
                                           {::scheduled-delay scheduled-delay  ; Q: Convert to long?
                                            ::specs/recent recent
                                            ::now now
                                            ::actual-delay delta_f
                                            ::delay-in-millis (float (utils/nanos->millis scheduled-delay))
                                            ::stream stream})]
                  (if (= delta 1)
                    (do
                      (swap! fast-spins inc)
                      (when (> @fast-spins 5)
                        ;; Q: Does this ever happen if nothing's broken?
                        (println "FIXME: Debug only")
                        (throw (ex-info "Exiting to avoid fast-spin lock"
                                        state))))
                    (reset! fast-spins 0))
                  {::delta_f delta_f
                   ::next-action (strm/try-take! stream [::drained] delta_f [::timed-out])
                   ::log/state log-state})
                ;; The i/o portion of this loop is finished.
                ;; But we still need to wait on the caller to close the underlying stream.
                ;; If nothing else, it may still want/need to query state.
                {::delta_f ##Inf
                 ::next-action (strm/take! stream [::drained])
                 ::log/state log-state})
              log-state (log/flush-logs! logger log-state)
              ;; Q: Why am I forking logs here?
              [forked-logs log-state] (log/fork log-state)]
          (when-not (::specs/outgoing state)
            (println "Missing outgoing in" state)
            (throw (ex-info "Missing outgoing" state)))
          (println message-loop-name "Setting up deferred to trigger on next action")
          (dfrd/on-realized next-action
                            (partial action-trigger
                                     {::actual-next actual-next
                                      ::delta_f delta_f
                                      ::scheduling-time now}
                                     io-handle
                                     ;; Q: Wait. Why am I setting log-state to nil in here?
                                     ;; (I vaguely remember doing this. It just seems wrong)
                                     (assoc state ::log/state nil)
                                     ;; Putting the logs into an atom here ties in to setting
                                     ;; the state's log-state to nil.
                                     ;; It seems like a very screw-ball choice.
                                     ;; TODO: Remember why I did this and either document
                                     ;; the screwiness or roll it back out.
                                     (atom forked-logs #_log-state))
                            (fn [failure]
                              (log/flush-logs! logger
                                               (log/error forked-logs
                                                          ::schedule-next-timeout!
                                                          "Waiting on some I/O to happen in timeout"
                                                          {::actual-delay delta_f
                                                           ::now now}))
                              ;; We don't have any business doing this here, but the
                              ;; alternatives don't seem appealing.
                              ;; Well, we could recurse manually without a scheduled
                              ;; time.
                              (strm/close! stream)))))
      (log/flush-logs! logger
                       (log/warn log-state
                                 ::schedule-next-timeout!
                                 "I/O Handle closed")))
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
  [{:keys [::log/logger
           ::specs/->child
           ::specs/message-loop-name]
    :as io-handle}
   {log-state ::log/state
    :as state}]
  ;; At its heart, the reference implementation message event
  ;; loop is driven by a poller.
  ;; That checks for input on:
  ;; fd 8 (from the parent)
  ;; tochild[1] (to child)
  ;; fromchild[0] (from child)
  ;; and a timeout (based on the messaging state).
  (let [recent (System/nanoTime)
        ;; This is nowhere near as exciting as I
        ;; expect every time I look at it

        ;; This covers line 260
        ;; Although it seems a bit silly to do it here
        state (assoc state
                     ::specs/recent recent)
        child-output-loop (from-child/start-child-monitor! state io-handle)
        child-input-loop (to-child/start-parent-monitor! io-handle log-state ->child)
        log-state (log/debug log-state
                             ::start-event-loops!
                             "Child monitor thread should be running now. Scheduling next ioloop timeout")
        state (assoc state
                        ::log/state
                        (log/flush-logs! logger log-state))]
    (schedule-next-timeout! (assoc io-handle
                                   ::specs/child-output-loop child-output-loop
                                   ::specs/child-input-loop child-input-loop)
                            state)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef initial-state
        :args (s/cat :human-name ::specs/message-loop-name
                     ;; Q: What (if any) is the difference to spec that this
                     ;; argument is optional?
                     :server? :boolean?
                     :opts ::specs/state
                     :logger ::log/logger)
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
     ;; FIXME: This is going to break all my existing code.
     ;; But it really needs to happen now.
     log-state ::log/state
     :as opts}
    logger]
   {:pre [log-state]}
   ;; This version throws away the updated parent-logs.
   ;; That's a mistake.
   ;; It doesn't seem like one that's worth rectifying
   (let [[child-logs parent-logs] (log/fork log-state human-name)
         child-logs (log/debug child-logs
                              ::initialization
                              "Building state for initial loop based around options"
                              (dissoc
                               (assoc opts ::overrides {::->child-size pipe-to-child-size
                                                        ::child->size pipe-from-child-size})
                               ::log/state))
         pending-client-response (promise)]
     (when server?
       (deliver pending-client-response ::never-waited))
     {::specs/flow-control {::specs/client-waiting-on-response pending-client-response
                            ::specs/last-doubling (long 0)
                            ::specs/last-edge (long 0)
                            ::specs/last-speed-adjustment (long 0)
                            ::specs/n-sec-per-block K/sec->n-sec
                            ::specs/rtt (long 0)
                            ::specs/rtt-average (long 0)
                            ::specs/rtt-deviation (long 0)
                            ::specs/rtt-highwater (long 0)
                            ::specs/rtt-lowwater (long 0)
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
                        ;; FIXME: Move this to flow-control
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
                        ::specs/un-ackd-blocks (build-un-ackd-blocks {::log/logger logger
                                                                      ::log/state log-state})
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
      ::log/state child-logs
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
  ([human-name logger]
   (initial-state human-name {} false logger)))

(s/fdef start!
        :args (s/cat :state ::specs/state
                     :logger ::log/logger
                     :parent-callback ::specs/->parent
                     :child-callback ::specs/->child)
        :ret (s/keys :req [::log/state
                           ::specs/io-handle]))
(defn start!
   ;; I'd like to provide the option to build your own
   ;; input loop.
   ;; It seems like this would really need to be a function that
   ;; takes the PipedInputStream and builds a future that contains
   ;; the loop.
   ;; It wouldn't be bad to write, but it doesn't seem worthwhile
   ;; just now.
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/pipe-from-child-size]
     :or {pipe-from-child-size K/k-64}
     :as outgoing} ::specs/outgoing
    {:keys [::specs/pipe-to-child-size]
     :as incoming
     :or {pipe-to-child-size K/k-64}} ::specs/incoming
    :as state}
   logger
   parent-cb
   child-cb]
  (let [state (update state
                      ::log/state
                      #(log/debug %
                                  ::start!
                                  "Starting an I/O loop"
                                  {::specs/message-loop-name message-loop-name
                                   ::specs/pipe-from-child-size pipe-from-child-size
                                   ::specs/pipe-to-child-size pipe-to-child-size}))
        ;; TODO: Need to tune and monitor this execution pool
        ;; c.f. ztellman's dirigiste
        ;; For starters, I probably at least want the option to
        ;; use an instrumented executor.
        ;; Actually, that should probably be the default.
        executor (exec/utilization-executor 0.9 (utils/get-cpu-count))
        s (strm/stream)
        s (strm/onto executor s)
        ;; Q: Is there any meaningful difference between
        ;; using PipedIn-/Out-putStream pairs vs ByteArrayIn-/Out-putStreams?
        ;; A: Absolutely!
        ;; BAOS writes to a single byte array. You can get that array, but
        ;; there doesn't seem to be a good way to reset it.
        ;; The Piped stream pairs handle coordination so the reader gets
        ;; a stream of bytes.
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
        [main-log-state io-log-state] (log/fork (::log/state state) ::io-handle)
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
                   ::specs/to-child-done? (dfrd/deferred)
                   ::specs/from-parent-trigger (strm/stream)
                   ::specs/executor executor
                   ::log/logger logger
                   ::specs/message-loop-name message-loop-name
                   ::log/state-atom (atom io-log-state)
                   ::specs/stream s}
        [main-log-state child-log-state] (log/fork main-log-state message-loop-name)]
    ;; We really can't rely on what this returns.
    ;; Aside from the fact that we shouldn't, since it's called for side effects
    (start-event-loops! io-handle (assoc state
                                         ::log/state
                                         child-log-state))
    {::specs/io-handle io-handle
     ::log/state (log/flush-logs! logger
                                  (log/info main-log-state
                                            ::start!
                                            "Started an event loop"
                                            {::specs/message-loop-name message-loop-name
                                             ::specs/stream s}))}))

(s/fdef get-state
        :args (s/cat :io-handle ::specs/io-handle
                     :time-out nat-int?
                     :timed-out-value any?)
        ;; TODO: Add a fn piece that clarifies that the
        ;; :timed-out :ret possibility will match the
        ;; :timed-out-value :arg
        :ret (s/or :success ::specs/state
                   :timed-out any?)
        ;; If this timed out, should return the supplied
        ;; time-out parameter (or ::timed-out, if none).
        ;; Otherwise, the requested state.
        ;; TODO: Verify that this spec does what I expect.
        :fn (fn [{:keys [:args :ret]}]
              (if-let [failed (:timed-out ret)]
                (= failed (:time-out args))
                (:success ret))))
(defn get-state
  "Synchronous equivalent to deref"
  ;; This really involves side-effects
  ;; Q: Rename to get-state!
  ([{:keys [::log/logger
            ::specs/message-loop-name
            ::specs/stream]
     log-state-atom ::log/state-atom}
    timeout
    failure-signal]
   (swap! log-state-atom
          #(log/debug %
                      ::querying
                      "Submitting get-state query"
                      {::specs/message-loop-name message-loop-name
                       ::specs/stream stream}))
   (let [state-holder (dfrd/deferred)
         req (strm/try-put! stream [::query-state state-holder] timeout failure-signal)]
     ;; FIXME: Switch to using dfrd/chain instead
     (dfrd/on-realized req
                       (fn [success]
                         ;; FIXME: Need to cope with a put! timeout (which is not
                         ;; a failure)
                         ;; i.e. (if (= success failure-signal) (short-circuit))
                         (swap! log-state-atom
                                #(log/flush-logs! logger
                                                  (log/debug %
                                                             ::succeeded
                                                             "get-state query submitted"
                                                             {::result success
                                                              ::specs/message-loop-name message-loop-name}))))
                       (fn [failure]
                         ;; Q: Can this ever fail?
                         (swap! log-state-atom
                                #(log/flush-logs! logger
                                                  (if (instance? Throwable failure)
                                                    (log/exception %
                                                                   failure
                                                                   ::exceptional-failure
                                                                   "Submitting get-state query failed"
                                                                   {::specs/message-loop-name message-loop-name})
                                                     (log/error %
                                                                ::non-exceptional-failure
                                                                "Submitting get-state failed mysteriously"
                                                                {::result failure
                                                                 ::specs/message-loop-name message-loop-name}))))
                         (deliver state-holder failure)))
     ;; Need to sync log-state with local-logs.
     ;; This really should be less complex, but a better approach isn't coming to mind.
     (let [{log-state ::log/state
            :as result} (deref state-holder timeout failure-signal)
           main-log-state-atom (atom log-state)]
       (swap! log-state-atom (fn [io-log-state]
                               (let [[main-log-state io-log-state] (log/synchronize log-state io-log-state)]
                                 (reset! main-log-state-atom main-log-state)
                                 io-log-state)))
       (assoc result ::log/state @main-log-state-atom))))
  ([stream-holder]
   (get-state stream-holder 500 ::timed-out)))

(s/fdef halt!
        :args (s/cat :io-handle ::specs/io-handle)
        :ret any?)
(defn halt!
  [{:keys [::log/logger
           ::specs/message-loop-name
           ::specs/stream
           ::specs/from-child
           ::specs/child-out]
    :as io-handle}]
  ;; TODO: We need the log-state here, so we can append to it.
  ;; The obvious choice seems to involve calling get-state.
  (let [{log-state ::log/state} (get-state io-handle)
        my-logs (log/fork log-state)
        my-logs (log/info my-logs
                          ::halt!
                          "I/O Loop Halt Requested"
                          {::specs/message-loop-name message-loop-name})
        my-logs (try
                  (strm/close! stream)
                  (doseq [pipe [from-child
                                child-out]]
                    (.close pipe))
                  (log/info my-logs
                            ::halt!
                            "Halt initiated"
                            {::specs/message-loop-name message-loop-name})
                  (catch RuntimeException ex
                    (log/exception my-logs
                                   ex
                                   ::halt!
                                   "Signalling halt failed"
                                   {::specs/message-loop-name message-loop-name})))]
    (log/flush-logs! logger my-logs)))

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
  [{:keys [::log/logger
           ::specs/child-out
           ::specs/from-child
           ::specs/message-loop-name
           ::specs/pipe-from-child-size]
    log-state-atom ::log/state-atom
    :as io-handle}
   array-o-bytes]
  (swap! log-state-atom
         #(log/debug % ::child-> "Top" {::specs/message-loop-name message-loop-name}))
  (when-not from-child
    (let [prelog (utils/pre-log message-loop-name)]
      (throw (ex-info (str prelog "Missing PipedOutStream from child inside io-handle")
                      {::io-handle io-handle}))))
  (let [buffer-space (- pipe-from-child-size (.available child-out))
        n (count array-o-bytes)]
    ;; It seems like it would be nice to be able to block here, based
    ;; on how many bytes we really have buffered internally.
    ;; At this point, we're really in the equivalent of the
    ;; reference implementation's "real" child process.
    ;; All it has is a pipe that we promise to never block.
    ;; Although we might send back "try again later"
    ;; responses.
    (swap! log-state-atom
           #(log/debug %
                       ::child->
                       "Trying to send bytes from child"
                       {::message-size n
                        ::buffer-space-available buffer-space
                        ::specs/message-loop-name message-loop-name}))
    (let [result
          (if (< buffer-space n)
            (do
              (swap! log-state-atom
                     #(log/warn %
                                ::child->
                                "Not enough room to write.\nRefusing to block"))
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
              (swap! log-state-atom
                     #(log/debug %
                                 ::child->
                                 "Buffered"
                                 {::specs/message-loop-name message-loop-name
                                  ::message-size n}))
              true))]
      (swap! log-state-atom
             #(log/flush-logs! logger %))
      result)))

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
  [{:keys [::log/logger
           ::specs/message-loop-name
           ::specs/stream]
    log-state-atom ::log/state-atom
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
    (swap! log-state-atom
           #(log/info %
                      ::parent->
                      "Top"
                      {::specs/message-loop-name message-loop-name}))
    (try
      (let [success (strm/put! stream [::parent-> array-o-bytes])]
        (swap! log-state-atom
               #(log/debug %
                           ::parent->
                           "Parent put!. Setting up on-realized handler"
                           {::specs/message-loop-name message-loop-name}))
        (dfrd/on-realized success
                          (fn [x]
                            (swap! log-state-atom
                                   #(log/flush-logs! logger (log/debug %
                                                                       ::parent->
                                                                       "Buffered bytes from parent"
                                                                       ;; Note that this probably should run on a
                                                                       ;; totally different thread than the outer function
                                                                       {::triggered-from prelog
                                                                        ::specs/message-loop-name message-loop-name}))))
                          (fn [x]
                            (swap! log-state-atom
                                   #(log/flush-logs! logger (log/warn %
                                                                      ::parent->
                                                                      "Failed to buffer bytes from parent"
                                                                      {::triggered-from prelog
                                                                       ::specs/message-loop-name message-loop-name})))))
        (swap! log-state-atom
               #(log/debug %
                           ::parent->
                           "bottom"
                           {::specs/message-loop-name message-loop-name}))
        nil)
      (catch Exception ex
        (swap! log-state-atom
               #(log/flush-logs! logger
                                 (log/exception %
                                                ex
                                                ::parent->
                                                "Sending message to parent failed"
                                                {::specs/message-loop-name message-loop-name})))))))

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
  #_(comment (child-> io-handle ::specs/normal))
  (.close from-child))
