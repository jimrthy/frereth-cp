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
;;; Specs

(s/def ::timer-canceller #{::completed
                           ::from-child
                           ::from-parent})

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

;;;  634-643: try closing pipe to child: (DJB)
;;;           Well, maybe. If we're done with it

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
            ::specs/strm-hwm
            ::specs/un-sent-blocks
            ::specs/un-ackd-blocks
            ::specs/want-ping]} ::specs/outgoing
    :keys [::specs/message-loop-name
           ::specs/recent]
    :as state}]
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
        ;; TODO: This seems to be screaming for cond->
        min-resend-time (+ last-block-time n-sec-per-block)
        _ (log/debug (cl-format nil
                                (str "~a (~a) at ~:d: Minimum resend time: ~:d\n"
                                     "which is ~:d nanoseconds\n"
                                     "after last block time ~:d.\n"
                                     "Recent was ~:d ns in the past")
                                message-loop-name
                                (Thread/currentThread)
                                now
                                min-resend-time
                                n-sec-per-block
                                ;; I'm calculating last-block-time
                                ;; incorrectly, due to a misunderstanding
                                ;; about the name.
                                ;; It should really be the value of
                                ;; recent, set immediately after
                                ;; I send a block to parent.
                                last-block-time
                                (- now recent)))
        default-next (+ recent (utils/seconds->nanos 60))  ; by default, wait 1 minute
        _ (log/debug (cl-format nil
                                "~a: Default +1 minute: ~:d from ~:d"
                                message-loop-name
                                default-next
                                recent))
        ;; Lines 286-289
        _ (log/debug (str message-loop-name ": Scheduling based on want-ping value '" want-ping "'"))
        next-based-on-ping (if want-ping
                             ;; Go with the assumption that this matches wantping 1 in the original
                             ;; I think the point there is for the
                             ;; client to give the server 1 second to start up
                             (if (= want-ping ::specs/second-1)
                               (+ recent (utils/seconds->nanos 1))
                               (min default-next min-resend-time))
                             default-next)
        _ (log/debug (cl-format nil
                                "~a: Based on ping settings, adjusted next time to: ~:d"
                                message-loop-name
                                next-based-on-ping))
        ;; Lines 290-292
        ;; Q: What is the actual point to this?
        ;; (the logic seems really screwy, but that's almost definitely
        ;; a lack of understanding on my part)
        next-based-on-eof (let [un-ackd-count (count un-ackd-blocks)
                                un-sent-count(count un-sent-blocks)]
                            (if (and (< (+ un-ackd-count
                                           un-sent-count)
                                        K/max-outgoing-blocks)
                                     (if send-eof
                                       (not send-eof-processed)
                                       (or (< 0 un-ackd-count)
                                           (< 0 un-sent-count))))
                              (let [next-time
                                    (min next-based-on-ping min-resend-time)]
                                (log/debug "EOF criteria:\nun-ackd-count:"
                                           un-ackd-count
                                           "\nun-sent-count:"
                                           un-sent-count
                                           "\nsend-eof:"
                                           send-eof
                                           "\nsend-eof-processed:"
                                           send-eof-processed)
                                next-time)
                              next-based-on-ping))
        _ (log/debug (cl-format nil
                                "~a: Due to EOF status: ~:d"
                                message-loop-name
                                next-based-on-eof))
        ;; Lines 293-296
        rtt-resend-time (+ earliest-time rtt-timeout)
        next-based-on-earliest-block-time (if (and (not= 0 earliest-time)
                                                   (> rtt-resend-time
                                                      min-resend-time))
                                            (min next-based-on-eof rtt-resend-time)
                                            next-based-on-eof)
        _ (log/debug (cl-format nil
                                "~a: Adjusted for RTT: ~:d"
                                 message-loop-name
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
        _ (log/debug (cl-format nil
                                "~a: After [pretending to] adjusting for closed/ignored child watcher: ~:d"
                                message-loop-name
                                based-on-closed-child))
        ;; Lines 302-305
        actual-next (max based-on-closed-child recent)]
    actual-next))

;;; I really want to move schedule-next-timeout to flow-control.
;;; But it has a circular dependency with trigger-from-timer.
;;; Which...honestly also belongs in there.
;;; Q: How much more badly would this break things?
;;; TODO: Find out.
(declare trigger-from-timer)
(s/fdef schedule-next-timeout!
        :args (s/cat :state ::specs/state
                     :state-agent ::specs/state-agent)
        :ret ::specs/state)
(defn schedule-next-timeout!
  [{:keys [::specs/message-loop-name
           ::specs/recent]
    {:keys [::specs/next-action]
     :as flow-control} ::specs/flow-control
    :as state}
   state-agent]
  {:pre [recent]}
  (let [now (System/nanoTime)]
    (log/debug (cl-format nil
                          "~a (~a): Top of scheduler at ~:d"
                          message-loop-name
                          (Thread/currentThread)
                          now))
    (if (not= next-action ::completed)
      (do
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
              delta (inc (utils/nanos->millis delta-nanos))
              delta_f (float delta)  ; For printing
              next-action (dfrd/deferred)
              result (assoc-in state
                               [::specs/flow-control ::specs/next-action]
                               next-action)]
          (log/debug (cl-format nil
                                "~a: Initially calculated scheduled delay: ~:d nanoseconds after ~:d vs. ~:d"
                                message-loop-name
                                scheduled-delay
                                recent
                                now))
          (dfrd/on-realized next-action
                            (fn [success]
                              (let [fmt (str "~a: Timer for ~:d ms "
                                             "after ~:d cancelled, "
                                             "presumably "
                                             "because input arrived "
                                             "from elsewhere:\n~a")]
                                (log/debug (cl-format nil
                                                      fmt
                                                      message-loop-name
                                                      delta_f
                                                      now
                                                      success))))
                            (fn [failure]
                              (if (instance? TimeoutException failure)
                                (do
                                  ;; This actually wasn't a failure.
                                  ;; It just tripped the timer, so it's
                                  ;; time to do it again.
                                  (log/debug (cl-format nil
                                                        "~a: Timer for ~:d ms after ~:d timed out. Re-triggering I/O"
                                                        message-loop-name
                                                        delta_f
                                                        now))
                                  (send state-agent trigger-from-timer state-agent))
                                (do
                                  (log/error failure (cl-format nil
                                                                "~a: Waiting on timer to trigger I/O in ~:d ms after ~:d"
                                                                delta_f
                                                                now))
                                  (send state-agent (fn [_]
                                                      failure))))))
          (log/debug (cl-format nil
                                "~a: Setting timer to trigger in ~:d ms (vs ~:d scheduled)"
                                message-loop-name
                                delta_f
                                (float (utils/nanos->millis scheduled-delay))))
          ;; Annoying detail: If I provide a value that I think is reasonable
          ;; here, it counts as a success.
          (dfrd/timeout! next-action delta)
          result))
      (do
        (log/debug (str message-loop-name ": 'next-action' flagged complete."))
        state))))

(s/fdef start-event-loops!
        :args (s/cat :state-agent ::specs/state-agent
                     :state ::specs/state)
        :ret ::specs/state)
;;;          205-259 fork child
(defn start-event-loops!
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
    ;; This is nowhere near as exciting as I
    ;; expect every time I look at it
    (-> state
        (assoc
         ;; This covers line 260
         ::specs/recent recent)
        (schedule-next-timeout! state-agent))))

(s/fdef cancel-timer!
        :args (s/cat :state ::specs/state
                     :source ::timer-canceller)
        :ret any?)
(defn cancel-timer!
  "Cancels the next pending timer"
  [{{:keys [::specs/next-action]} ::specs/flow-control
    :keys [::specs/message-loop-name]
    :as state}
   source]
  (log/debug (str message-loop-name
                  ": Cancelling(?) "
                  next-action
                  " because "
                  source))
  (when (and next-action
             (not= next-action ::completed))
    ;; Altering the agent's state outside the agent like this
    ;; is wrong on pretty much every level.
    ;; But I'm seeing at least 1 timer loop go through before
    ;; this can, and that's wasting 9-10 ms.

    ;; This doesn't help much for the initial client loop that's
    ;; eagerly waiting for input from the child. I think there's
    ;; something badly wrong with the details behind that.

    (log/info (str message-loop-name ": cancelling I/O timer "
                   next-action
                   ", a " (class next-action)))
    (dfrd/success! next-action source)))

(s/fdef trigger-output
        :args (s/cat :state-agent ::specs/state-agent
                     :state ::specs/state)
        :ret ::specs/state)
(defn trigger-output
  [state-agent
   {{:keys [::specs/->child]} ::specs/incoming
    {:keys [::specs/next-action]} ::specs/flow-control
    :keys [::specs/message-loop-name]
    :as state}]
  (log/debug (str message-loop-name
                  " (thread "
                  (Thread/currentThread)
                  "): Triggering Output"))
  ;; Originally, it seemed like it would make sense to cancel
  ;; the timer here, to avoid duplicating the call when I
  ;; get input from either the parent or the child.
  ;; Doing it that way entails too much delay. If the
  ;; timer is running in a tight loop, it might trigger
  ;; several more times before they get around to
  ;; actually calling this.
  (let [state
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
          ;; The timeout on that may completely change
          ;; when the child schedules another send,
          ;; or a message arrives from parent to
          ;; update the RTT.
          (to-parent/maybe-send-block! state))]
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
    (comment
      (let [unsent-blocks-from-child? (from-child/blocks-not-sent? state)]
        (if unsent-blocks-from-child?
          (recur state)
          (schedule-next-timeout! state))))
    (log/debug (str message-loop-name ": Scheduling next timeout"))
    ;; This is taking a ludicrous amount of time.
    (let [start (System/nanoTime)
          ;; TODO: How much should I blame on logging?
          result (schedule-next-timeout! state state-agent)
          end (System/nanoTime)]
      (utils/debug message-loop-name
                   "Scheduling next timeout took"
                   (- end start)
                   " nanoseconds")
      result)))

(s/fdef trigger-from-child
        :args (s/cat :state ::specs/state
                     :state-agent ::specs/state-agent
                     :array-o-bytes bytes?)
        :ret ::specs/state)
(defn trigger-from-child
  [{{:keys [::specs/strm-hwm]
     :as outgoing} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}
   state-agent
   array-o-bytes]
  {:pre [array-o-bytes]}
  ;; The downside to doing this here (and trigger-from-parent)
  ;; is that we could easily hit a timeout between the time
  ;; we call send and this gets called.
  (cancel-timer! state ::from-child)
  (log/info (str message-loop-name
                 ": trigger-from-child\nSent stream address: "
                 strm-hwm))
  (let [state' (if (from-child/room-for-child-bytes? state)
                 (do
                   (log/debug (str message-loop-name
                                   " ("
                                   (Thread/currentThread)
                                   "): There is room for another message"))
                   (let [result (from-child/consume-from-child state array-o-bytes)]
                     result))
                 ;; trigger-output does some state management, even
                 ;; if we discard the incoming bytes because our
                 ;; buffer is full
                 ;; TODO: Need a way to signal the child to
                 ;; try again shortly
                 (do
                   (log/error "Discarding incoming bytes, silently")
                   state))]
    ;; Q: worth checking output conditions here.
    ;; It's pointless to call this if we just have
    ;; to wait for the timer to expire.
    (trigger-output
     state-agent
     state')))

(s/fdef trigger-from-parent
        :args (s/cat :state ::specs/state
                     :state-agent ::specs/state-agent
                     :array-o-bytes bytes?)
        :ret ::specs/state)
(defn trigger-from-parent
  "Message block arrived from parent. Agent has been handed work"
  ;; TODO: Move as much of this as possible into from-parent
  ;; The only reason I haven't already moved the whole thing
  ;; is that we need to use to-parent to send the ACK, and I'd
  ;; really rather not introduce dependencies between those namespaces
  [{{:keys [::specs/->child]} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}
   state-agent  ; so we can forward downstream to trigger the next state change
   ^bytes message]
  {:pre [->child]}

  ;; It seems like I should call cancel-timer! here.
  ;; It's safer (albeit slower) than calling it immediately
  ;; before we get into this agent thread, which is supposed
  ;; to be about side-effects.
  ;; Mingling this sort of interaction is terrible.
  ;; TODO: It's time to ditch the agent approach in this segment and
  ;; just embrace manifold.
  (cancel-timer! state ::from-parent)
  (log/debug (str message-loop-name ": Incoming from parent"))

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
                         (assoc-in state
                                   [::specs/incoming ::specs/parent->buffer]
                                   message))
          state' (to-child/forward! ->child (or pre-processed
                                                state))]
      (trigger-output state-agent state'))
    (catch RuntimeException ex
      (log/error ex
                 "Trying to cope with a message arriving from parent"))))

(defn trigger-from-timer
  [{:keys [::specs/message-loop-name]
    :as state}
   state-agent]
  (log/debug (str message-loop-name ": I/O triggered by timer"))
  ;; I keep thinking that I need to check data arriving from
  ;; the child, but the main point to this logic branch is
  ;; to resend an outbound block that hasn't been ACK'd yet.
  (trigger-output state-agent state))

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
                                 ::specs/rtt-timeout K/sec->n-sec}
           ::specs/incoming {::specs/->child child-callback
                             ::specs/->child-buffer []
                             ::specs/gap-buffer (to-child/build-gap-buffer)
                             ::specs/receive-eof false
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
                                                        K/initial-max-block-length)
                             ::specs/next-message-id 1
                             ::specs/->parent parent-callback
                             ::specs/ackd-addr 0
                             ;; Q: Does this make any sense at all?
                             ;; It isn't ever going to change, so I might
                             ;; as well just use the hard-coded value
                             ;; in constants and not waste the extra time/space
                             ;; sticking it in here.
                             ;; That almost seems like premature optimization,
                             ;; but this approach seems like serious YAGNI.
                             ::specs/send-buf-size K/send-byte-buf-size
                             ::specs/send-eof false
                             ::specs/send-eof-acked false
                             ::specs/send-eof-processed false
                             ::specs/strm-hwm 0
                             ::specs/total-blocks 0
                             ::specs/total-block-transmissions 0
                             ::specs/un-ackd-blocks (build-un-ackd-blocks)
                             ::specs/un-sent-blocks PersistentQueue/EMPTY
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
     (throw (ex-info "Starting timed out"
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
         :keys [::specs/message-loop-name]
         :as state} @state-agent]
    (log/info "Halting" message-loop-name)
    ;; This seems to work on the server, but it fails when
    ;; the client's cranking through messages faster than
    ;; emacs can track.
    (cancel-timer! state ::completed)
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
  (let [state @state-agent
        {:keys [::specs/message-loop-name]} state]
    ;; The formatting here is past being repetitive
    ;; enough to justify its own family of utils
    ;; functions
    (log/debug (str message-loop-name
                    " (thread "
                    (Thread/currentThread)
                    "): Incoming message from child to\n"
                    state))
    ;; In a lot of ways, it seems like it would be more
    ;; elegant to have this (and parent->) call succeed!
    ;; on next-action.
    ;; Then have the handler set up for that in the
    ;; scheduler check the success value and do the
    ;; send[-off].
    ;; Sticking with this approach for now, since I'm
    ;; trying to make incremental changes, but...it
    ;; needs more thought.
    ;; But don't modify state outside the agent handler/thread
    #_(cancel-timer! state ::from-child)
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
    ;; from blocking (according to the spec)
    (send state-agent trigger-from-child state-agent array-o-bytes)))

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

    ;; trigger-from-parent is expecting to have a ::->child-buffer key
    ;; that's really a vector that we can just conj onto.
    (let [{{:keys [::specs/->child-buffer]} ::specs/incoming
           :keys [::specs/message-loop-name]
           :as state} @state-agent]
      (log/info (str message-loop-name
                     " ("
                     (Thread/currentThread)
                     "): Top of parent->"))
      ;; It seems very wrong to do this here. But I really need
      ;; it to happen as fast as possible, because it tends to
      ;; get triggered again while I'm in the middle of other
      ;; things when it's running aggressively at the beginning.
      ;; Actually, this adds back in all the nasty multi-
      ;; threading issues that clojure should prevent.
      ;; I think I may have to ditch agents completely to make
      ;; this work at all.
      ;; For now, at least do this inside the agent thread instead.
      #_(cancel-timer! state ::from-parent)
      ;; One flaw with these buffer checks stems from what
      ;; happens with a pure ACK. I think I may have botched
      ;; this aspect of the translation.
      (if (< (count ->child-buffer) max-child-buffer-size)
        (let [previously-buffered-message-bytes (reduce + 0
                                                    (map (fn [^bytes buf]
                                                           (count buf))
                                                         ->child-buffer))]
          (log/debug (str message-loop-name
                          ": There's room in the child buffer; possibly processing"))
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
              ;; into the agent handler.
              ;; That impulse seems wrong. Based on preliminary numbers,
              ;; any filtering I can do outside an an agent send is a win.
              (log/debug (str message-loop-name
                              ": Message is small enough. Tell agent to handle"))
              ;; See comments in child-> re: send vs. send-off
              (send state-agent trigger-from-parent state-agent buf))
            (do
              ;; TODO: If there's
              (log/warn (str "Message too large\n"
                             "Incoming message is " incoming-size
                             " / " K/max-msg-len))
              (schedule-next-timeout! state state-agent)
              state-agent)))
        (do
          (log/warn (str message-loop-name
                         ": Child buffer overflow\n"
                         "Have " (count ->child-buffer)
                         "/"
                         max-child-buffer-size
                         " messages buffered. Wait!"))
          (schedule-next-timeout! state state-agent)
          state-agent)))))
