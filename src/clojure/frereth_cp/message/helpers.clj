(ns frereth-cp.message.helpers
  "Top-level message helpers"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.util :as utils]
            [frereth.weald
             [logging :as log]
             [specs :as weald]])
  (:import io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::n nat-int?)

(s/def ::block-counting-state (s/merge ::specs/state
                                       (s/keys :req [::n])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef flag-ackd-blocks
        :args (s/cat :start int?
                     :stop int?
                     :state ::block-counting-state
                     :block ::specs/block)
        :ret ::block-counting-state)
(declare mark-block-ackd)
(defn flag-ackd-blocks
  [start stop
   state
   {:keys [::specs/start-pos
           ::specs/transmissions
           ::specs/buf]
    :as block}]
  {:pre [transmissions]}
  (let [state (update state
                      ::weald/state
                      #(log/debug %
                                  ::flag-ackd-blocks
                                  ""
                                  {::start start
                                   ::stop stop
                                   ::block block}))]
    (let [length (.readableBytes buf)]
      (if (<= start
              start-pos
              (+ start-pos length)
              stop)
        (-> state
            (update ::weald/state
                    #(log/trace %
                                ::flag-ackd-blocks
                                "(it's a match)"))
            (update ::specs/outgoing
                    (fn [cur]
                      (-> cur
                          (mark-block-ackd block)
                          (update ::specs/total-blocks inc)
                          (update ::specs/total-block-transmissions + transmissions)))))
        state))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef earliest-block-time
        :args (s/cat :message-loop-name string?
                     :log-state ::weald/state
                     :blocks ::specs/un-ackd-blocks)
        :ret (s/keys :req [::specs/earliest-time
                           ::weald/state]))
(defn earliest-block-time
  "Calculate the earliest time

Based on earliestblocktime_compute, in lines 138-153
"
  [message-loop-name log-state un-acked-blocks]
  ;;; Comment from DJB:
  ;;; XXX: use priority queue
  ;; (That's what led to me using the sorted-set)

  ;; This gets called right after we flag the blocks
  ;; that have been ACK'd
  ;; TODO: Switch from remove to set/select
  (let [un-flagged (remove ::specs/ackd? un-acked-blocks)
        prelog (utils/pre-log message-loop-name)
        log-state (log/debug log-state
                             ::earliest-block-time
                             "Calculating min-time across un-ACK'd blocks"
                             {::specs/message-loop-name message-loop-name
                              ::un-ackd-count (count un-flagged)})]
    {::weald/state log-state
     ::specs/earliest-time
     (if (< 0 (count un-flagged))
       (let [original (apply min (map ::specs/time
                                      ;; In the original,
                                      ;; time 0 means it's been ACK'd and is ready to discard
                                      ;; Having the time serve dual purposes
                                      ;; kept tripping me up.
                                      un-flagged))
             ;; Should be able to do this because un-ackd-blocks is
             ;; a set that's sorted by :time.
             ;; Probably can't, because un-flagged is a lazy seq
             ;; that could throw out that ordering.
             ;; This seems to be working.
             ;; TODO: Switch to this version
             likely-successor (-> un-flagged first ::specs/time)]
         (when (not= original likely-successor)
           ;; TODO: Get rid of this and calculating original.
           ;; At this point, I'm pretty confident that it's a complete waste
           ;; of CPU cycles.
           (throw (ex-info "Time calculation mismatch"
                           {::expected original
                            ::actual likely-successor})))
         original)
       0)}))

(s/fdef drop-ackd!
        :args (s/cat :acked ::specs/state)
        :ret ::specs/state)
(defn drop-ackd!
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/ackd-addr
            ::specs/send-eof
            ::specs/un-ackd-blocks]
     :as outgoing} ::specs/outgoing
    :as state}]
  ;; To match the next block, the main point is to discard
  ;; the first sequence of blocks that have been ACK'd
  ;; drop-while seems obvious
  ;; However, we also need to update ackd-addr
;;;           168-176: Updates globals for adjacent blocks that
;;;                    have been ACK'd
;;;                    This includes some counters that seem important:
;;;                        blocknum
;;;                        sendacked (ackd-addr, here)
;;;                        sendbytes (obsoleted replaced by strm-hwm)
;;;                        sendprocessed (pointless, due to un-*-blocks
;;;                        blockfirst
  (let [log-prefix (utils/pre-log message-loop-name)
        to-drop (filter ::specs/ackd? un-ackd-blocks)
        to-keep (remove ::specs/ackd? un-ackd-blocks)
        state (update state
                      ::weald/state
                      #(log/debug %
                                  ::drop-ackd!
                                  "Keeping un-ACKed"
                                  {::specs/message-loop-name message-loop-name
                                   ::retention-count (count to-keep)
                                   ::retaining (reduce (fn [acc b]
                                                         (str acc "\n" b))
                                                       ""
                                                       to-keep)
                                   ::dropping (count un-ackd-blocks)}))
        dropped-block-lengths (apply + (map (fn [b]
                                              (-> b ::specs/buf .readableBytes))
                                            to-drop))
        kept (reduce (fn [acc dropped]
                       (disj acc dropped))
                     un-ackd-blocks
                     to-drop)
        state (-> state
                  (update ::weald/state
                          #(log/warn %
                                     ::drop-ackd!
                                     "Really should be smarter re: ::ackd-addr here"
                                     {::specs/ackd-addr ackd-addr
                                      ::specs/message-loop-name message-loop-name}))
                  ;; Note that this really needs to be the stream address of the
                  ;; highest contiguous block that's been ACK'd.
                  ;; This makes any scheme for ACK'ing pieces out of
                  ;; order more complicated.
                  ;; As-is, this is really tracking the count of bytes
                  ;; that have been ACK'd.
                  ;; For these purposes, that doesn't accomplish much.
                  (update-in [::specs/outgoing ::specs/ackd-addr] + dropped-block-lengths)
                  (assoc-in [::specs/outgoing ::specs/un-ackd-blocks] kept))
;;;           183: earliestblocktime_compute()
        state (reduce (fn [state block]
                        ;; This is why the function name has a !
                        (let [^ByteBuf buffer (::specs/buf block)]
                          (.release buffer))
                        (update state
                                ::weald/state
                                #(log/debug %
                                            ::drop-ackd!
                                            "Releasing associated buf"
                                            block)))
                      state
                      to-drop)]
    (let [{:keys [::specs/earliest-time]
           log-state ::weald/state} (earliest-block-time message-loop-name
                                                        (::weald/state state)
                                                        un-ackd-blocks)]
      (assoc (assoc-in state
                       [::specs/outgoing ::specs/earliest-time]
                       earliest-time)
             ::weald/state log-state))))

;;;; 155-185: acknowledged(start, stop)
(s/fdef mark-ackd-by-addr
        :args (s/cat :state ::specs/state
                     :start int?
                     :stop int?)
        :ret ::specs/state)
(defn mark-ackd-by-addr
  "Mark sent blocks between positions start and stop as ACK'd

Based [cleverly] on acknowledged(), running from lines 155-185"
  [{{:keys [::specs/un-ackd-blocks
            ::specs/send-eof
            ::specs/send-eof-acked
            ::specs/strm-hwm]} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}
   start
   stop]
  ;; TODO: If un-ackd blocks is empty, we can just short-circuit this
  (let [;; This next log message is annoying right now, because
        ;; it seems very repetitive and pointless.
        ;; That's probably because we aren't taking advantages of
        ;; any of these addressing options and really only ACK'ing
        ;; the high-water-mark stream address.
        state (update state
                      ::weald/state
                      #(log/debug %
                                  ::mark-ackd-by-addr
                                  "Setting ACK flags on blocks between start and stop"
                                  {::start start
                                   ::stop stop
                                   ::specs/message-loop-name message-loop-name}))
        state (if (< strm-hwm
                     (if (= send-eof ::specs/false)
                       stop
                       ;; Protocol is to ACK 1 past the final
                       ;; stream address for EOF
                       (inc stop)))
                ;; This is pretty definitely a bug.
                ;; It seems to only really turn up during EOF transitions,
                ;; so it's probably just my broken logic
                ;; TODO: Figure out something more extreme to do here.
                (update state
                        ::weald/state
                        #(log/error %
                                    ::mark-ackd-by-addr
                                    "Other side ACK'd bytes we haven't sent yet"
                                    {::specs/strm-hwm strm-hwm
                                     ::stop stop
                                     ::specs/send-eof send-eof}))
                state)]
    (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
      (as-> (reduce (partial flag-ackd-blocks start stop)
                    state
                    un-ackd-blocks) state
        (update state
                ::weald/state
                #(log/debug %
                            ::mark-ackd-by-addr
                            "Done w/ initial flag reduce"
                            (dissoc state ::weald/state)))
        ;; Again, gaps kill it
        (update state
                ::weald/state
                #(log/warn %
                           ::mark-ackd-by-addr
                           "This treatment of ::ackd-addr also fails"
                           {::specs/message-loop-name message-loop-name}))
        (assoc-in state
                  [::specs/outgoing ::specs/ackd-addr]
                  stop))

      ;; else:
      ;; Note that it might have ACK'd the previous address.
      ;; There's another wrinkle in here:
      ;; It ACK's the message ID as soon as it's received.
      ;; It doesn't ACK the actual stream address until the
      ;; bytes have been written to the child.
      ;; We have to choose between the possibility that the
      ;; buffer dies prematurely (meaning we've ACK'd blocks
      ;; that never actually made it to the child) vs. risking
      ;; its death after the bytes have been written.
      ;; Classic networking trade-off.
      ;; Even if we wait to send the ACK, there's no guarantee
      ;; that the child "process" didn't die immediately after
      ;; reading, which means the bytes would have disappeared
      ;; anyway.
      ;; That sort of consistency really needs to be handled
      ;; at the application level.
      ;; The bytes made it over the wire. That's the important
      ;; thing at this layer.

      ;; No real change
      (update state
              ::weald/state
              #(log/info %
                         ::mark-ackd-by-addr
                         "Nothing ACK'd by address"
                         {::specs/message-loop-name message-loop-name})))))

(s/fdef mark-block-ackd
        :args (s/cat :outgoing ::specs/outgoing
                     :block ::specs/block)
        :ret ::specs/outgoing)
(defn mark-block-ackd
  "Flag block ACK'd in the un-ackd set"
  [{:keys [::specs/un-ackd-blocks]
    :as outgoing}
   block]
  (assert (contains? un-ackd-blocks block)
          (str "Can't mark\n"
               block
               "\nas ACK'd because it is not in\n"
               un-ackd-blocks))
  ;; This approach seems annoyingly inefficient.
  ;; Q: Would it be faster/more efficient to convert
  ;; un-ackd-blocks to a sorted-map? (The trick there is
  ;; that I'd need to pick a key. start-pos seems pretty
  ;; obvious, but I don't have that readily available
  ;; when I initially create the block).
  ;; Q: What about the time? Since that's what I'm
  ;; sorting by anyway.
  ;; TODO: Worry about this later. I'm sure I have
  ;; bigger bottlenecks that will show up once
  ;; things run well enough to stick a profiler on it.
  (-> outgoing
      (update ::specs/un-ackd-blocks disj block)
      (update ::specs/un-ackd-blocks
              conj
              (assoc block
                     ::specs/ackd?
                     true))))

;;; Q: Would these wrappers make more sense under shared/bit-twiddling?
;;; A: Yes.
;;; TODO: Almost definitely need to cope with 2s complements.

(defn read-long
  [^ByteBuf bb]
  (.readLong bb))

(defn read-ulong
  [^ByteBuf bb]
  (let [incoming (.readLong bb)]
    (assert (<= 0 incoming) "Need to cope with the stupidity of java not having unsigned numbers")
    incoming))

(defn read-int
  [^ByteBuf bb]
  (.readInt bb))

(defn read-uint
  [^ByteBuf bb]
  (.readUnsignedInt bb))

(defn read-short
  [^ByteBuf bb]
  (.readShort bb))

(defn read-ushort
  [^ByteBuf bb]
  (.readUnsignedShort bb))
