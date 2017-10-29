(ns frereth-cp.message.helpers
  "Top-level message helpers"
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.util :as utils])
  (:import io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::n nat-int?)

(s/def ::block-counting-state (s/merge ::specs/state
                                       (s/keys :req [::n])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef flag-acked-blocks
        :args (s/cat :start int?
                     :stop int?
                     :acc ::block-counting-state
                     :block ::specs/block)
        :ret ::block-counting-state)
(declare mark-block-ackd)
(defn flag-acked-blocks
  [start stop
   acc
   {:keys [::specs/start-pos
           ::specs/transmissions]
    :as block}]
  {:pre [transmissions]}
  (log/debug (str "flag-acked-blocks: " start "-" stop
                  " for\n" block))
  (if (<= start
          start-pos
          (+ start-pos (::specs/length block))
          stop)
    (do
      (log/trace "(it's a match)")
      (update acc
              ::specs/outgoing
              (fn [cur]
                (-> cur
                    (mark-block-ackd block)
                    (update ::specs/total-blocks inc)
                    (update ::specs/total-block-transmissions + transmissions)))))
    acc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef earliest-block-time
        :args (s/cat :message-loop-name string?
                     :blocks ::specs/un-ackd-blocks)
        :ret nat-int?)
(defn earliest-block-time
  "Calculate the earliest time

Based on earliestblocktime_compute, in lines 138-153
"
  [message-loop-name un-acked-blocks]
  ;;; Comment from DJB:
  ;;; XXX: use priority queue
  ;; (That's what led to me using the sorted-set)

  ;; This gets called right after we flag the blocks
  ;; that have been ACK'd
  (let [un-flagged (remove ::ackd? un-acked-blocks)]
    (log/debug (utils/pre-log message-loop-name)
               "Calculating min-time across"
               (count un-flagged)
               "un-ACK'd blocks")
    (if (< 0 (count un-flagged))
      (apply min (map ::specs/time
                      ;; In the original,
                      ;; time 0 means it's been ACK'd and is ready to discard
                      ;; Having the time serve dual purposes
                      ;; kept tripping me up.
                      un-flagged))
      0)))

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
        _ (log/debug log-prefix
                     (str "drop-ack'd! Keeping "
                          (count to-keep)
                          " un-ACK'd block(s):\n"
                          (reduce (fn [acc b]
                                    (str acc "\n" b))
                                  ""
                                  to-keep)
                          "\nout of\n"
                          (count un-ackd-blocks)))
        dropped-block-lengths (apply + (map (fn [b]
                                              (-> b ::specs/buf .readableBytes))
                                            to-drop))
        kept (reduce (fn [acc dropped]
                       (disj acc dropped))
                     un-ackd-blocks
                     to-drop)
        _ (log/warn log-prefix
                    (str "Really should be smarter re: ::ackd-addr (aka "
                         ackd-addr
                         ") here"))
        state (-> state
                  ;; Note that this really needs to be the stream address of the
                  ;; highest contiguous block that's been ACK'd.
                  ;; This makes any scheme for ACK'ing pieces out of
                  ;; order more complicated.
                  ;; As-is, this is really tracking the count of bytes
                  ;; that have been ACK'd.
                  ;; For these purposes, that doesn't accomplish much.
                  (update-in [::specs/outgoing ::specs/ackd-addr] + dropped-block-lengths)
                  (assoc-in [::specs/outgoing ::specs/un-ackd-blocks] kept))]
    (log/warn log-prefix "ackd-addr handling is still broken")
;;;           183: earliestblocktime_compute()
    (doseq [block to-drop]
      (log/debug log-prefix
                 "Releasing the buf associated with"
                 block)
      ;; This is why the function name has a !
      (let [^ByteBuf buffer (::specs/buf block)]
        (.release buffer)))
    (assoc-in state
              [::specs/outgoing ::specs/earliest-time]
              (earliest-block-time message-loop-name un-ackd-blocks))))

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
            ::specs/send-eof-acked]} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}
   start
   stop]
  ;; TODO: If un-ackd blocks is empty, we can just short-circuit this
  (let [log-prefix (utils/pre-log message-loop-name)]
    ;; This next log message is annoying right now, because
    ;; it seems very repetitive and pointless.
    ;; That's probably because we aren't taking advantages of
    ;; any of these addressing options and really only ACK'ing
    ;; the high-water-mark stream address.
    (log/debug log-prefix
               "Setting ACK flags on blocks with addresses from"
               start "to" stop)
    (when (< (get-in state [::specs/outgoing ::specs/strm-hwm])
             stop)
      ;; This is definitely a bug.
      ;; TODO: Figure out something more extreme to do here.
      (log/error log-prefix "Other side ACK'd bytes we haven't sent yet"))
    (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
      (let [state (reduce (partial flag-acked-blocks start stop)
                          state
                          un-ackd-blocks)
            ;;;           177-182: Possibly set sendeofacked flag
            state (if (and send-eof
                           (= start 0)
                           ;; It seems like this next check should be >=
                           ;; But this is what the reference implementation checks.
                           (> stop (get-in state [::specs/outgoing ::specs/strm-hwm]))
                           (not send-eof-acked))
                    (assoc-in state [::specs/outgoing ::specs/send-eof-acked] true)
                    state)]
        (log/debug log-prefix
                   "Done w/ initial flag reduce:\n"
                   state)
        ;; Again, gaps kill it
        (log/warn log-prefix "This treatment of ::ackd-addr also fails")
        (assoc-in state
                  [::specs/outgoing ::specs/ackd-addr]
                  stop))
      (do
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
        (log/info log-prefix "Nothing ACK'd by address")
        ;; No change
        state))))

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
  ;; when I initially create the block)
  (-> outgoing
      (update ::specs/un-ackd-blocks disj block)
      (update ::specs/un-ackd-blocks
              conj
              (assoc block
                     ::specs/ackd?
                     true))))

;;; Q: Would these wrappers make more sense under shared/bit-twiddling?

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
