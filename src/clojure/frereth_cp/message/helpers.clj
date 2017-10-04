(ns frereth-cp.message.helpers
  "Top-level message helpers"
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.specs :as specs])
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
  (log/debug (str message-loop-name
                  ": Calculating min-time across"
                  un-acked-blocks))
  (if (< 0 (count un-acked-blocks))
    (apply min (map ::specs/time
                    ;; Time 0 means it's been ACK'd and is ready to discard
                    un-acked-blocks))
    0))

;;;; 155-185: acknowledged(start, stop)
(s/fdef mark-acknowledged!
        :args (s/cat :state ::specs/state
                     :start int?
                     :stop int?)
        :ret ::specs/state)
(defn mark-acknowledged!
  "Mark sent blocks between positions start and stop as ACK'd

Based [cleverly] on acknowledged(), running from lines 155-185"
  [{{:keys [::specs/un-ackd-blocks
            ::specs/send-eof
            ::specs/send-eof-acked]} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}
   start
   stop]
  ;; This next log message is annoying right now.
  ;; That's probably because we aren't taking advantages of
  ;; any of these addressing options and really only ACK'ing
  ;; the high-water-mark stream address.
  (log/debug (str message-loop-name
                  ": Setting ACK flags on blocks with addresses from "
                  start " to " stop))
  (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
    (let [acked (reduce (partial flag-acked-blocks start stop)
                        state
                        un-ackd-blocks)]
      (log/debug (str message-loop-name
                      ": Done w/ initial flag reduce:\n"
                      acked))
      ;; To match the next block, the main point is to discard
      ;; the first sequence of blocks that have been ACK'd
      ;; drop-while seems obvious
      ;; However, we also need to update send-acked, send-bytes, and send-processed
;;;           168-176: Updates globals for adjacent blocks that
;;;                    have been ACK'd
;;;                    This includes some counters that seem important:
;;;                        blocknum
;;;                        sendacked
;;;                        sendbytes
;;;                        sendprocessed
;;;                        blockfirst
      (let [possibly-ackd (get-in acked [::specs/outgoing ::specs/un-ackd-blocks])
            to-drop (filter ::specs/ackd? possibly-ackd)
            to-keep (remove ::specs/ackd? possibly-ackd)
            _ (log/debug (str message-loop-name
                              ": Keeping "
                              (count to-keep)
                              " blocks:\n"
                              (reduce (fn [acc b]
                                        (str acc "\n" b))
                                      ""
                                      to-keep)
                              "\nout of\n"
                              possibly-ackd
                              "\n\n"))
            dropped-block-lengths (apply + (map ::specs/length to-drop))
            kept (reduce (fn [acc dropped]
                           (disj acc dropped))
                         un-ackd-blocks
                         to-drop)
            ;; TODO: Drop reliance on these send-* keys
            state (-> acked
                      (update ::specs/outgoing
                              (fn [cur]
                                (-> cur
                                    (update ::specs/send-acked + dropped-block-lengths))))
                      (update-in [::specs/outgoing ::specs/send-bytes] - dropped-block-lengths)
                      (update-in [::specs/outgoing ::specs/send-processed] - dropped-block-lengths)
                      (assoc-in [::specs/outgoing ::specs/un-ackd-blocks] kept))
;;;           177-182: Possibly set sendeofacked flag
            state (if (and send-eof
                           (= start 0)
                           (> stop (+ (get-in state [::specs/outgoing ::specs/send-acked])
                                      (get-in state [::specs/outgoing ::specs/send-bytes])))
                           (not send-eof-acked))
                    (assoc-in state [::specs/outgoing ::specs/send-eof-acked] true)
                    state)]
;;;           183: earliestblocktime_compute()
        (doseq [block to-drop]
          (log/debug (str message-loop-name
                          ": Releasing the buf associated with"
                          block))
          ;; This is why the function name has a !
          (let [^ByteBuf buffer (::specs/buf block)]
            (.release buffer)))
        (assoc-in state [::specs/outgoing ::specs/earliest-time]
                  (earliest-block-time message-loop-name un-ackd-blocks))))
    ;;; No change
    state))

(s/fdef mark-block-ackd
        :args (s/cat :outgoing ::specs/outgoing
                     :block ::specs/block)
        :ret ::specs/outgoing)
(defn mark-block-ackd
  [{:keys [::specs/un-ackd-blocks]
    :as outgoing}
   block]
  (log/debug "Marking" block "ACK'd")
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
