(ns frereth-cp.message.helpers
  "Top-level message helpers"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.specs :as specs])
  (:import io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef earliest-block-time
        :args (s/coll-of ::specs/block)
        :ret nat-int?)
(defn earliest-block-time
  "Calculate the earliest time

Based on earliestblocktime_compute, in lines 138-153
"
  [blocks]
  ;;; Comment from DJB:
  ;;; XXX: use priority queue
  (min (map ::specs/time blocks)))

;;;; 155-185: acknowledged(start, stop)
(s/fdef acknowledged
        :args (s/cat :state ::specs/state
                     :start int?
                     :stop int?)
        :ret ::specs/state)
(defn mark-acknowledged
  "Mark blocks between positions start and stop as ACK'd

Based [cleverly] on acknowledged, running from lines 155-185"
  [{:keys [::specs/blocks
           ::specs/send-acked
           ::specs/send-bytes
           ::specs/send-processed
           ::specs/send-eof
           ::specs/send-eof-acked
           ::specs/total-block-transmissions
           ::specs/total-blocks]
    :as state}
   start
   stop]
  (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
    (let [acked (reduce (fn [{:keys [::n]
                              :as acc}
                             block]
                          (let [start-pos (::specs/start-pos block)]
                            (if (<= start
                                    start-pos
                                    (+ start-pos (::specs/length block))
                                    stop)
                              (-> acc
                                  (assoc-in [::specs/blocks n ::specs/time] 0)
                                  (update ::specs/total-blocks inc)
                                  (update ::specs/total-block-transmissions + (::specs/transmissions block)))
                              (update acc ::n inc))))
                        (assoc state ::n 0)
                        blocks)]
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
      (let [[to-drop to-keep] (split-with #(= 0 (::specs/time %)) acked)
            dropped-block-lengths (apply + (map ::specs/length to-drop))
            ;; TODO: Drop reliance on these
            ;; Instead: need something like:
            _ (comment (doseq [block to-drop] (.release (::buffer block))))
            state (update state ::specs/send-acked + dropped-block-lengths)
            state (update state ::specs/send-bytes - dropped-block-lengths)
            state (update state ::specs/send-processed - dropped-block-lengths)
            state (assoc state ::specs/blocks to-keep)
;;;           177-182: Possibly set sendeofacked flag
            state (or (when (and send-eof
                                 (= start 0)
                                 (> stop (+ (::specs/send-acked state)
                                            (::specs/send-bytes state)))
                                 (not send-eof-acked))
                        (update state ::specs/send-eof-acked true))
                      state)]
;;;           183: earliestblocktime_compute()
        (assoc state ::specs/earliest-time (earliest-block-time blocks))))
    ;;; No change
    state))

(defn read-long
  [^ByteBuf bb]
  (.readLong bb))

(defn read-ulong
  [^ByteBuf bb]
  (.readUnsignedLong bb))

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
