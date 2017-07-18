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
(defn flag-acked-blocks
  [start stop
   {:keys [::n]
    :as acc}
   {:keys [::specs/start-pos
           ::specs/transmissions]
    :as block}]
  {:pre [transmissions]}
  (println "flag-acked-blocks:" start "-" stop "for" block)
  (update
   (if (<= start
           start-pos
           (+ start-pos (::specs/length block))
           stop)
     (-> acc
         (update ::specs/outgoing
                 (fn [cur]
                   (-> cur
                       (assoc-in [::specs/blocks n ::specs/time] 0)
                       (update ::specs/total-blocks inc)
                       (update ::specs/total-block-transmissions + transmissions)))))
     acc)
   ::n inc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

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
  (let [un-acked-blocks (filter #(not= 0 (::specs/time %)) blocks)]
    (if (< 0 (count un-acked-blocks))
      (apply min (map ::specs/time
                      ;; Time 0 means it's been ACK'd and is ready to discard
                      un-acked-blocks))
      0)))

;;;; 155-185: acknowledged(start, stop)
(s/fdef acknowledged
        :args (s/cat :state ::specs/state
                     :start int?
                     :stop int?)
        :ret ::specs/state)
(defn mark-acknowledged!
  "Mark blocks between positions start and stop as ACK'd

Based [cleverly] on acknowledged(), running from lines 155-185"
  [{{:keys [::specs/blocks
            ::specs/send-eof
            ::specs/send-eof-acked]} ::specs/outgoing
    :as state}
   start
   stop]
  (log/debug "Setting ACK flags on blocks with addresses from" start "to" stop)
  (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
    (let [acked (reduce (partial flag-acked-blocks start stop)
                        (assoc state ::n 0)
                        blocks)]
      (log/debug "Done w/ initial flag reduce:\n" acked)
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
      (let [[to-drop to-keep] (split-with #(= 0 (::specs/time %)) (get-in acked [::specs/outgoing ::specs/blocks]))
            _ (log/debug "Keeping:\n" to-keep "\n\n")
            dropped-block-lengths (apply + (map ::specs/length to-drop))
            ;; TODO: Drop reliance on these
            state (-> acked
                      (update ::specs/outgoing
                              (fn [cur]
                                (-> cur
                                    (update ::specs/send-acked + dropped-block-lengths))))
                      (update-in [::specs/outgoing ::specs/send-bytes] - dropped-block-lengths)
                      (update-in [::specs/outgoing ::specs/send-processed] - dropped-block-lengths)
                      (assoc-in [::specs/outgoing ::specs/blocks] (vec to-keep)))
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
          (log/debug "Releasing the buf associated with" block)
          (.release (::specs/buf block)))
        (assoc-in state [::specs/outgoing ::specs/earliest-time] (earliest-block-time blocks))))
    ;;; No change
    state))

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
