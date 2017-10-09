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
    (log/debug (str message-loop-name
                    ": Calculating min-time across "
                    (count un-flagged)
                    " un-ACK'd blocks"))
    (if (< 0 (count un-flagged))
      (apply min (map ::specs/time
                      ;; In the original,
                      ;; time 0 means it's been ACK'd and is ready to discard
                      ;; Having the time serve dual purposes
                      ;; kept tripping me up.
                      un-flagged))
      0)))

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
  (let [log-prefix (utils/pre-log message-loop-name)]
    ;; This next log message is annoying right now, because
    ;; it seems very repetitive and pointless.
    ;; That's probably because we aren't taking advantages of
    ;; any of these addressing options and really only ACK'ing
    ;; the high-water-mark stream address.
    (log/debug log-prefix
               "Setting ACK flags on blocks with addresses from"
               start "to" stop)
    ;; This is definitely a bug.
    ;; TODO: Figure out something more extreme to do here.
    (when (< (get-in state [::specs/outgoing ::specs/strm-hwm])
             stop)
      (log/error log-prefix "Other side ACK'd bytes we haven't sent yet"))
    (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
      (let [acked (reduce (partial flag-acked-blocks start stop)
                          state
                          un-ackd-blocks)]
        (log/debug log-prefix
                   "Done w/ initial flag reduce:\n"
                   acked)
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
        (let [possibly-ackd (get-in acked [::specs/outgoing ::specs/un-ackd-blocks])
              to-drop (filter ::specs/ackd? possibly-ackd)
              to-keep (remove ::specs/ackd? possibly-ackd)
              _ (log/debug log-prefix
                           (str "Keeping "
                                (count to-keep)
                                " blocks:\n"
                                (reduce (fn [acc b]
                                          (str acc "\n" b))
                                        ""
                                        to-keep)
                                "\nout of\n"
                                possibly-ackd
                                "\n\n"))
              dropped-block-lengths (apply + (map (fn [b]
                                                    (-> b ::specs/buf .readableBytes))
                                                  to-drop))
              kept (reduce (fn [acc dropped]
                             (disj acc dropped))
                           un-ackd-blocks
                           to-drop)
              state (-> acked
                        ;; Note that this really needs to be the stream address of the
                        ;; highest contiguous block that's been ACK'd.
                        ;; This makes any scheme for ACK'ing pieces out of
                        ;; order more complicated.
                        ;; As-is, this is really tracking the count of bytes
                        ;; that have been ACK'd.
                        ;; For these purposes, that doesn't accomplish much.
                        (update-in [::specs/outgoing ::specs/ackd-addr] + dropped-block-lengths)
                        (assoc-in [::specs/outgoing ::specs/un-ackd-blocks] kept))
;;;           177-182: Possibly set sendeofacked flag
              state (if (and send-eof
                             (= start 0)
                             ;; It seems like this next check should be >=
                             ;; But this is what the reference implementation checks.
                             (> stop (get-in state [::specs/outgoing ::specs/strm-hwm]))
                             (not send-eof-acked))
                      (assoc-in state [::specs/outgoing ::specs/send-eof-acked] true)
                      state)]
          (log/warn log-prefix "Get back to ackd-addr handling")
;;;           183: earliestblocktime_compute()
          (doseq [block to-drop]
            (log/debug log-prefix
                       "Releasing the buf associated with"
                       block)
            ;; This is why the function name has a !
            (let [^ByteBuf buffer (::specs/buf block)]
              ;; My "write big array" unit test fails during
              ;; to-parent/build-message-block-description
              ;; because it's trying to write to a ByteBuf with
              ;; refCnt 0.
              ;; This seems like the most likely culprit.
              ;; Hypothesis: I need to add a .acquire call
              ;; when I create a slice.
              (.release buffer)))
          (-> state
              (assoc-in [::specs/outgoing ::specs/earliest-time]
                        (earliest-block-time message-loop-name un-ackd-blocks))
              (assoc-in [::specs/outgoing ::specs/ackd-addr]
                        stop))))
      (do
        ;; Q: Is this correct?
        ;; At the very least, there might have been the
        ;; previous message received.
        (log/info log-prefix "Nothing ACK'd")
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
  ;; It *is* updating the caller
  (log/warn "Marking\n" block "\nACK'd isn't working. Q: Why not?")
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
