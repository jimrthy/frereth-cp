(ns frereth-cp.message.from-parent-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.message.from-parent :as from-parent]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-utilities :as test-helpers])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(deftest verify-block-collapse
  ;; TODO: This is screaming for generative testing
  (let [^ByteBuf buf (Unpooled/buffer 128)]
    (try
      (.writeBytes buf (byte-array (range 100)))
      (let [half (byte-array 50)]
        (.readBytes buf half)
        (is (= (vec half) (range 50)))
        (.discardReadBytes buf)
        (.capacity buf 50)
        (.readBytes buf half)
        (is (= (vec half) (range 50 100))))
      (finally
        (.release buf)))))

(deftest check-flacked-others
  (let [start-state (test-helpers/build-ack-flag-message-portion)]
    (let [{:keys [::specs/blocks
                  ::specs/send-acked
                  ::specs/send-bytes
                  ::specs/send-processed
                  ::specs/total-blocks
                  ::specs/total-block-transmissions]
           :as flagged} (from-parent/flag-acked-others! start-state)
          expected-remaining-blocks (drop 2 (::specs/blocks start-state))]
      (try
        (let [dropped-block-length (reduce + 0
                                           (->> start-state
                                                ::specs/blocks
                                                (take 2)
                                                (map ::specs/length)))]
          (is (= 5 total-blocks) "Total blocks ACK'd")
          (is (= (+ (get-in start-state [::specs/blocks 0 ::specs/length])
                    (get-in start-state [::specs/blocks 1 ::specs/length]))
                 send-acked) "Bytes that have been dropped")
          (is (= (- (::specs/send-bytes start-state)
                    dropped-block-length)
                 send-bytes) "Bytess that have not been sent but not dropped")
          (is (= (- (::specs/send-processed start-state) dropped-block-length)
                 send-processed) "Sent bytes that have been absorbed into blocks")
          (is (= 20 total-block-transmissions))
          (is (= (map #(dissoc % ::specs/time) expected-remaining-blocks)
                 (map #(dissoc % ::specs/time) blocks))))
        (finally
          (doseq [b (::specs/blocks flagged)]
            (.release (::specs/buf b))))))))

(deftest check-big-flacked-others
  ;; This needs to be expanded to match the behavior in check-flacked-others
  (testing "Values for big message streams"
    (let [^ByteBuf buf (Unpooled/buffer 48)]
      ;; We're going to have to be able to cope with big numbers
      ;; sooner or later
      (.writeLong buf -56)   ; bytes in range #1
      (.writeInt buf -4)     ; bytes between ranges 1-2
      (.writeShort buf -256) ; bytes in range #1
      (.writeShort buf 7)   ; bytes between ranges 2-3
      (.writeShort buf 25)  ; bytes in range #3
      (.writeShort buf 32)  ; bytes between ranges 3-4
      (.writeShort buf 8)   ; bytes in range #4
      (.writeShort buf 12)  ; bytes between ranges 4-5
      (.writeShort buf 16)  ; bytes in range #5
      (.writeShort buf 24)  ; bytes between ranges 5-6
      (.writeShort buf 32)  ; bytes in range #6
      (let [flagged (from-parent/flag-acked-others! {::specs/receive-buf buf})]
        (is (not flagged) "What should that look like?")))))
