(ns frereth-cp.message.message-test
  (:require [clojure.data]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(defn build-ack-flag-message-portion
  []
  (let [^ByteBuf buf (Unpooled/buffer 48)]
    ;; There are no .writeUnsigned??? methods
    ;; This seems problematic.
    ;; For this implementation, where we never bother
    ;; ACKing anything except the first block (immediately),
    ;; it probably doesn't matter.
    (.writeLong buf 56)   ; bytes in range #1
    (.writeInt buf 4)     ; bytes between ranges 1-2
    (.writeShort buf 256) ; bytes in range #1
    (.writeShort buf 7)   ; bytes between ranges 2-3
    (.writeShort buf 25)  ; bytes in range #3
    (.writeShort buf 32)  ; bytes between ranges 3-4
    (.writeShort buf 8)   ; bytes in range #4
    (.writeShort buf 12)  ; bytes between ranges 4-5
    (.writeShort buf 16)  ; bytes in range #5
    (.writeShort buf 24)  ; bytes between ranges 5-6
    (.writeShort buf 32)  ; bytes in range #6
    (let [bytes-acked (+ 56 256 25 8 16 32)
          now #_(System/nanoTime) 1234
          ;; To be safe, any test that uses these needs
          ;; to .release() these buffers before it ends.
          ;; Q: Doesn't it?
          b1 (Unpooled/buffer 16)
          _ (.writeBytes b1 (byte-array [1]))
          b2 (Unpooled/buffer 16)
          _ (.writeBytes b2 (byte-array [2]))
          b3 (Unpooled/buffer 16)
          _ (.writeBytes b3 (byte-array [1]))
          b4 (Unpooled/buffer 16)
          _ (.writeBytes b4 (byte-array [2]))
          b5 (Unpooled/buffer 16)
          _ (.writeBytes b5 (byte-array [1]))
          b6 (Unpooled/buffer 16)
          _ (.writeBytes b6 (byte-array [2]))
          b7 (Unpooled/buffer 16)
          _ (.writeBytes b7 (byte-array [2]))
          start-blocks [{::specs/buf b1
                         ::specs/start-pos 10
                         ::specs/length 40
                         ::specs/time (- now 1)
                         ::specs/transmissions 1}  ; Covered by range 1
                        {::specs/buf b2
                         ::specs/start-pos 60
                         ::specs/length 256
                         ::specs/time (- now 2)
                         ::specs/transmissions 2} ; Range 2
                        {::specs/buf b3
                         ::specs/start-pos 316
                         ::specs/length 64
                         ::specs/time (- now 3)
                         ::specs/transmissions 3}  ; Partially covered by range 3
                        ;; Since that hasn't been ACK'd, we can'd drop any of the rest
                        {::specs/buf b4
                         ::specs/start-pos 380
                         ::specs/length 8
                         ::specs/time (- now 4)
                         ::specs/transmissions 4}   ; Covered by range 4
                        {::specs/buf b5
                         ::specs/start-pos 388
                         ::specs/length 12
                         ::specs/time (- now 5)
                         ::specs/transmissions 5}  ; Gap between 4 and 5
                        {::specs/buf b6
                         ::specs/start-pos 400
                         ::specs/length 16
                         ::specs/time (- now 6)
                         ::specs/transmissions 6}  ; Block 5
                        {::specs/buf b7
                         ::specs/start-pos 440
                         ::specs/length 32
                         ::specs/time (- now 7)
                         ::specs/transmissions 7}]]   ; block 6
      {::specs/blocks start-blocks
       ::specs/earliest-time 0
       ::specs/receive-buf buf
       ::specs/send-acked 0
       ::specs/send-bytes 1000   ; Something bigger than what's getting acked
       ::specs/send-processed (* 2 bytes-acked)  ; 786
       ::specs/total-block-transmissions 0
       ::specs/total-blocks 0})))

(deftest basic-echo
  (let [response (promise)
        parent-state (atom 0)
        parent-cb (fn [_ rsp]
                    (let [dst (byte-array (.readableBytes rsp))
                          response-state @parent-state]
                      (.getBytes rsp 0 dst)
                      ;; Should get 2 callbacks here:
                      ;; 1. The ACK
                      ;; 2. The actual response
                      ;; Although, depending on timing, 3 or
                      ;; more are possible
                      ;; (If we don't end this quickly enough to
                      ;; avoid a repeated send, for example)
                      (when (= response-state 1)
                        (deliver response dst))
                      (swap! parent-state inc)))
        child-cb (fn [state byte-buf]
                   ;; Just echo it directly back
                   (message/child-> state byte-buf))
        initialized (message/initial-state parent-cb child-cb)
        state (message/start! initialized)]
    (try
      (let [src (Unpooled/buffer K/k-1)
            ;; TODO: Need to start with something like the
            ;; ByteBuf (and pending un-ACK'd packets) generated
            ;; by  build-ack-flag-message-portion
            packet (byte-array (range message/max-msg-len))]
        (.writeBytes src packet)
        (let [wrote (future (message/parent-> state src))
              outcome (deref response 1000 ::timeout)]
          (if (not (agent-error state))
            (do
              (is (not= outcome ::timeout))
              (when-not (= outcome ::timeout)
                (is (= @parent-state 2))
                (is (not outcome) "What else do we have here?"))
              (is (realized? wrote))
              (when (realized? wrote)
                (let [outcome @wrote]
                  ;; Pretty sure that returns the new state
                  (is (not outcome) "What should we have here?"))))
            (is (not (agent-error state))))))
      (finally
        (message/halt! state)))))

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
      (let [flagged (message/flag-acked-others! {::specs/receive-buf buf})]
        (is (not flagged) "What should that look like?")))))

(deftest check-flag-acked-block
  (let [start-state (build-ack-flag-message-portion)
        flagged (help/flag-acked-blocks 0 56
                                        (assoc start-state ::help/n 0)
                                        (first (::specs/blocks start-state)))]
    (try
      (is (= (-> start-state
                 (update-in [::specs/blocks 0 ::specs/time] (constantly 0))
                 (assoc ::specs/total-block-transmissions 1
                        ::specs/total-blocks 1))
             (dissoc flagged ::help/n)))
      (let [flagged (help/flag-acked-blocks 0 56
                                            (assoc start-state ::help/n 1)
                                            (second (::specs/blocks start-state)))]
        (is (= (assoc start-state ::help/n 2)
               flagged)))
      (finally
        (doseq [b (::specs/blocks start-state)]
          (.release (::specs/buf b)))))))

(deftest check-mark-acked
  (let [start-state (build-ack-flag-message-portion)
        acked (help/mark-acknowledged! start-state 0 56)]
    (try
      (comment (pprint acked))
      (is (= (keys start-state) (keys acked)))
      ;; It's tempting to convert these to a set to make
      ;; comparing problems easier.
      ;; But start-state has invalid data now, since one of
      ;; its ByteBuf instances has been released.
      (let [b1 (::specs/blocks start-state)
            b1n (count b1)
            b2 (::specs/blocks acked)
            b2n (count b2)]
        (when-not (= (dec b1n) b2n)
          ;; Can't call clojure.data/diff due to the same issue with
          ;; the released ByteBuf
          #_(comment (pprint (clojure.data/diff b1 b2)))
          (is (= (dec b1n) b2n)
              (str "Start-state has " b1n
                   " blocks.\nFlagged version has "
                   b2n
                   "\n"))))
      (is (= (drop 1 (::specs/blocks start-state))
             (::specs/blocks acked)))
      (finally
        ;; Don't do this over start-state, since 1 of its buffers has been released
        (doseq [b (::specs/blocks acked)]
          (.release (::specs/buf b)))))))

(deftest check-flacked-others
  (let [start-state (build-ack-flag-message-portion)]
    (let [{:keys [::specs/blocks
                  ::specs/send-acked
                  ::specs/send-bytes
                  ::specs/send-processed
                  ::specs/total-blocks
                  ::specs/total-block-transmissions]
           :as flagged} (message/flag-acked-others! start-state)
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

(deftest parallel-parent-test
  (testing "parent-> should be thread-safe"
    (is false "Write this")))

(deftest parallel-child-test
  (testing "child-> should be thread-safe"
    (is false "Write this")))

(deftest simulate-dropped-acks
  ;; When other side fails to respond "quickly enough",
  ;; should re-send message blocks
  ;; This adds an entirely new wrinkle (event scheduling)
  ;; to the mix
  (is false "Write this"))
