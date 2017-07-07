(ns frereth-cp.message.message-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.specs :as specs])
  (:import [io.netty.buffer ByteBuf Unpooled]))

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

(deftest check-flacked-others
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
          start-blocks [{::specs/start-pos 10
                         ::specs/length 40
                         ::specs/transmissions 1}  ; Covered by range 1
                        {::specs/start-pos 60
                         ::specs/length 256
                         ::specs/transmissions 2} ; Range 2
                        {::specs/start-pos 316
                         ::specs/length 64
                         ::specs/transmissions 3}  ; Partially covered by range 3
                        {::specs/start-pos 380
                         ::specs/length 8
                         ::specs/transmissions 4}   ; Covered by range 4
                        {::specs/start-pos 388
                         ::specs/length 12
                         ::specs/transmissions 5}  ; Gap between 4 and 5
                        {::specs/start-pos 400
                         ::specs/length 16
                         ::specs/transmissions 6}  ; Block 5
                        {::specs/start-pos 440
                         ::specs/length 32
                         ::specs/transmissions 7}]  ; block 6
          start-state {::specs/blocks start-blocks
                       ::specs/receive-buf buf
                       ::specs/send-acked 0
                       ::specs/send-bytes bytes-acked
                       ::specs/send-processed (* 2 bytes-acked)
                       ::specs/total-block-transmissions 0
                       ::specs/total-blocks 0}
          {:keys [::specs/blocks
                  ::specs/send-acked
                  ::specs/send-bytes
                  ::specs/send-processed
                  ::specs/total-blocks
                  ::specs/total-block-transmissions]
           :as flagged} (message/flag-acked-others! start-state)
          expected-remaining-blocks [{::specs/start-pos 316
                                      ::specs/length 64
                                      ::specs/transmissions 3}
                                     {::specs/start-pos 388
                                      ::specs/length 12
                                      ::specs/transmissions 5}]]
      (is (= 4 total-blocks))
      (is (= 0 send-acked) "Bytes that have been ACK'd")
      (is (= 78 send-bytes) "Bytess that have not been ACK'd")
      (is (= 0 send-processed) "Sent bytes that have been absorbed into blocks")
      (is (= 20 total-block-transmissions))
      (is (= expected-remaining-blocks blocks)))))

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
