(ns frereth-cp.message.message-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.message :as message])
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
      (let [src (Unpooled/buffer message/k-1)
            packet (byte-array (range 1088))]
        (message/parent-> state src)
        (let [outcome (deref response 1000 ::timeout)]
          (is (not= outcome ::timeout))
          (when-not (= outcome ::timeout)
            (is (= @parent-state 2))
            (is (not outcome) "What else do we have here?"))))
      (finally
        (message/halt! state)))))

(deftest parallel-parent-test
  (testing "parent-> should be thread-safe"
    (is false "Write this")))

(deftest parallel-child-test
  (testing "child-> should be thread-safe"
    (is false "Write this")))

(deftest simulate-dropped-acks
  ;; When other side fails to respond "quickly enough",
  ;; should re-send message blocks
  (is false "Write this"))
