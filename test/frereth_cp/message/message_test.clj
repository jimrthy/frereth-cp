(ns frereth-cp.message.message-test
  (:require [clojure.data]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-helpers :as test-helpers])
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
            ;; TODO: Need to start with something like the
            ;; ByteBuf (and pending un-ACK'd packets) generated
            ;; by  build-ack-flag-message-portion
            packet (byte-array (range K/max-msg-len))]
        (.writeBytes src packet)
        (let [wrote (future (message/parent-> state src))
              outcome (deref response 1000 ::timeout)]
          (if-let [err (agent-error state)]
            (is (not err))
            (do
              (is (not= outcome ::timeout))
              (when-not (= outcome ::timeout)
                (is (= @parent-state 2))
                (is (not outcome) "What else do we have here?"))
              (is (realized? wrote))
              (when (realized? wrote)
                (let [outcome-agent @wrote]
                  (is (not (agent-error outcome-agent)))
                  (when-not (agent-error outcome-agent)
                    ;; Fun detail:
                    ;; wrote is a promise.
                    ;; When I deref that, there's an agent
                    ;; that I need to deref again to get
                    ;; the actual end-state
                    (let [outcome @outcome-agent]
                      (is (not outcome) "What should we have here?")))))))))
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
  ;; This adds an entirely new wrinkle (event scheduling)
  ;; to the mix
  (is false "Write this"))
