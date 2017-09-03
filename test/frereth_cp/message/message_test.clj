(ns frereth-cp.message.message-test
  (:require [clojure.data]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-utilities :as test-helpers]
            [frereth-cp.message.to-parent :as to-parent]
            [frereth-cp.util :as utils])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(deftest basic-echo
  (let [response (promise)
        parent-state (atom 0)
        parent-cb (fn [dst]
                    (let [response-state @parent-state]
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
        state-agent-atom (atom nil)
        child-cb (fn [array-o-bytes]
                   ;; Just echo it directly back.
                   (let [state-agent @state-agent-atom]
                     (is state-agent)
                     ;; Oh. This is nasty.
                     ;; I have a circular dependency between
                     ;; this and initialized.

                     ;; And this is getting called inside an
                     ;; agent send handler
                     ;; Which means I have the agent state
                     ;; directly available, but not the actual
                     ;; agent.

                     ;; Which is what I need here, because child->
                     ;; is going to trigger another send.

                     ;; The truly obnoxious part of this is that
                     ;; I think that managing the state using
                     ;; an agent probably was probably a bad idea
                     ;; from the very beginning.

                     ;; Although it has been convenient, up until
                     ;; now.

                     ;; Wrapping it inside an atom is obnoxious, but
                     ;; it works.

                     ;; Don't do anything like this for anything real.
                     (message/child-> state-agent array-o-bytes)))
        initialized (message/initial-state parent-cb child-cb)
        state (message/start! initialized)]
    (reset! state-agent-atom state)
    (try
      (let [src (Unpooled/buffer K/k-1)  ; w/ header, this takes it to the 1088 limit
            msg-len (- K/max-msg-len K/header-length K/min-padding-length)
            message-body (byte-array (range msg-len))
            ;; Just pick an arbitrary number
            message-id 25792]
        (is (= msg-len K/k-1))
        (.writeBytes src message-body)
        (let [incoming (to-parent/build-message-block message-id {::specs/buf src
                                                                  ::specs/length msg-len
                                                                  ::specs/send-eof false
                                                                  ::specs/start-pos 0})]
          (is (= K/max-msg-len (count incoming)))
          ;; TODO: Add tests that send a variety of gibberish messages
          (let [wrote (future (message/parent-> state incoming))
                outcome (deref response 1000 ::timeout)]
            (if-let [err (agent-error state)]
              (do
                (is (not err))
                (log/error (utils/get-stack-trace err)))
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
                        (is (not outcome) "What should we have here?"))))))))))
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
