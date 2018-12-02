(ns frereth.cp.message.registry-test
  (:require [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [frereth.cp.message.registry :as reg]
            [frereth.cp.message.specs :as specs]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [executor :as exec]
             [stream :as strm]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helpers

(s/fdef mock-io-handle
        :args (s/cat :message-loop-name ::specs/message-loop-name)
        :ret ::specs/io-handle)
(defn mock-io-handle
  [message-loop-name]
  (let [->child (fn [bs]
                  (println "Incoming:" bs))
        ->parent (fn [bs]
                   (println "Outgoing:" bs))
        from-child (java.io.PipedOutputStream.)
        child-out (java.io.PipedInputStream.)
        to-child-done? (promise)
        from-parent-trigger (strm/stream)
        executor (exec/utilization-executor 0.1)
        logger (log/std-out-log-factory)
        log-state (log/init (keyword (str *ns*) message-loop-name))]
    {::specs/->child ->child
     ::specs/->parent ->parent
     ::specs/from-child from-child
     ::specs/child-out child-out
     ::specs/to-child-done? to-child-done?
     ::specs/from-parent-trigger from-parent-trigger
     ::specs/executor executor
     ::weald/logger logger
     ::specs/message-loop-name message-loop-name
     ::weald/state-atom (atom log-state)}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(deftest registry-spec
  (testing "valid"
    (let [loop-name "valid"
          io-handle (mock-io-handle loop-name)
          reg (-> (reg/ctor)
                  (reg/register io-handle))]
      (is (not (s/explain-data ::reg/registry reg)))
      (let [reg (reg/de-register reg loop-name)]
        (is (s/valid? ::reg/registry reg)))))
  (testing "basic types"
    (testing "plain dict"
      (let [ok {}]
        (is (s/valid? ::reg/registry ok)))
      (testing "must-be-dict"
        (let [nope []]
          (is (not (s/valid? ::reg/registry nope))))))))
