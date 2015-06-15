(ns com.frereth.common.async-zmq-test
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.async-zmq :refer :all]
            [com.frereth.common.util :as util]
            [com.stuartsierra.component :as component]
            [component-dsl.system :as cpt-dsl]))

(defn mock-up
  []
  (let [descr '{:one com.frereth.common.async-zmq/ctor
                :two com.frereth.common.async-zmq/ctor}
        ctx (mq/context 1)
        one-pair (mq/build-internal-pair! ctx)
        two-pair (mq/build-internal-pair! ctx)
        ;; TODO: It's tempting to set these built-ins
        ;; as defaults, but they really won't be useful
        ;; very often
        reader (fn [sock]
                 (println "Mock Reader triggered")
                 (let [read (mq/raw-recv! sock)]
                   (println "Mock Reader Received:\n" (util/pretty read))
                   read))
        generic-writer (fn [receiver sock msg]
                  ;; Q: if we're going to do this,
                  ;; does the event loop need access to the socket at all?
                  ;; A: Yes. Because it spends most of its time polling on that socket
                  (let [listener (async/thread
                                   (let [result (mq/raw-recv! receiver)]
                                     (println "Mock writer's background thread listener received:\n"
                                              (util/pretty result))
                                     result))]
                    (mq/send! sock msg)
                    (async/<!! listener)))
        writer1 (partial generic-writer (:rhs one-pair))
        writer2 (partial generic-writer (:rhs two-pair))
        configuration-tree {:one {:mq-ctx ctx
                                  :ex-sock (:lhs one-pair)
                                  :in-chan (async/chan)
                                  :external-reader reader
                                  :external-writer writer1}
                            :two {:mq-ctx ctx
                                  :ex-sock (:lhs two-pair)
                                  :in-chan (async/chan)
                                  :external-reader reader
                                  :external-writer writer2}}]
    (cpt-dsl/build {:structure descr
                    :dependencies {}}
                   configuration-tree)))

(defn started-mock-up
  "For scenarios where the default behavior is fine
Probably won't be very useful: odds are, we'll want to
customize the reader/writer to create useful tests"
  []
  (component/start (mock-up)))

(deftest basic-loops []
  (testing "Manage start/stop"
    (let [system (started-mock-up)]
      (component/stop system))))
