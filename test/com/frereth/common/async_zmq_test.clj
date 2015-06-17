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
                 (comment (println "Mock Reader triggered"))
                 (let [read (mq/raw-recv! sock)]
                   (comment (println "Mock Reader Received:\n" (util/pretty read)))
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
                    (mq/send! sock msg :dont-wait)
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
    (assoc (cpt-dsl/build {:structure descr
                           :dependencies {}}
                          configuration-tree)
           :other-sides {:one (:rhs one-pair)
                         :two (:rhs two-pair)})))

(defn started-mock-up
  "For scenarios where the default behavior is fine
Probably won't be very useful: odds are, we'll want to
customize the reader/writer to create useful tests"
  []
  (let [inited (mock-up)
        other (:other-sides inited)]
    (assoc (component/start (dissoc inited :other-sides))
           :other-sides other)))

(comment
  (deftest basic-loops []
    (testing "Manage start/stop"
      (let [system (started-mock-up)]
        (component/stop system)))))

(deftest message-from-outside
  "This is frustrating because it works sometimes"
  []
  (let [system (started-mock-up)]
    (try
      (let [dst (-> system :one :in-chan)
            receive-thread (async/go
                             (async/<! dst))
            src (-> system :other-sides :one)
            sym (gensym)
            msg (-> sym name .getBytes)]
        ;; Sleeping to give the event loops a chance to stabilize
        ;; just makes things worse
        (comment (Thread/sleep 100))
        (mq/send! src msg :dont-wait)
        (testing "From outside in"
          (comment (Thread/sleep 100))
          (let [[v c] (async/alts!! [(async/timeout 1000) dst])]
            (is (= sym v))
            (is (= dst c)))))
      (finally
        (component/stop system)))))

(comment
  (deftest message-to-outside []
    (let [system (started-mock-up)]
      (try
        (let [src (-> system :one :in-chan)
              dst (-> system :other-sides :one)
              msg (-> (gensym) name .getBytes)]
          (let [result (async/thread (mq/raw-recv! dst :dont-wait))
                [v c] (async/alts!! [(async/timeout 1000)
                                     [src msg]])]
            (testing "Message submitted to async loop"
              (is (= src c))
              (is v))
            (testing "Message made it to other side"
              (let [[v c] (async/alts!! [(async/timeout 1000) result])]
                (is (= msg v))
                (is (= result c))))))))))
