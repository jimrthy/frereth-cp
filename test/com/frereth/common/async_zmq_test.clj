(ns com.frereth.common.async-zmq-test
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.async-zmq :refer :all]
            [com.frereth.common.util :as util]
            [com.stuartsierra.component :as component]
            [component-dsl.system :as cpt-dsl]))

(defn mock-up
  "The second half of this seems pretty pointless
  FIXME: Make it go away"
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
        generic-writer (fn [which sock msg]
                         ;; Q: if we're going to do this,
                         ;; does the event loop need access to the socket at all?
                         ;; A: Yes. Because it spends most of its time polling on that socket
                         (println "Mock writer sending" msg "on Pair" which)
                         (mq/send! sock msg :dont-wait))
        writer1 (partial generic-writer "one")
        writer2 (partial generic-writer "two")
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

(comment
  #_(require '[com.frereth.common.async-zmq-test :as azt])
  (def mock (#_azt/started-mock-up started-mock-up))
  (mq/send! (-> mock :other-sides :one) (pr-str {:a 1 :b 2 :c 3}) :dont-wait)
  (async/alts!! [(async/timeout 1000) (-> mock :one :ex-chan)])
  (component/stop mock))
(deftest message-from-outside
  []
  (let [system (started-mock-up)]
    (try
      (let [dst (-> system :one :ex-chan)
            receive-thread (async/go
                             (async/<! dst))
            src (-> system :other-sides :one)
            sym (gensym)
            msg (-> sym name .getBytes)]
        (println "Pretending to send" msg "from the outside world")
        (mq/send! src msg :dont-wait)
        (testing "From outside in"
          (comment (Thread/sleep 100))
          (let [[v c] (async/alts!! [(async/timeout 1000) receive-thread])]
            (is (= sym v))
            (is (= receive-thread c)))))
      (finally
        (component/stop system)))))

(comment
  (let [mock (started-mock-up)
        src (-> mock :one :in-chan)
        dst (-> mock :other-sides :one)
        _ (println "Kicking everything off")
        [v c] (async/alts!! [(async/timeout 1000)
                             [src "Who goes there?"]])]
    (println "Let's see how that worked")
    (if-let [serialized
             (loop [serialized (mq/raw-recv! dst :dont-wait)
                    attempts 5]
               ;; Note that, if a PAIR socket tries to send
               ;; a message when there's no peer, it blocks.
               ;; So this really should work.
               (if serialized
                 serialized
                 (do
                   (Thread/sleep 100)
                   (when (< 0 attempts))
                   (recur (mq/raw-recv! dst :dont-wait)
                          (dec attempts)))))]
      (let [result (deserialize serialized)]
        (assert v "Channel submission failed")
        (component/stop mock)
        [v result])
      ["Nothing came out" v])))

(deftest message-to-outside []
  (println "Starting mock for testing message-to-outside")
  (let [system (started-mock-up)]
    (println "mock loops started")
    (try
      (let [src (-> system :one :in-chan)
            dst (-> system :other-sides :one)
            ;;msg-string (-> (gensym) name)
            ;;msg (.getBytes msg-string)
            msg #_(gensym) {:action :login
                            :user "#1"
                            :auth-token (gensym)
                            :character-set "utf-8"}]
        (comment (Thread/sleep 500))
        (println "Submitting" msg "to internal channel")
        (let [[v c] (async/alts!! [(async/timeout 1000)
                                   [src msg]])]
          ;; We are sending this message successfully
          (testing "Message submitted to async loop"
            (is (= src c) "Timed out trying to send")
            (is v))
          (println "Pausing to let message get through loop pairs")
          (Thread/sleep 1500)  ; give it time to get through the loop
          (testing "Did message make it to other side?"
            (let [result
                  (loop [retries 5
                         serialized (mq/recv! dst :dont-wait)]
                    (if serialized
                      (let [result (deserialize serialized)]
                        (is (= msg result))
                        (println "message-to-outside delivered" result)
                        result)
                      (when (< 0 retries)
                        (let [n (- 6 retries)]
                          (println "Retry # " n)
                          (Thread/sleep (* 100 n))
                          (recur (dec retries)
                                 (mq/recv! dst :dont-wait))))))]
              (when-not result
                (is false "Message swallowed"))))))
      (finally
        (component/stop system)))
    (println "message-to-outside exiting")))
