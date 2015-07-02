(ns com.frereth.common.async-zmq-test
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.async-zmq :refer :all]
            [com.frereth.common.zmq-socket :as common-mq]
            [com.frereth.common.util :as util]
            [com.stuartsierra.component :as component]
            [component-dsl.system :as cpt-dsl]
            [schema.core :as s])
  (:import [com.stuartsierra.component SystemMap]))

(defn mock-structure
  []
  '{:one com.frereth.common.async-zmq/ctor
    :two com.frereth.common.async-zmq/ctor
    :ex-one com.frereth.common.zmq-socket/ctor
    :ex-two com.frereth.common.zmq-socket/ctor
    :ctx com.frereth.common.zmq-socket/ctx-ctor})

(defn mock-cfg
  []
  (let [;; TODO: It's tempting to set these built-ins
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
        internal-url (name (gensym))]
    {:one {:_name "Event Loop One"
           :in-chan (async/chan)
           :external-reader reader
           :external-writer writer1}
     :two {:_name "Event Loop Two"
           :in-chan (async/chan)
           :external-reader reader
           :external-writer writer2}
     :ex-one {:url {:protocol :inproc
                    :address internal-url}
              :sock-type :pair
              :direction :bind}
     :ex-two {:url {:protocol :inproc
                    :address internal-url}
              :sock-type :pair
              :direction :connect}}))

(defn mock-depends
  []
  {:one {:ex-sock :ex-one}
   :two {:ex-sock :ex-two}
   :ex-one [:ctx]
   :ex-two [:ctx]})

(defn mock-up
  "TODO: Need tests that work with both EventEair instances"
  []
  (let [descr (mock-structure)
        dependencies (mock-depends)
        configuration-tree (mock-cfg)]
    (cpt-dsl/build {:structure descr
                    :dependencies dependencies}
                   configuration-tree)))

(defn started-mock-up
  "For scenarios where the default behavior is fine
Probably won't be very useful: odds are, we'll want to
customize the reader/writer to create useful tests"
  []
  (component/start (mock-up)))

(s/defn with-mock
  "This really isn't a good way to handle this, but it seems like an obvious lazy starter approach

To be fair, the 'proper' approach here is starting to look like a macro.

I've already been down that path with midje.

I'd like to pretend that the results would be happier with macros that
I write, but I know better."
  [f :- (s/=> s/Any SystemMap)]
  (let [system (started-mock-up)]
    (try
      (f system)
      (finally
        (component/stop system)))))

(deftest basic-loops []
    (testing "Manage start/stop"
      (let [system (started-mock-up)]
        (component/stop system))))

(comment
  #_(require '[com.frereth.common.async-zmq-test :as azt])
  (def mock (#_azt/started-mock-up started-mock-up))
  (mq/send! (-> mock :other-sides :one) (pr-str {:a 1 :b 2 :c 3}) :dont-wait)
  (async/alts!! [(async/timeout 1000) (-> mock :one :ex-chan)])
  (component/stop mock))
(deftest message-from-outside
  []
  (let [system (started-mock-up)
        ;; For purposes of this test (which is more low-level
        ;; building block than realistic usage), we don't
        ;; want the "other half" EventPair stealing the message:
        ;; we just want to verify that it should have been sent.
        ;; This is more than a little ridiculous, but it *is*
        ;; a very low-level test
        src (-> system :two :ex-sock)
        stopped (component/stop (:two system))
        system (assoc system :two stopped)]
    (try
      (let [dst (-> system :one :ex-chan)
            ;; Because of the way this is wired up,
            ;; we need to read the message that stopped the
            ;; event loop
            original-killer (async/<!! dst)
            receive-thread (async/go
                             (async/<! dst))
            sym (gensym)
            msg (-> sym name .getBytes)]
        (println "Pretending to send" msg
                 "(" sym
                 ") from the outside world")
        (mq/send! (:socket src) msg :dont-wait)
        (testing "From outside in"
          (comment (Thread/sleep 100))
          (let [[v c] (async/alts!! [(async/timeout 1000) receive-thread])]
            ;; Apparently a gensym can't = the symbol we just pulled
            ;; back, even though it really is the same
            ;; Actually, it isn't. I'm getting back a different
            ;; value.
            (is (= (class sym) (class v))
                (str "v should have the same class as sym. Instead it's a"
                               (class v)))
            (is (= (name sym) (name v))
                "Response doesn't even resemble the source gensym")
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
  (let [system (started-mock-up)
        ;; Again, we don't want the "other half" EventPair
        ;; stealing the messages that we're trying to verify
        ;; reach it.
        ;; Yes, this test is pretty silly.
        dst (-> system :two :ex-sock)
        stopped (component/stop (:two system))
        stop-signal (async/<!! (-> system :one :ex-chan))      ; flush the buffer
        system (assoc system :two stopped)]
    (println "mock loops started")
    (try
      (let [src (-> system :one :in-chan)
            msg {:action :login
                 :user "#1"
                 :auth-token (gensym)
                 :character-set "utf-8"}]
        (println "Submitting" msg "to internal channel")
        (let [[v c] (async/alts!! [(async/timeout 1000)
                                   [src msg]])]
          (testing "Message submitted to async loop"
            (is (= src c) "Timed out trying to send")
            (is v))

          ;; give it time to get through the loop
          ;; This shouldn't matter. If there isn't a listener
          ;; ready, the sender should block
          (comment (println "Pausing to let message get through loop pairs")
                   (Thread/sleep 1500))

          (testing "Did message make it to other side?"
            (let [result
                  (loop [retries 5
                         serialized (mq/recv! (:socket dst) :dont-wait)]
                    (if serialized
                      (let [result (deserialize serialized)]
                        (println "Received"
                                 serialized
                                 "a"
                                 (class serialized)
                                 "\naka"
                                 result "a"
                                 (class result))
                        (is (= msg result))
                        (println "message-to-outside delivered" result)
                        result)
                      (when (< 0 retries)
                        (let [n (- 6 retries)]
                          (println "Retry # " n)
                          (Thread/sleep (* 100 n))
                          (recur (dec retries)
                                 (mq/recv! (:socket dst) :dont-wait))))))]
              (is result "Message swallowed")))))
      (finally
        (component/stop system)))
    (println "message-to-outside exiting")))

(deftest echo
  []
  (testing "Can send a request and get an echo back"
    (let [test (fn [system]
                 (let [left-chan (-> system :one :in-chan)
                       ex-left (-> system :one :ex-chan)
                       right-chan (-> system :two :in-chan)
                       ex-right (-> system :two :ex-chan)
                       msg {:op :echo
                            :payload "The quick red fox"}]
                   (testing "\n\tRequest sent"
                     (let [[v c] (async/alts!! [[left-chan msg] (async/timeout 150)])]
                       (is (= c left-chan))
                       (is v)))
                   (let [[v c] (async/alts!! [ex-right (async/timeout 750)])]
                     (testing "\n\tInitial request received"
                       (is (= c ex-right))
                       (is (= msg v))))
                   (let [[v c] (async/alts!! [[right-chan msg] (async/timeout 150)])]
                     (testing "\n\tResponse sent"
                       (is (= c right-chan))
                       (is v)))
                   (let [[v c] (async/alts!! [ex-left (async/timeout 750)])]
                     (testing "\n\tEcho received"
                       (is (= c ex-left))
                       (is (= msg v))))))]
      (with-mock test))))

(deftest evaluate
  []
  (testing "Can send a request and get an echo back"
    (let [test (fn [system]
                 (let [left-chan (-> system :one :in-chan)
                       ex-left (-> system :one :ex-chan)
                       right-chan (-> system :two :in-chan)
                       ex-right (-> system :two :ex-chan)
                       x (rand-int 1000)
                       y (rand-int 1000)
                       msg {:op :eval
                            :payload (list '* x y)}]
                   (testing "\n\tRequest sent"
                     (let [[v c] (async/alts!! [[left-chan msg] (async/timeout 150)])]
                       (is (= c left-chan))
                       (is v)))
                   (let [[v c] (async/alts!! [ex-right (async/timeout 750)])]
                     (testing "\n\tInitial request received"
                       (is (= c ex-right))
                       (is (= msg v)))
                     (let [read (:payload v)
                           op (first read)
                           result (apply op (rest read))
                           [v c] (async/alts!! [[right-chan result] (async/timeout 150)])]
                       (testing "\n\tResponse sent"
                         (is (= c right-chan))
                         (is v))))
                   (let [[v c] (async/alts!! [ex-left (async/timeout 750)])]
                     (testing "\n\tEcho received"
                       (is (= c ex-left))
                       (is (= (* x y) v))))))]
      (with-mock test))))
