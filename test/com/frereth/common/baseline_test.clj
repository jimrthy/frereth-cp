(ns com.frereth.common.baseline-test
  "For checking the pieces underlying my Components"
  (:require [cljeromq.core :as mq]
            [cljeromq.curve :as curve]
            [clojure.spec :as s]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.async-zmq]
            [com.frereth.common.util :as util]
            [com.frereth.common.zmq-socket]))

(deftest check-reader-spec
  (let [reader (fn [sock]
                 (let [read (mq/raw-recv! sock)]
                   (comment) (println "Mock Reader Received:\n" (util/pretty read))
                   (util/deserialize read)))]
    (when-not (s/valid? :com.frereth.common.async-zmq/external-reader reader)
      (is (not (s/explain :com.frereth.common.async-zmq/external-reader reader))))))
(comment (check-reader-spec))

(deftest check-server-socket
  (testing "Server version of socket spec that fails when I start the async-zmq-loop"
    (let [ctx (mq/context 1)]
      (try
        (let [sock (mq/socket! ctx :pair)]
          (try
            (let [internal-url (name (gensym))
                  server-keys (curve/new-key-pair)
                  server (com.frereth.common.zmq-socket/ctor {:context-wrapper {:ctx ctx
                                                                                :thread-count 1}
                                                              :zmq-url #:cljeromq.common{:zmq-protocol :inproc
                                                                                         :zmq-address internal-url}
                                                              :sock-type :pair
                                                              :socket sock
                                                              :direction :bind
                                                              :server-key (:private server-keys)})]
              (when-not (s/valid? :com.frereth.common.zmq-socket/server-socket-description server)
                (println "Failed base server socket spec")
                (is (not (s/explain :com.frereth.common.zmq-socket/server-socket-description server))))
              (when-not (s/valid? :com.frereth.common.zmq-socket/socket-description server)
                (println "Failed generic socket description spec")
                (is (not (s/explain :com.frereth.common.zmq-socket/socket-description server)))))
            (finally
              (mq/close! sock))))
        (catch clojure.lang.ExceptionInfo ex
          (is (not (.getMessage ex)))
          (is (not (.getData ex)))
          (throw ex))
        (finally
          (mq/terminate! ctx))))))
(comment (check-server-socket))

(deftest check-client-socket
  (testing "Client half of socket spec that fails when I start the async-zmq-loop"
    (let [ctx (mq/context 1)]
      (try
        (let [sock (mq/socket! ctx :pair)]
          (try
            (let [internal-url (name (gensym))
                  server-keys (curve/new-key-pair)
                  server (com.frereth.common.zmq-socket/ctor {:context-wrapper {:ctx ctx
                                                                                :thread-count 1}
                                                              :zmq-url #:cljeromq.common{:zmq-protocol :inproc
                                                                                         :zmq-address internal-url}
                                                              :socket sock
                                                              :sock-type :pair
                                                              :direction :connect
                                                              :client-keys (curve/new-key-pair)
                                                              :server-key (:public server-keys)})]
              (is (s/valid? :com.frereth.common.zmq-socket/client-socket-description server))
              (is (s/valid? :com.frereth.common.zmq-socket/socket-description server)))
            (finally (mq/close! sock))))
        (finally
          (mq/terminate! ctx))))))
(comment (check-client-socket))
