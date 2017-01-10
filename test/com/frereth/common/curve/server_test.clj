(ns com.frereth.common.curve.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.server :as server]
            [com.stuartsierra.component :as cpt]
            [component-dsl.system :as cpt-dsl]
            [manifold.stream :as strm]))

(defrecord StreamOwner [chan]
  cpt/Lifecycle
  (start
    [this]
    (assoc this :chan (or chan (strm/stream))))
  (stop
    [this]
    (println "Stopping StreamOwner")
    (when chan
      (strm/close! chan))
    (assoc this :chan nil)))
(defn chan-ctor
  [_]
  (->StreamOwner (strm/stream)))

(def options {:cp-server {:security {:keydir "curve-test"
                                     ;; Note that name really isn't legal.
                                     ;; It needs to be something we can pass
                                     ;; along to DNS, padded to 255 bytes.
                                     ;; This bug really should show up in
                                     ;; a test.
                                     :name "local.test"}
                          :extension (byte-array [0x01 0x02 0x03 0x04
                                                  0x05 0x06 0x07 0x08
                                                  0x09 0x0a 0x0b 0x0c
                                                  0x0d 0x0e 0x0f 0x10])}})
(def sys-struct {:cp-server 'com.frereth.common.curve.server/ctor
                 :client-chan 'com.frereth.common.curve.server-test/chan-ctor})

(defn build
  []
  (let [structure sys-struct]
    (cpt-dsl/build #:component-dsl.system {:structure structure

                                           :dependencies {:cp-server [:client-chan]}}
                   options)))

(deftest start-stop
  (testing "That we can start and stop successfully"
    (let [ch (strm/stream)
          init (build ch)
          started (cpt/start init)]
      (is started)
      (strm/close! ch)
      (is (cpt/stop started)))))
(comment
  (def test-sys (build))
  (alter-var-root #'test-sys cpt/start)
  (alter-var-root #'test-sys cpt/stop)
  )

(deftest shake-hands
  (let [client (strm/stream)]
    (let [init (build client)
          started (cpt/start init)]
      (println "Server should be started now")
      (try
        (println "Sending HELLO")
        (let [success (deref (strm/try-put! client "Howdy!" 1000 ::timed-out))]
          (println "put! success:" success)
          (is (not= ::timed-out success)))
        (finally
          (println "Triggering event loop exit")
          (cpt/stop started))))))
