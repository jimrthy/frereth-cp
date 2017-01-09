(ns com.frereth.common.curve.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.server :as server]
            [com.stuartsierra.component :as cpt]
            [component-dsl.system :as cpt-dsl]
            [manifold.stream :as strm]))

(defn build
  [client-chan]
  (let [cfg {:cp-server {:client-chan client-chan
                         :security {:keydir "curve-test"
                                    ;; Note that name really isn't legal.
                                    ;; It needs to be something we can pass
                                    ;; along to DNS, padded to 255 bytes.
                                    ;; This bug really should show up in
                                    ;; a test.
                                    :name "local.test"}
                         :extension (byte-array [0x01 0x02 0x03 0x04
                                                 0x05 0x06 0x07 0x08
                                                 0x09 0x0a 0x0b 0x0c
                                                 0x0d 0x0e 0x0f 0x10])}}
        structure {:cp-server com.frereth.common.curve.server/ctor}]
    (cpt-dsl/build #:component-dsl.system {:structure structure
                                           :dependencies {}}
                   cfg)))

(deftest start-stop
  (testing "That we can start and stop successfully"
    (let [init (build (promise))
          started (cpt/start init)]
      (is started)
      (is (cpt/stop started)))))

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
