(ns com.frereth.common.curve.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.server :as server]
            [manifold.stream :as strm]
            [mount.core :as mount]))

(defn start
  [client-chan]
  (-> (mount/only #{#'server/cp-state})
      (mount/with-args {:server-state {:client-chan client-chan
                                       :security {:name "local.test"
                                                  :keydir "curve-test"}
                                       :extension (byte-array [0x01 0x02 0x03 0x04
                                                               0x05 0x06 0x07 0x08
                                                               0x09 0x0a 0x0b 0x0c
                                                               0x0d 0x0e 0x0f 0x10])}})
      mount/start))

(deftest start-stop
  (testing "That we can start and stop successfully"
    (let [started (start (promise))]
      (is (= {:started ["#'com.frereth.common.curve.server/cp-state"]} started)))
    (is (= {:stopped ["#'com.frereth.common.curve.server/cp-state"]} (mount/stop)))))

(deftest shake-hands
  (let [client (strm/stream)]
    (let [started (start client)]
      (println "Server should be started now"))
    (try
      (println "Sending HELLO")
      (let [success (deref (strm/try-put! client "Howdy!" 1000 ::timed-out))]
        (println "put! success:" success)
        (is (not= ::timed-out success)))
      (finally
        (println "Triggering event loop exit")
        (is (mount/stop))))))
