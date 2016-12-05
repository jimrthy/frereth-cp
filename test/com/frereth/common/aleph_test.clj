(ns com.frereth.common.aleph-test
  (:require [clojure.edn :as edn]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.aleph :as aleph]
            [clojure.core.async :as async]))

(deftest count-messages
  (testing "Count minimalist requests/responses"
    (let [counter (atom 0)
          port 12017
          handler (fn [msg]
                    (println "Message received:" msg)
                    (swap! counter inc))
          server (aleph/start-server! (aleph/request-response handler)
                                      port)]
      (try
        (let [client (aleph/start-client! "localhost" port)]
          (doseq [n (range 10)]
            (aleph/put! client n))
          (println "\nMessages sent\n")
          (doseq [n (range 10)]
            (let [m (aleph/take! client)]
              (is (= (inc n) m))))
          ;; Q: Does closing the client (whatever that means)
          ;; accomplish the same thing?
          (aleph/put! client ::none))
        (is (= @counter 10))
        (finally (.close server))))))
(comment
  (count-messages))

(deftest test-routing
  (testing "Router"
    (let [connections (atom {})
          port 12081
          expected-message (atom nil)
          sync-ch (async/chan)
          handler (fn [msg]
                    (is (= msg @expected-message))
                    (async/>!! sync-ch ::next))
          server (aleph/start-server!
                  (aleph/router connections handler)
                  port)]
      (try
        (let [client (aleph/start-client! "localhost" port)]
          (testing "Receiving"
            (doseq [n (range 10)]
              (let [msg {:payload n}]
                (reset! expected-message msg)
                (aleph/put! client msg)
                (let [[_ ch] (async/alts!! [(async/timeout 500)
                                            sync-ch])]
                  (is (= ch sync-ch))))))
          ;; This really isn't very interesting with just 1 client
          ;; But it was finicky
          (testing "Sending"
            (let [cxns @connections
                  out-fn (@connections "127.0.0.1")]
              (assert out-fn (str "Missing localhost client in " cxns))
              (let [msg '{:a 1
                          :b [2 3 4 5]
                          :c #{6 7 8}
                          :d (9 10 11 x)}
                    out-success (out-fn msg)]
                (try
                  (if-let [deferred-received (aleph/take! client ::not-found 500)]
                    (do
                      (is (= msg deferred-received)))
                    (is false "Client didn't receive anything"))
                  (catch Exception ex
                    (println "Failed trying to read from client" ex)
                    (.printStackTrace ex)))))))
        (finally
          (.close server))))))
(comment
  (test-routing))
