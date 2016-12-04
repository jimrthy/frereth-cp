(ns com.frereth.common.aleph-test
  (:require [clojure.edn :as edn]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.aleph :as aleph]))

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
  (println "Starting test-routing")
  (testing "Router"
    (let [connections (atom {})
          port 12081
          expected-message (atom nil)
          handler (fn [msg]
                    (is (= msg @expected-message)))
          server (aleph/start-server!
                  (aleph/router connections handler)
                  port)]
      (try
        (let [client (aleph/start-client! "localhost" port)]
          (testing "Receiving"
            (doseq [n (range 10)]
              (let [msg {:payload n}]
                (reset! expected-message msg)
                (aleph/put! client msg))
              (Thread/sleep 10)))
          ;; This really isn't very interesting with just 1 client
          ;; But it was finicky
          (testing "Sending"
            (let [cxns @connections
                  out-fn (@connections "127.0.0.1")
                  msg '{:a 1
                        :b [2 3 4 5]
                        :c #{6 7 8}
                        :d (9 10 11 x)}
                  out-success (out-fn #_msg "The quick red fox")]
              (println "out-success:" out-success
                       "a" (class out-success)
                       "Actual:" @out-success)
              (println "Did the client receive that message?")
              (try
                (if-let [deferred-received (aleph/take! client ::not-found)]
                  (do
                    (println "Got" deferred-received "back from calling take")
                    ;; Take is already calling deref. Shouldn't need to
                    ;; do this again
                    (is (= deferred-received msg)))
                  (is false "Client didn't receive anything"))
                (catch Exception ex
                  (println "Failed trying to read from client" ex)
                  (.printStackTrace ex))))))
        (finally
          (println "Stopping server")
          (.close server))))))
(comment
  (test-routing))
