(ns com.frereth.common.aleph-test
  (:require [aleph.udp :as udp]
            [byte-streams :as b-s]
            [clojure.edn :as edn]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.aleph :as aleph]
            [clojure.core.async :as async]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm]))

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
            (let [m (aleph/take! client ::timed-out 500)]
              (is (= (inc n) m))))
          ;; Q: Does closing the client (whatever that means)
          ;; accomplish the same thing?
          ;; (That doesn't seem to be a thing)
          (aleph/put! client ::none))
        (is (= @counter 10))
        (finally (.close server))))))
(comment
  (count-messages))

(deftest test-routing
  ;; This approach no longer makes any real sense, assuming it ever did
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
                  out-fn (get cxns "127.0.0.1")]
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

(deftest udp-basics
  (let [port 17718
        server-future (udp/socket {:port port})
        server (deref server-future 20 ::timed-out)]
    (println "Server future:" server-future)
    (if-not (= server ::timed-out)
      (try
        ;; Note that this approach is highly likely to have firewall issues.
        ;; Although so will pretty much any/every other.
        (let [client @(udp/socket {})]
          (try
            (let [initial-pull-future (strm/try-take! server ::drained 50 ::timed-out)
                  msg-1 {:host "localhost"
                         :port port
                         :message (byte-array (range 256))}
                  initial-put-future (strm/try-put! client msg-1 50 ::timed-out)]
              (dfrd/on-realized initial-pull-future
                                (fn success [{:keys [message]
                                              :as packet}]
                                  (println "Initial message received by server:" message
                                           "\ncontained in" packet)
                                  (is (b-s/bytes= message (:message msg-1)))
                                  (let [pull-2-future (strm/try-take! client ::drained 50 ::timed-out)
                                        msg-2 (byte-array (range 256 1024))
                                        put-2-future (strm/try-put! server (assoc packet :message msg-2) 50 ::timed-out)]
                                    (dfrd/on-realized put-2-future
                                                      (fn [success]
                                                        (is (not= success ::timed-out)))
                                                      (fn [failure]
                                                        (is (not failure))))
                                    (dfrd/on-realized pull-2-future
                                                      (fn [{:keys [:host :message]
                                                            in-port :port}]
                                                        (println "Incoming message:" message)
                                                        (is (b-s/bytes= message msg-2))
                                                        (println "Incoming port:" in-port)
                                                        (is (= port in-port)))
                                                      (fn [fail]
                                                        (is false fail)))
                                    (let [round-tripped (deref pull-2-future 50 ::timed-out)]
                                      (is (not= round-tripped ::timed-out)))))
                                (fn fail [x]
                                  (is (not x))))
              (dfrd/on-realized initial-put-future
                                (fn success [x]
                                  (is (not= x ::timed-out)))
                                (fn fail [x]
                                  (is (not x))))
              (is (not= (deref initial-pull-future 50 ::timed-out) ::timed-out)))
            (finally (strm/close! client))))
        (finally (strm/close! server)))
      (is (not= server ::timed-out)))))
