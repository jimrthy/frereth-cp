(ns com.frereth.common.aleph-test
  (:require [clojure.edn :as edn]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.aleph :as aleph]))

(deftest count-messages
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
      (finally (.close server)))))
(comment
  (count-messages))
