(ns com.frereth.common.aleph-test
  (:require [clojure.edn :as edn]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.aleph :as aleph]))

(deftest count-messages
  (let [counter (atom 0)
        port 12017
        handler (fn [bs]
                  (println "Message received:"
                         (edn/read-string (String. bs)))
                  (let [n (swap! counter inc)]
                    (-> n pr-str .getBytes)))
        server (aleph/start-server! (aleph/request-response handler)
                                    port)]
    (try
      (let [client (aleph/start-client! "localhost" port)]
        (doseq [n (range 10)]
          (let [bs (-> n pr-str .getBytes)]
            (aleph/put! client bs)))
        (println "\nMessages sent\n")
        (doseq [n (range 10)]
          (let [m (-> client
                      aleph/take!
                      String.
                      edn/read-string)]
            (is (= (inc n) m)))))
      ;; OK, ok, I need to add a marshalling wrapper
      (comment (aleph/put! client ::none))
      (is (= @counter 10))
      (finally (.close server)))))
(comment
  (count-messages))
