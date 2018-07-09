(ns frereth-cp.server.cookie-test
  "Test out pieces involved in Server Cookie handling"
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.server.cookie :as cookie]
            [frereth-cp.shared
             [crypto :as crypto]
             [logging :as log]
             [specs :as specs]]))

(deftest compare-inner-cookie-approaches
  (let [initial-log-state (log/init ::build-inner)
        client-keys (crypto/random-keys "compare-inner")
        client-short-pk (::specs/my-compare-inner-public client-keys)]
    (is client-short-pk (str "From " (keys client-keys) " in " client-keys))
    (let [my-keys (crypto/random-key-pair)
          minute-key (crypto/random-key)
          {log-state ::log/state
           working-nonce ::specs/byte-array} (crypto/get-safe-nonce initial-log-state)
          original (cookie/build-inner-cookie-original initial-log-state
                                                       client-short-pk
                                                       my-keys
                                                       minute-key
                                                       (vec working-nonce))
          {easier ::specs/byte-array} (cookie/build-inner-cookie initial-log-state
                                                                 client-short-pk
                                                                 my-keys
                                                                 minute-key
                                                                 (vec working-nonce))]
      (is (= (vec original) (vec easier)))
      (when (not= (vec original) (vec easier))
        ;; original is 112 bytes vs. easier's 96.
        ;; So I've definitely managed to bungle something
        (is (= (count original) (count easier)))))))
