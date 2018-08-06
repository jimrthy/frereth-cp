(ns frereth-cp.server.cookie-test
  "Test out pieces involved in Server Cookie handling"
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.server.cookie :as cookie]
            [frereth-cp.shared
             [crypto :as crypto]
             [logging :as log]
             [specs :as specs]]))

;; Generated randomly using random-keys for reproducible tests
(def client-keys
  {:public [3 127 -40 124 49 16 61 -10 112 -26 -18 -49 26 0 -125 82 25 -127 -20 56 -57 -46 122 -61 -58 -50 121 38 54 13 -69 66],
   :secret [49 107 -101 43 -92 109 -109 -94 -99 119 -78 65 124 -20 63 96 43 70 54 30 31 -54 -3 7 -71 90 70 -112 120 45 66 -68]})

(def server-keys
  {:public [-124 60 33 47 -58 -65 91 103 -57 -92 -61 -33 -77 80 -102 41 26 -5 -15 -78 25 82 -20 -77 90 1 107 16 21 125 109 109],
   :secret [-41 -106 17 -62 4 19 100 41 -128 -1 18 22 125 -4 -56 -57 -108 -5 45 108 110 30 -78 98 -92 94 122 22 -12 47 92 119]})

(comment
  (let [initial-log-state (log/init ::build-inner)
        {log-state ::log/state
         safe-nonce ::crypto/safe-nonce}
        (crypto/get-safe-nonce initial-log-state)]
    (vec safe-nonce)))
(def safe-nonce [-84 -68 113 9 -76 70 -40 48 109 -74 84 49 23 -1 -55 106])

(def minute-key
  [-25 -71 31 -101 88 27 116 92 100 -67 101 -76 -116 -94 -74 45 10 -60 126 -38 127 69 48 -111 -75 -32 93 123 26 103 85 -36])

(deftest compare-inner-cookie-approaches
  ;; Q: Is it worth restoring the original version that used random values?
  ;; A: No. This is just to validate that I can generate inner cookies that
  ;; are usable before deleting the original approach
  (let [initial-log-state (log/init ::build-inner)
        client-short-pk (:public client-keys)
        server-short-sk (:secret server-keys)
        original (cookie/build-inner-cookie-original initial-log-state
                                                     (byte-array client-short-pk)
                                                     (byte-array server-short-sk)
                                                     (byte-array minute-key)
                                                     (byte-array safe-nonce))
        original' (vec original)
        {nonce-suffix ::specs/server-nonce-suffix
         easier ::specs/byte-array} (cookie/build-inner-cookie initial-log-state
                                                               (byte-array client-short-pk)
                                                               (byte-array server-short-sk)
                                                               (byte-array minute-key)
                                                               (byte-array safe-nonce))
        easier' (vec easier)]
    (is (= original' easier'))
    (when (not= original' easier')
      (println "Original:\n" original' "\neasier:\n" easier')
      (is (= (count original') (count easier'))))))
