(ns frereth-cp.shared.crypto-test
  (:require [clojure.test :refer (deftest is)]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.crypto :as crypto]))

(deftest shared-secret-basics
  (let [client (crypto/random-key-pair)
        server (crypto/random-key-pair)
        server-shared (crypto/box-prepare (.getPublicKey client)
                                          (.getSecretKey server))
        client-shared (crypto/box-prepare (.getPublicKey server)
                                          (.getSecretKey client))]
    ;; Decrypting inner initiate vouch fails this part of
    ;; the test: those bytes aren't even vaguely equal.
    (is (b-t/bytes= client-shared server-shared))
    ;; Except...that isn't really what bytes= tests.
    ;; Q: Is it?
    ;; A: there are definitely some holes in it that I
    ;; don't understand. But this next line verifies that
    ;; this really should be cut-and-dried.
    (is (= (vec client-shared) (vec server-shared)))
    (let [nonce (byte-array [0x71 0x72 0x73 0x74
                             0x75 0x76 0x77 0x78
                             0x79 0x7a 0x7b 0x7c
                             0x7d 0x7e 0x7f 0x80
                             0x81 0x82 0x83 0x84
                             0x85 0x86 0x87 0x88])
          plain-text (.getBytes "The quick red fox jumped over the lazy brown dog")
          length (count plain-text)
          crypto-box (crypto/box-after client-shared
                                       plain-text
                                       length
                                       nonce)
          _ (assert crypto-box)
          ;; I'm doing something badly wrong.
          ;; This next form fails.
          decrypted (crypto/open-after crypto-box
                                       0
                                       length
                                       nonce
                                       server-shared)]
      (is (b-t/bytes= decrypted plain-text)))))
