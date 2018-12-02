(ns frereth-cp.shared.crypto-test
  (:require [clojure.spec.test.alpha :as test]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]]))

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
          decrypted (crypto/open-after crypto-box
                                       0
                                       (+ length K/box-zero-bytes)
                                       nonce
                                       server-shared)
          dst (byte-array length)]
      (.getBytes decrypted 0 dst)
      (is (b-t/bytes= dst plain-text)))))

;;; FIXME: Also need a test that checks crypto/open-box

(deftest check-persistent-safe-nonce
  (let [key-dir "curve-test"]
    (testing "Same size"
      (let [nonce (byte-array K/key-length)]
        (crypto/do-safe-nonce nonce key-dir 0 false)
        (is nonce "Just getting here was a win")))
    (testing "Leave padding at end"
      (let [nonce (byte-array (* 2 K/key-length))]
        (crypto/do-safe-nonce nonce key-dir 0 false)
        (let [tail (drop K/key-length nonce)]
          (is (every? zero? tail)))))
    (testing "Leave padding at beginning"
      (let [nonce (byte-array (* 2 K/key-length))]
        (crypto/do-safe-nonce nonce key-dir K/key-length false)
        (let [head (take K/key-length nonce)]
          (is (every? zero? head)))))))

(deftest check-random-safe-nonce
  (testing "Leave padding at end"
    (let [nonce (byte-array (* 2 K/key-length))]
      (crypto/do-safe-nonce nonce 0)
      (let [tail (drop K/key-length nonce)]
        (is (every? zero? tail)))))
  (testing "Leave padding at beginning"
    (let [nonce (byte-array (* 2 K/key-length))]
      (crypto/do-safe-nonce nonce K/key-length)
      (let [head (take K/key-length nonce)]
        (is (every? zero? head))))))

(deftest random-mod
  (let [raw (test/check `crypto/random-mod)
        extracted (first raw)
        result (get-in extracted [:clojure.spec.test.check/ret :result])]
    (is result)))
