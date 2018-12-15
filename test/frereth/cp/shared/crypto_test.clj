(ns frereth.cp.shared.crypto-test
  (:require [clojure.spec.test.alpha :as test]
            [clojure.test :refer (deftest is testing)]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]))

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
          log-state (log/init ::shared-secret-basics)
          {decrypted ::crypto/unboxed} (crypto/open-after log-state
                                                          crypto-box
                                                          0
                                                          (+ length K/box-zero-bytes)
                                                          nonce
                                                          server-shared)
          decrypted (bytes decrypted)]
      (is (b-t/bytes= decrypted plain-text)))))

;;; FIXME: Also need a test that checks crypto/open-box

(deftest check-persistent-safe-nonce
  (let [key-dir "curve-test"
        logger (log/std-out-log-factory)
        log-state (log/init ::check-persistent-safe-nonce)]
    (testing "Same size"
      (let [nonce (byte-array K/key-length)]
        (crypto/do-safe-nonce logger log-state nonce key-dir 0 false)
        (is nonce "Just getting here was a win")))
    (testing "Leave padding at end"
      (let [nonce (byte-array (* 2 K/key-length))]
        (crypto/do-safe-nonce logger log-state nonce key-dir 0 false)
        (let [tail (drop K/key-length nonce)]
          (is (every? zero? tail)))))
    (testing "Leave padding at beginning"
      (let [nonce (byte-array (* 2 K/key-length))]
        (crypto/do-safe-nonce logger log-state nonce key-dir K/key-length false)
        (let [head (take K/key-length nonce)]
          (is (every? zero? head)))))))

(deftest check-random-safe-nonce
  (let [log-state (log/init ::check-random-safe-nonce)]
    (testing "Leave padding at end"
      (let [nonce (byte-array (* 2 K/key-length))]
        (crypto/do-safe-nonce log-state nonce 0)
        ;; The implementation doesn't match this expectation.
        ;; This approach will just fill every byte after the
        ;; offset.
        ;; In practice, that seems to be what I actually want
        ;; to do: mostly, it's taking a byte array with some
        ;; specific prefix and then appending a pseudo-random suffix.
        ;; It's probably worth remembering that it might be nice to be
        ;; able to fill a specific length. It should be at least
        ;; slightly faster to build the entire buffer/byte array in
        ;; place, rather than assembling it piece-meal (TODO: test
        ;; that).
        (let [tail (drop K/key-length nonce)]
          (is (every? zero? tail)))))
    (testing "Leave padding at beginning"
      (let [nonce (byte-array (* 2 K/key-length))]
        (crypto/do-safe-nonce log-state nonce K/key-length)
        (let [head (take K/key-length nonce)]
          (is (every? zero? head)))))))

(deftest random-mod
  (let [raw (test/check `crypto/random-mod)
        extracted (first raw)
        result (get-in extracted [:clojure.spec.test.check/ret :result])]
    (is result)))
