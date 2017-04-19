(ns test-bit-twiddling
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]))

(deftest complement-2s
  (testing "positives"
    (is (= 0 (b-t/possibly-2s-complement 0)))
    (is (= 1 (b-t/possibly-2s-complement 1)))
    (is (= 127 (b-t/possibly-2s-complement 0x7f))))
  (testing "negatives"
    (is (= -1 (b-t/possibly-2s-complement 0xff)))
    (is (= -128 (b-t/possibly-2s-complement 0x80)))))

(deftest uncomplement-2s
  (testing "positives"
    (is (= 0 (b-t/possibly-2s-uncomplement 0)))
    (is (= 1 (b-t/possibly-2s-uncomplement 1)))
    (is (= 127 (b-t/possibly-2s-uncomplement 127))))
  (testing "negatives"
    (is (= 0xff (b-t/possibly-2s-uncomplement -1)))
    (is (= 0x80 (b-t/possibly-2s-uncomplement -128)))))

(deftest known-uint64-pack-unpack
  (testing "This number has specifically caused problems"
    ;; According to python, n & 0xff == 0.
    ;; I'm getting -128.
    ;; Neither seems to make sense, since
    ;; 40 == 0x28.
    ;; Even if I'm getting confused by little/big
    ;; -endian issues...actually, that's probably
    ;; it.
    ;; -32678 | -56 *is* -56.
    ;; Q: Would it make sense to pack the abs(),
    ;; then set the signed bit on the final number?
    (let [n -84455550510807040
          ;; 84455550510807040 == 0x1280e02f81b800
          ;; => 12 80 e0 2f 81 b8 00   (split it into bytes)
          ;; => 00 b8 81 2f e0 80 12   ("reversed")
          ;; => 00 b8 81 2f e0 80 92   (set the initial - bit)
          packed (b-t/uint64-pack! n)]
      (is packed)
      ;; Just because I'm having lots of fun with this, it packs into:
      ;; [-128 -56 -2 80 -97 116 83 126]
      ;; [-128 -56 -2 80 -97 116 83 126] ; Original "hard-coded"
      (println (vec packed))
      (testing "\n\t\tunpacking"
        ;; When I do this manually, I get
        ;; -9166797419286604930
        ;; The unit test is failing because it returns
        ;; (9102747499453401216)
        ;; Original, expected value:
        ;; -84455550510807040
        (let [unpacked (b-t/uint64-unpack packed)]
          (is (= (class n) (class unpacked)))
          (is (= n unpacked)))))))

(defn rand64
  "Pretty much what randint does, but extended for a full 64-bits

This seems like it might be worth making more generally available.

Since it really isn't secure, that might be a terrible idea"
  []
  (let [max-signed-long (bit-shift-left 1 62)
      max+1 (* 4 (bigint max-signed-long))]
    (-> max+1
        rand
        (- (/ max+1 2))
        long)))

(deftest random-uint64-pack-unpack
  ;; Generative testing clearly seems appropriate/required here
  ;; TODO: as soon as I figure out why the basic implementation's
  ;; broken
  (testing "Get random 64-bit int"
    (let [n (rand64)]
      (if (not= n 0)
        (testing "\n\tpacking"
          (let [packed (b-t/uint64-pack! n)]
            (is packed)
            (testing "\n\t\tunpacking"
              (is (= (b-t/uint64-unpack packed)
                     n)))))))))
