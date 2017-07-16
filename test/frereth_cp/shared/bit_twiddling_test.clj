(ns frereth-cp.shared.bit-twiddling-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.shared.bit-twiddling :as b-t]))

(deftest complement-2s
  (testing "positives"
    (is (= 0 (b-t/possibly-2s-complement-8 0)))
    (is (= 1 (b-t/possibly-2s-complement-8 1)))
    (is (= 127 (b-t/possibly-2s-complement-8 0x7f))))
  (testing "negatives"
    (is (= -1 (b-t/possibly-2s-complement-8 0xff)))
    (is (= -128 (b-t/possibly-2s-complement-8 0x80)))))

(deftest uncomplement-2s
  (testing "positives"
    (is (= 0 (b-t/possibly-2s-uncomplement-8 0)))
    (is (= 1 (b-t/possibly-2s-uncomplement-8 1)))
    (is (= 127 (b-t/possibly-2s-uncomplement-8 127))))
  (testing "negatives"
    (is (= 0xff (b-t/possibly-2s-uncomplement-8 -1)))
    (is (= 0x80 (b-t/possibly-2s-uncomplement-8 -128)))))

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
          ;; 0 72 126 -48 31 -12 -45 -2
          ;; Actual value (from C):
          ;; => 00 48 7e d0 1f f4 d3 fe
          ;; (hex -> base10 says I have that part correct now)
          packed (b-t/uint64-pack! n)]
      (is packed)
      (println (vec packed))
      (testing "\n\t\tunpacking"
        ;; When I do this manually, I get
        ;; -9166797419286604930
        ;; The unit test is failing because it returns
        ;; 71727689543745096
        ;; which, in turn, unpacks to
        ;; [72 126 -48 31 -12 -45 -2 0]
        ;; Original, expected value:
        ;; -84455550510807040
        (let [unpacked (b-t/uint64-unpack packed)]
          (is (= (class n) (class unpacked)))
          (is (= n unpacked))
          (testing "actual"
            (let [actual (byte-array [0x00 0x48 0x7e 0xd0 0x1f 0xf4 0xd3 0xfe])
                  real-unpacked (b-t/uint64-unpack actual)]
              (is (= n real-unpacked))
              (is (= real-unpacked unpacked)))))))))

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
