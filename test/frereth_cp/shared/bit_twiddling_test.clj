(ns frereth-cp.shared.bit-twiddling-test
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (are deftest is testing)]
            [clojure.test.check.clojure-test :as c-t]
            [clojure.test.check.generators :as lo-gen]
            [clojure.test.check.properties :as props]
            [frereth-cp.shared.bit-twiddling :as b-t])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(comment
  ;; This isn't working.
  ;; Q: Why not?
  (deftest check-byte-buf-conversion
    (let [n 256
          buf (Unpooled/buffer n)
          byte-array-class (class (byte-array 0))]
      (doseq [x (range n)] (.writeByte buf x))
      (let [bs (b-s/convert buf #_(byte-array n) #_bytes byte-array-class)]
        (is (= n (count bs))))
      (let [bss (b-s/convert buf (b-s/seq-of byte-array-class))]
        (is (= 1 (count bss)))
        (is (= n (count (first bss)))))
      ;; Note that this will release the ByteBuf
      (b-s/print-bytes buf)
      (let [s (b-t/->string buf)]
        ;; It seems tempting to do some sort of validation here.
        ;; Really, the fact that it works without throwing an exception
        ;; is a victory.
        (is s)))))

(deftest complement-2s
  (are [x expected] (= expected (b-t/possibly-2s-complement-8 x))
    0 0
    1 1
    0x7f 127
    0xff -1
    0x80 -128
    ;; Q: Am I interpreting this correctly?
    208 -48
    180 -76))

(deftest uncomplement-2s
  (are [x expected] (= expected (b-t/possibly-2s-uncomplement-8 x))
    0 0
    1 1
    127 127
    -1 0xff
    -128 0x80))

(c-t/defspec check-uint16-unpack
  (props/for-all [n (s/gen (s/int-in 0 65536))]
                 (is (= n (-> n
                              b-t/uint16-pack
                              b-t/uint16-unpack)))))

(deftest byte-1-uint64-pack
  ;; This is really just a circular truism.
  ;; uint64-pack! is built around possibly-2s-complement-8.
  (are [expected] (= (aget (b-t/uint64-pack! expected) 0)
                     (b-t/possibly-2s-complement-8 expected))
    1 127 128 180))

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
  ;; TODO: Generative testing clearly seems appropriate/required here
  (testing "Get random 64-bit int"
    (let [n (rand64)]
      (if (not= n 0)
        (testing "\n\tpacking"
          (let [packed (b-t/uint64-pack! n)]
            (is packed)
            (testing "\n\t\tunpacking"
              (is (= (b-t/uint64-unpack packed)
                     n)))))))))
