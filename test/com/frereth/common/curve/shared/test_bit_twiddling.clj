(ns test-bit-twiddling
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]))

(deftest uint64-pack-unpack
  (testing "Get random 64-bit int"
    (loop [tries 5]
      (if (< 0 tries)
        ;; Q: How do I actually do this?
        ;; I think I probably really need BigIntegers.
        ;; But they don't support bitwise operations.
        ;; There *is* a clojure.test.check.generator
        ;; for this, which seems like it may be the way to go.
        (let [n (- (rand-int (bit-shift-left 1 64))
                   (bit-shift-left 1 63))]
          (if (not= n 0)
            (testing "packing"
              (let [packed (b-t/uint64-pack! n)]
                (is packed)
                (testing "unpacking"
                  (is (= (b-t/uint64-unpack packed)
                         n)))))
            (recur (dec n))))
        (is false "Giving up")))))
