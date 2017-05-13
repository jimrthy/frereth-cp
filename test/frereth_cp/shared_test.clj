(ns frereth-cp.shared-test
  (:require [clojure.test :refer (is deftest testing)]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]))

(deftest basic-byte-copy
  (let [dst (byte-array (take 32 (repeat 0)))]
    (b-t/byte-copy! dst shared/hello-nonce-prefix)
    (is (= (subs (String. dst) 0 (count shared/hello-nonce-prefix))
           (String. shared/hello-nonce-prefix)))))

(deftest check-byte=
  (let [lhs (byte-array (take 256 (repeat 0)))
        rhs (byte-array (take 255 (repeat 0)))]
    (is (not (b-t/bytes= lhs rhs)))
    (let [rhs (byte-array (take 256 (repeat 0)))]
      (is (b-t/bytes= lhs rhs)))
    (let [rhs (byte-array (take 256 (repeat 1)))]
      (is (not (b-t/bytes= lhs rhs))))
    (let [rhs (byte-array (assoc (vec (take 256 (repeat 0))) 255 3))]
      (is (not (b-t/bytes= lhs rhs))))))
