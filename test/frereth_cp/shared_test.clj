(ns frereth-cp.shared-test
  (:require [clojure.test :refer (are is deftest testing)]
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

(deftest server-encoding
  (let [encoded (shared/encode-server-name "foo..bacon.com")]
    (is (= 256 (count encoded)))
    (let [segment-1-length (aget encoded 0)]
      (is (= 3 segment-1-length)))
    (let [segment-2-length (aget encoded 4)]
      (is (= 5 segment-2-length)))
    (let [segment-3-length (aget encoded 10)]
      (is (= 3 segment-3-length)))
    (are [offset expected]
        (let [actual (aget encoded offset)]
          (is (= expected (char actual))))
      1 \f
      2 \o
      3 \o
      5 \b
      6 \a
      7 \c
      8 \o
      9 \n
      11 \c
      12 \o
      13 \m)))
