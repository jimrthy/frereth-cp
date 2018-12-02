(ns frereth.cp.shared-test
  (:require [clojure.spec.alpha :as s]
            [clojure.test :refer (are is deftest testing)]
            [frereth.cp.shared :as shared]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]]))

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
