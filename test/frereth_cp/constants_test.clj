(ns frereth-cp.constants-test
  (:require [com.frereth.common.curve.shared.constants :as K]
            [clojure.test :refer (deftest is testing)]))

(deftest test-initiate-message-length-filter
  (testing "Under 640 rounds down to nearest 16"
    (is (= (K/initiate-message-length-filter 15) 0))
    (is (= (K/initiate-message-length-filter 639) 624)))
  (testing "640 is 640"
    (is (= (K/initiate-message-length-filter 640) 640)))
  (testing "Over 640 is still 640"
    (is (= (K/initiate-message-length-filter 651) 640))
    (is (= (K/initiate-message-length-filter 6510) 640))))
