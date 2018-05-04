(ns frereth-cp.constants-test
  (:require [frereth-cp.shared.constants :as K]
            [clojure.test :refer (deftest is testing)]))

(deftest test-initiate-message-length-filter
  ;; It's been replaced by
  ;; (K/legal-vouch-message-length? msg-bytes)
  ;; which gets called from
  ;; frereth-cp.client.message/filter-initial-message-bytes
  ;; That trusts the message loop to get his part
  ;; correct.
  (throw (RuntimeException. "This has gone away"))
  (testing "Under 640 rounds down to nearest 16"
    (is (= (K/initiate-message-length-filter 15) 0))
    (is (= (K/initiate-message-length-filter 639) 624)))
  (testing "640 is 640"
    (is (= (K/initiate-message-length-filter 640) 640)))
  (testing "Over 640 is still 640"
    (is (= (K/initiate-message-length-filter 651) 640))
    (is (= (K/initiate-message-length-filter 6510) 640))))
