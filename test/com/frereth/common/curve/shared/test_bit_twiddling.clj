(ns test-bit-twiddling
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]))

(defn rand64
  "This seems like it might be worth making more generally available.

Since it really isn't secure, that might be a terrible idea"
  []
  (let [max-signed-long (bit-shift-left 1 62)
      max+1 (* 4 (bigint max-signed-long))]
    (-> max+1
        rand
        (- (/ max+1 2))
        long)))

(deftest known-uint64-pack-unpack
  (testing "This number has specifically caused problems"
    (let [n -84455550510807040
          packed (b-t/uint64-pack! n)]
      (is packed)
      (testing "\n\t\tunpacking"
        (is (= (b-t/uint64-unpack packed)
               n))))))

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
