(ns com.frereth.common.communication-test
  (:require [clojure.test :refer (deftest is)]
            [com.frereth.common.communication :refer :all]))

(deftest router-extraction []
  (let [client-id (byte-array [1 2 32 4 5])
        address-frame (byte-array 0)
        separator (byte-array 0)
        message (.getBytes "This seems about as simple as it's likely to get")
        frames [client-id address-frame separator message]
        extracted (extract-router-message frames)]
    (is (= client-id (:id extracted)) "Identity frame extraction failed")
    (is (= (list) (:addresses extracted)) "Address mismatch")
    (is (= [message] (:contents extracted)))))
