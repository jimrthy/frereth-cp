(ns com.frereth.common.communication-test
  (:require [clojure.test :refer (deftest is)]
            [com.frereth.common.communication :refer :all]))

(deftest router-extraction []
  (let [client-id (byte-array [1 2 32 4 5])
        address-frame (byte-array [1 2 3 4])
        separator (byte-array 0)
        raw-message "This seems about as simple as it's likely to get"
        message (.getBytes (pr-str raw-message))
        frames [client-id address-frame separator message]
        extracted (extract-router-message frames)]
    (is (= client-id (:id extracted)) "Identity frame extraction failed")
    (is (= [address-frame] (:addresses extracted)) "Address mismatch")
    (is (= raw-message (:contents extracted)))))
