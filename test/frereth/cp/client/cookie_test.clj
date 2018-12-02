(ns frereth-cp.client.cookie-test
  "Test out pieces involved in client cookie handling"
  (:require [clojure.test :refer (deftest is testing)]))

(deftest url-comparison
  (testing "Distinct addresses"
    (let [ca (java.net.InetAddress/getByName "www.google.ca")
          com (java.net.InetAddress/getByName "www.google.com")]
      (is (not= ca com))))
  (testing "Multiple domains at same address"
    (let [www (java.net.InetAddress/getByName "www.frereth.com")
          beta (java.net.InetAddress/getByName "beta.frereth.com")]
      (is (= beta www)))))
