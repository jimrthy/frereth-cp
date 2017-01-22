(ns com.frereth.common.curve.shared-test
  (:require [clojure.test :refer (is deftest testing)]
            [com.frereth.common.curve.shared :as shared]))

(deftest basic-byte-copy
  (let [dst (byte-array (take 32 (repeat 0)))]
    (shared/byte-copy! dst shared/hello-nonce-prefix)
    (is (= (subs (String. dst) 0 (count shared/hello-nonce-prefix))
           (String. shared/hello-nonce-prefix)))))
