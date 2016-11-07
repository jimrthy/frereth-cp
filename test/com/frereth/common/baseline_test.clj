(ns com.frereth.common.baseline-test
  "For checking the pieces underlying my Components"
  (:require [cljeromq.core :as mq]
            [clojure.spec :as s]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.async-zmq]
            [com.frereth.common.util :as util]))

(deftest check-reader-spec
  (let [reader (fn [sock]
                 (let [read (mq/raw-recv! sock)]
                   (comment) (println "Mock Reader Received:\n" (util/pretty read))
                   (util/deserialize read)))]
    (when-not (s/valid? :com.frereth.common.async-zmq/external-reader reader)
      (is (not (s/explain :com.frereth.common.async-zmq/external-reader reader))))))
(comment
  (check-reader-spec)
  )
