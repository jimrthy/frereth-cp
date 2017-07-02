(ns frereth-cp.message.message-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.message :as message]))

(deftest basic-echo
  (let [parent-cb (fn [byte-buf]
                    (throw (RuntimeException. "write this")))
        child-cb (fn [byte-buf]
                   (throw (RuntimeException. "write this")))
        state (message/initial-state parent-cb child-cb)]
    (throw (RuntimeException. "write this"))))
