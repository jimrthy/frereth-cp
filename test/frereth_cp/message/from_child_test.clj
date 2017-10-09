(ns frereth-cp.message.from-child-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.message.from-child :as from-child]
            [frereth-cp.message.specs :as specs])
  (:import clojure.lang.PersistentQueue))

(deftest child-consumption
  (let [start-state #:frereth-cp.message.specs {:message-loop-name "Testing basic consumption from child"
                                                :outgoing #:frereth-cp.message.specs {:max-block-length 512
                                                                                      :ackd-addr 0
                                                                                      :strm-hwm 0
                                                                                      :un-sent-blocks PersistentQueue/EMPTY}}
        bytes-to-send (byte-array (range 8193))]
    (let [{:keys [::specs/outgoing]
           :as result} (from-child/consume-from-child start-state bytes-to-send)]
      (is (= 8193 (::specs/strm-hwm outgoing)))
      (is (= 0 (::specs/ackd-addr outgoing)))
      (is (= 512 (::specs/max-block-length outgoing)))
      (is (= 17 (count (::specs/un-sent-blocks outgoing)))))))
