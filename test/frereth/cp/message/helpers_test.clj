(ns frereth-cp.message.helpers-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.message
             [helpers :as help]
             [specs :as specs]
             [test-utilities :as test-helpers]]))

(deftest check-basic-acking
  (let [target {::value 1
                ::specs/ackd? false}
        not-target {::value 2
                    ::specs/ackd? false}
        start {::specs/un-ackd-blocks #{target
                                        not-target}}
        actual (help/mark-block-ackd start target)
        expected {::specs/un-ackd-blocks #{not-target
                                           (assoc target ::specs/ackd? true)}}]
    (is (= expected actual))))

(deftest check-mark-acked
  (let [start-state (test-helpers/build-ack-flag-message-portion)
        ;; Pretend we just received an ACK
        ackd-addr 56
        acked (help/mark-ackd-by-addr start-state 0 ackd-addr)]
    (try
      (comment (pprint acked))
      (is (= (keys start-state) (keys (dissoc acked ::help/n))))
      ;; It's tempting to convert these to a set to make
      ;; comparing problems easier.
      ;; But start-state has invalid data now, since one of
      ;; its ByteBuf instances has been released.
      (let [b1 (get-in start-state [::specs/outgoing ::specs/un-ackd-blocks])
            b1n (count b1)
            b2 (get-in acked [::specs/outgoing ::specs/un-ackd-blocks])
            b2n (count b2)]
        (when-not (= b1n b2n)
          ;; Can't call clojure.data/diff due to the same issue with
          ;; the released ByteBuf
          #_(comment (pprint (clojure.data/diff b1 b2)))
          (is (= b1n b2n)
              (str "Start-state has " b1n
                   " blocks.\nFlagged version has "
                   b2n
                   "\n")))
        (let [dropped (filter (fn [{:keys [::specs/start-pos
                                           ::specs/length]}]
                                (> ackd-addr (+ start-pos length)))
                              b1)
              expected (apply set (map (partial disj b1) dropped))
              actual (set (mapcat (fn [x]
                                    (if (::specs/ackd? x)
                                      nil
                                      [x]))
                                  b2))]
          (println "Expected:\n" expected "\nbased on\n" b1)
          (println "Actual:\n" actual "\nbased on\n" b2)
          (is (= expected
                 actual))))
      (finally
        ;; Don't do this over start-state, since 1 of its buffers has been released
        (doseq [b (::specs/blocks acked)]
          (.release (::specs/buf b)))))))

(deftest check-flag-acked-block
  (let [start-state (test-helpers/build-ack-flag-message-portion)
        blocks (get-in start-state [::specs/outgoing ::specs/un-ackd-blocks])
        block (last blocks)
        flagged (help/flag-ackd-blocks 0 56
                                       start-state
                                       block)]
    (try
      (testing "ACK'd"
        (let [expected (-> start-state
                           (update-in [::specs/outgoing ::specs/un-ackd-blocks]
                                      (fn [cur]
                                        (-> cur
                                            (disj block)
                                            (conj (assoc block ::specs/ackd? true)))))
                           (assoc-in [::specs/outgoing ::specs/total-block-transmissions] 1)
                           (assoc-in [::specs/outgoing ::specs/total-blocks] 1))]
          (is (= expected flagged))))
      (testing "Not"
          (let [flagged (help/flag-ackd-blocks 0 56
                                               start-state
                                               (second blocks))]
            (is (= start-state flagged))))
      (finally
        (doseq [b (::specs/blocks start-state)]
          (.release (::specs/buf b)))))))
