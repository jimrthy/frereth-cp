(ns frereth-cp.message.helpers-test
  (:require [clojure.test :refer (deftest is)]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-utilities :as test-helpers]))

(deftest check-mark-acked
  (let [start-state (test-helpers/build-ack-flag-message-portion)
        acked (help/mark-acknowledged! start-state 0 56)]
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
        (when-not (= (dec b1n) b2n)
          ;; Can't call clojure.data/diff due to the same issue with
          ;; the released ByteBuf
          #_(comment (pprint (clojure.data/diff b1 b2)))
          (is (= (dec b1n) b2n)
              (str "Start-state has " b1n
                   " blocks.\nFlagged version has "
                   b2n
                   "\n")))
        (let [dropped (filter (fn [{:keys [::specs/start-pos
                                           ::specs/length]}]
                                (> 56 (+ start-pos length)))
                              b1)]
          (is (= (map (partial disj b1) dropped)
                 b2))))
      (finally
        ;; Don't do this over start-state, since 1 of its buffers has been released
        (doseq [b (::specs/blocks acked)]
          (.release (::specs/buf b)))))))

(deftest check-flag-acked-block
  (let [start-state (test-helpers/build-ack-flag-message-portion)
        flagged (help/flag-acked-blocks 0 56
                                        (assoc start-state ::help/n 0)
                                        (first (::specs/blocks start-state)))]
    (try
      (is (= (-> start-state
                 (update-in [::specs/blocks 0 ::specs/time] (constantly 0))
                 (assoc ::specs/total-block-transmissions 1
                        ::specs/total-blocks 1))
             (dissoc flagged ::help/n)))
      (let [flagged (help/flag-acked-blocks 0 56
                                            (assoc start-state ::help/n 1)
                                            (second (::specs/blocks start-state)))]
        (is (= (assoc start-state ::help/n 2)
               flagged)))
      (finally
        (doseq [b (::specs/blocks start-state)]
          (.release (::specs/buf b)))))))
