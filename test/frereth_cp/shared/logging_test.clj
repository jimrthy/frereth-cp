(ns frereth-cp.shared.logging-test
  (:require [clojure.spec.test.alpha :as test]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.shared.logging :as log]))

(defn set-up
  [ctx]
  (-> (log/init ctx 0)
      (log/debug ::set-up "Entry 1")
      (log/debug ::set-up "Entry 2")))

(deftest check-fork
  (let [log-1 (set-up ::check-fork)
        [log-1 log-2] (log/fork log-1 ::forked)]

    (is (= (::log/lamport log-1)
           (::log/lamport log-2)))
    (let [forked-entries (::log/entries log-2)]
      (is (= (count forked-entries) 1)))))

(deftest merge-entries
  ;; This is a slow test, so it's probably worth spinning off into
  ;; a folder that's really only meant for pre-commit testing.
  (let [raw (test/check `log/merge-entries)
        result (get-in (first raw) [:clojure.spec.test.check/ret :result])]
    (is result)
    (when (not result)
      (throw (ex-info "" {::failure raw})))))
