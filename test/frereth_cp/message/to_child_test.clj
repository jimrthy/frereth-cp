(ns frereth-cp.message.to-child-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.to-child :as x]))

(deftest check-gap-buffer
  (testing "obvious"
    (let [g-b (-> (x/build-gap-buffer)
                  (assoc [0 3] :a)
                  (assoc [1 2] :b)
                  (assoc [3 4] :c))]
      (is (= (keys g-b) [[0 3] [1 2] [3 4]]))))
  (testing "with overlap"
    (let [g-b (-> (x/build-gap-buffer)
                  (assoc [0 3] :a)
                  (assoc [1 4] :b)
                  (assoc [2 5] :c)
                  (assoc [3 6] :d)
                  (assoc [0 3] :e))]
      (is (= (vals g-b) [:e :b :c :d]))))
  (testing "scrambled"
    (let [g-b (-> (x/build-gap-buffer)
                  (assoc [0 3] :a)
                  (assoc [3 6] :d)
                  (assoc [2 5] :c)
                  (assoc [1 4] :b)
                  (assoc [0 3] :e))]
      (is (= (vals g-b) [:e :b :c :d])))))

(deftest gap-buffer-destructuring
  (let [g-b (-> (x/build-gap-buffer)
                (assoc [0 1] :a)
                (assoc [1 2] :b)
                (assoc [3 4] :c))]
    (run! (fn [[[start stop :as k] v]]
            (is (< start stop)))
          g-b)))

(deftest msg-consolidation
  ;; This is really testing internal implementation details.
  ;; So it's actually at least a little bit evil.
  ;; Should really be testing consolidate-gap-buffer instead
  ;; But I needed to start somewhere.
  ;; And, sadly, consolidate-message-block is less
  ;; cumbersome, from this angle.
  (let [incoming {::specs/->child-buffer []
                  ::specs/receive-bytes 10
                  ::specs/gap-buffer (x/build-gap-buffer)}
        g-b-key [10 15]
        contents (range 5)
        ;; This needs to be here so the consolidator can drop it
        incoming (assoc-in incoming [::specs/gap-buffer g-b-key] contents)]
    (testing "Baseline"
      ;; The newly-arrived gap-buffer matches what we have in incoming.
      ;; This feels backwords.
      ;; The real problem, from that angle, is that this is testing
      ;; a fn I refactored out of a nested reduce.
      ;; incoming is the accumulator.
      ;; g-b is the next value in the seq being reduced.
      (let [g-b [g-b-key contents]
            consolidated (x/consolidate-message-block incoming g-b)
            {:keys [::specs/->child-buffer
                    ::specs/receive-bytes
                    ::specs/gap-buffer]} consolidated]
        (testing "'gap' added to child buffer"
          (is (= 1 (count ->child-buffer))))
        (testing "Moved receive-bytes stream pointer"
          (is (= 15 receive-bytes)))
        (testing "Moved 'gap' out of gap-buffer"
          (let [n (count gap-buffer)]
            (is (= 0 n))))))
    (testing "Previously consolidated"
      (let [g-b [[4 9] contents]
            {:keys [::specs/->child-buffer
                    ::specs/receive-bytes
                    ::specs/gap-buffer]} (x/consolidate-message-block incoming g-b)]
        (testing "Nothing new for child"
          (is (= 0 (count ->child-buffer))))
        (testing "receive-bytes didn't move"
          ;; Actually, this *should* have gotten updated to 15.
          ;; This probably points out a bug in the current implementation.
          ;; Or, more likely, the test: having the gap-buffer start
          ;; at receive-bytes should not be a legal start state.
          (is (= 15 receive-bytes)))
        (testing "Gap buffer still really should have consolidated"
          ;; The thing about this test is that it really should have
          ;; a1) Moved this buffer into ->child-buffer
          ;; b1) Updated receive-bytes
          ;; OR:
          ;; a2) Left this buffer in place
          ;; b2) Left receive-bytes alone
          ;; But what it *is* doing is:
          ;; a3) Dropping this staged gap
          ;; b3) Leaving receive-bytes alone
          ;;
          ;; a1/b1 seems like what should happen, for robustness
          ;; a2/b2 seems acceptable, as it indicates an invalid start state
          ;; a3/b3 is just obviously wrong.
          (is (= 1 (count gap-buffer))))))))
(comment
  (msg-consolidation)
  )
