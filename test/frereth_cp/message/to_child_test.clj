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
  (testing "Baseline"
    (let [incoming {::specs/->child-buffer []
                    ::specs/receive-bytes 0
                    ::specs/gap-buffer (x/build-gap-buffer)}
          g-b-key [0 5]
          contents (range 5)
          ;; This needs to be here so the consolidator can drop it
          incoming (assoc-in incoming [::specs/gap-buffer g-b-key] contents)
          g-b [g-b-key contents]
          consolidated (x/consolidate-message-block incoming g-b)]
      (let [{:keys [::specs/->child-buffer
                    ::specs/receive-bytes
                    ::specs/gap-buffer]} consolidated]
        (testing "'gap' added to child buffer"
          (is (= (count ->child-buffer) 1)))
        (testing "Moved receive-bytes stream pointer"
          (is (= receive-bytes 5)))
        (testing "Moved 'gap' out of gap-buffer"
          (let [n (count gap-buffer)]
            (is (= 0 n))))))))
(comment
  (msg-consolidation)
  )
