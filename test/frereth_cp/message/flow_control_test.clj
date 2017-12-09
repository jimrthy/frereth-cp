(ns frereth-cp.message.flow-control-test
  (:require [clojure.core.reducers :as r]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer (deftest is testing)]))

(deftest performance-check
  ;; Really just verifying that floats are much faster
  ;; than ratios, since they're baked into the CPU
  (let [start-time (System/nanoTime)
        iterations 5000
        float-start-time (atom 0)
        float-finish-time (atom 0)
        ratio-start-time (atom 0)
        ratio-finish-time (atom 0)]
    (testing "Floats"
      (let [ns (r/map (fn [_]
                        (rand-int Integer/MAX_VALUE))
                      (range iterations))
            start (System/nanoTime)
            result (r/fold + ns)
            end (System/nanoTime)]
        ;; Just so the test looks like it's doing something
        (is (< 0 result))
        (reset! float-start-time start)
        (reset! float-finish-time end)))
    (testing "Ratios"
      (let [numerators (r/foldcat (r/map (fn [_]
                                           (rand-int Integer/MAX_VALUE))
                                         (range iterations)))
            denominators (r/foldcat (r/map (fn [_]
                                             (rand-int Integer/MAX_VALUE))
                                           (range iterations)))
            ns (into [] (map (fn [numerator denominator]
                               (/ numerator denominator))
                             numerators denominators))
            start (System/nanoTime)
            result (r/fold + ns)
            end (System/nanoTime)]
        (is (< 0 result))
        (reset! ratio-start-time start)
        (reset! ratio-finish-time end)))
    (testing "Timing"
      ;; The real point
      (let [float-delta (- @float-finish-time @float-start-time)
            ratio-delta (- @ratio-finish-time @ratio-start-time)]
        ;; This isn't exactly proof that floats are much faster,
        ;; but it's very indicative.
        ;; And it obviously *should* be true across the board.
        (is (< (* 250 float-delta) ratio-delta))))))

(comment
  (r/foldcat (r/map (fn [_]
                      (rand-int Integer/MAX_VALUE))
                    (range 10)))
  (let [iterations 10
        numerators (r/foldcat (r/map (fn [_]
                                       (rand-int Integer/MAX_VALUE))
                                     (range iterations)))
        denominators (r/foldcat (r/map (fn [_]
                                         (rand-int Integer/MAX_VALUE))
                                       (range iterations)))]
    (into [] (map (fn [numerator denominator]
                    (/ numerator denominator))
                  numerators denominators)))
  )
