(ns frereth.cp.message.flow-control-test
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
        (is (pos? result))
        (reset! float-start-time start)
        (reset! float-finish-time end)))
    (testing "Ratios"
      (let [numerators (r/foldcat (r/map (fn [_]
                                           (rand-int Integer/MAX_VALUE))
                                         (range iterations)))
            denominators (r/foldcat (r/map (fn [_]
                                             (rand-int Integer/MAX_VALUE))
                                           (range iterations)))
            ns (vec (map (fn [numerator denominator]
                           (/ numerator denominator))
                         numerators denominators))
            start (System/nanoTime)
            result (r/fold + ns)
            end (System/nanoTime)]
        (is (pos? result))
        (reset! ratio-start-time start)
        (reset! ratio-finish-time end)))
    (testing "Timing"
      ;; The real point
      (let [float-delta (- @float-finish-time @float-start-time)
            ratio-delta (- @ratio-finish-time @ratio-start-time)]
        ;; This isn't exactly proof that floats are much faster,
        ;; but it's very indicative.
        ;; It obviously *should* be true across the board.
        ;; The margin between the two seems to vary widely.
        ;; The first time I ran it, the ratio was something
        ;; like 5000:1.
        ;; For this sort of test to be even vaguely meaningful, I
        ;; need to run enough iterations in conjunction with other
        ;; "real" code to see.
        ;; That really wasn't the point. Reading the ratios in
        ;; the logs was annoying. I don't need that much precision
        ;; for the scheduling where this mattered. Floats
        ;; generally aren't going to be significantly slower.
        ;; So go with them for the convenience (any speed boost
        ;; is gravy).
        (is (< (* 100 float-delta) ratio-delta))))))

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
    (vec (map (fn [numerator denominator]
                (/ numerator denominator))
              numerators denominators)))
  )
