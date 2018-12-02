(ns frereth.cp.message.to-child-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth.cp.message
             [specs :as specs]
             [to-child :as x]])
  (:import io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Helpers

;; This seems generally useful.
;; Maybe it should move to test_utilities?
(defn seq->buf
  [src]
  (Unpooled/copiedBuffer (byte-array src)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest build-gap-buffer
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
  (let [human-name "test-consolidation"
        incoming {::specs/->child-buffer []
                  ::specs/contiguous-stream-count 10
                  ::specs/gap-buffer (x/build-gap-buffer)}
        g-b-key [10 15]
        contents (seq->buf (range 5))
        ;; This needs to be here so the consolidator can drop it
        incoming (assoc-in incoming [::specs/gap-buffer g-b-key] contents)]
    (testing "Baseline"
      ;; The newly-arrived gap-buffer matches what we have in incoming.
      ;; This feels backwards.
      ;; The real problem, from that angle, is that this is testing
      ;; a fn I refactored out of a nested reduce.
      ;; incoming is the accumulator.
      ;; g-b is the next value in the seq being reduced.
      (let [g-b [g-b-key contents]
            consolidated (x/consolidate-message-block human-name incoming g-b)
            {:keys [::specs/->child-buffer
                    ::specs/contiguous-stream-count
                    ::specs/gap-buffer]} consolidated]
        (testing "'gap' added to child buffer"
          (is (= 1 (count ->child-buffer))))
        (testing "Moved contiguous-bytes counter"
          (is (= 15 contiguous-stream-count)))
        (testing "Moved 'gap' out of gap-buffer"
          (let [n (count gap-buffer)]
            (is (= 0 n))))))
    (testing "Previously consolidated"
      (let [g-b [[4 9] contents]
            {:keys [::specs/->child-buffer
                    ::specs/contiguous-stream-count
                    ::specs/gap-buffer]} (x/consolidate-message-block human-name
                                                                      incoming
                                                                      g-b)]
        (testing "Nothing new for child"
          (is (= 0 (count ->child-buffer))))
        (testing "contiguous-byte counter didn't move"
          (is (= 10 contiguous-stream-count)))
        (testing "Dropped obsolete gap"
          (is (= 0 (count gap-buffer))))))))
(comment
  (msg-consolidation)
  )

(deftest gap-consolidation
  ;; This seems to be begging for generative testing
  (let [src (range)
        msg-1 (seq->buf (take 5 src))
        buf (-> (x/build-gap-buffer)
                (assoc [1 5] msg-1)
                (assoc [7 9] (seq->buf (take 3 src)))
                (assoc [11 14] (seq->buf (take 4 src)))
                (assoc [16 20] (seq->buf (take 5 src))))
        state {::specs/incoming {::specs/gap-buffer buf
                                 ::specs/contiguous-stream-count 0
                                 ::specs/->child-buffer []}}]
    (testing "Destructuring"
      ;; Implementation detail, but this is how consolidate-gap-buffer starts
      (let [one (first buf)
            [[start stop] theoretical-buffer] one]
        (is (= 1 start))
        (is (= 5 stop))
        (is (= msg-1 theoretical-buffer))))
    (testing "Do nothing"
      (let [consolidated (x/consolidate-gap-buffer state)]
        (is (= state consolidated))))
    (testing "Fill initial gap"
      (let [state (update-in state
                             [::specs/incoming ::specs/gap-buffer]
                             assoc
                             [0 3] (seq->buf (take 3 src)))
            {{:keys [::specs/->child-buffer
                     ::specs/gap-buffer
                     ::specs/contiguous-stream-count]} ::specs/incoming
             :as consolidated} (x/consolidate-gap-buffer state)]
        (is consolidated)
        ;; The rest of this needs lots of attention.
        (throw (RuntimeException. "Start back here"))
        (testing "big picture"
          (is (= 2 (count ->child-buffer)))
          (is (= 6 contiguous-stream-count))
          (is (= 3 (count gap-buffer))))
        (testing "consolidated"
          (let [buf-2 (second ->child-buffer)]
            ;; This covers the addresses from 1-5.
            ;; :filler accounts for bytes 0-3
            ;; So this skips the first 2 bytes (1 and 2)
            ;; I feel like this may indicate an
            ;; off-by-1 bug: it seems like this should
            ;; really leave me with bytes 4 and 5
            (is (= 3 (.readerIndex buf-2)))
            (is (= 2 (.readableBytes buf-2)))
            (let [dst (byte-array 2)]
              (.readBytes (.slice buf-2) dst)
              ;; reading those bytes shouldn't impact the original
              (is (= 2 (.readableBytes buf-2)))
              (is (= 3 (aget dst 0)))
              (is (= 4 (aget dst 1))))))))
    (testing "Consolidate multiples"
      (let [state (update-in state
                             [::specs/incoming ::specs/gap-buffer]
                             (fn [current]
                               (assoc current
                                      [4 8] (seq->buf (take 5 src))
                                      [8 12] (seq->buf (take 5 src))
                                      [15 15] (seq->buf (take 1 src)))))
            {{:keys [::specs/->child-buffer
                     ::specs/gap-buffer
                     ::specs/contiguous-stream-count]} ::specs/incoming
             :as consolidated} (x/consolidate-gap-buffer state)]
        (testing "All but first"
          ;; Nothing should have happened yet
          (is (= 0 (count ->child-buffer)))
          (is (= 0 contiguous-stream-count))
          (is (= 7 (count gap-buffer))))
        (testing "all"
          (let [state (update-in state
                                 [::specs/incoming ::specs/gap-buffer]
                                 assoc
                                 [0 1] (seq->buf [255 1]))
                {{:keys [::specs/->child-buffer
                         ::specs/gap-buffer
                         ::specs/contiguous-stream-count]} ::specs/incoming
                 :as consolidated} (x/consolidate-gap-buffer state)]
            (is (= 8 (count ->child-buffer)))
            (is (= 21 contiguous-stream-count))
            ;; I should probably verify that the reader-indexes got
            ;; updated correctly.
            ;; But that would make this test ridiculously more
            ;; complicated.
            (is (= 0 (count gap-buffer)))))))))
