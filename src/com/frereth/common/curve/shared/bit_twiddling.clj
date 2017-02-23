(ns com.frereth.common.curve.shared.bit-twiddling
  "Shared functions for fiddling with bits"
  (:require [clojure.spec :as s]
            [clojure.tools.logging :as log]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn byte-copy!
  "Copies the bytes from src to dst"
  ([dst src]
   (let [m (count src)]
     (run! (fn [n]
             (aset-byte dst n (aget src n)))
           (range m))))
  ([dst offset n src]
   (run! (fn [m]
           (aset-byte dst (+ m offset) (aget src m)))
         (range n)))
  ([dst offset n src src-offset]
   (run! (fn [m]
           (aset-byte dst (+ m offset)
                      (aget src (+ m src-offset))))
         (range n))))

(s/fdef bytes=
        :args (s/cat :x bytes?
                     :y bytes?)
        :ret boolean?)
(defn bytes=
  [x y]
  ;; This has to take constant time.
  ;; No short-cutting!
  (let [nx (count x)
        ny (count y)
        diff (reduce (fn [acc n]
                       (let [xv (aget x n)
                             yv (aget y n)]
                         (bit-or acc (bit-xor xv yv))))
                     0
                     (range (min nx ny)))]
    (and (not= 0 (unsigned-bit-shift-right (- 256 diff) 8))
         (= nx ny))))

(defn sub-byte-array
  "Return an array that copies a portion of the source"
  ([src beg]
   (-> src
       vec
       (subvec beg)
       byte-array))
  ([src beg end]
   (-> src
       vec
       (subvec beg end)
       byte-array)))

(defn uint64-pack!
  "Sets 8 bytes in dst (starting at offset n) to x

Note that this looks/smells very similar to TweetNaclFast's
Box.generateNonce.

If that's really all this is used for, should definitely use
that implementation instead"
  [^bytes dst n ^Long x]
  (log/info "Trying to pack" x "a" (class x) "into offset" n "of"
             (count dst) "bytes at" dst)
  (let [x' (bit-and 0xff x)]
    (aset-byte dst n x')
    (let [x (unsigned-bit-shift-right x 8)
          x' (bit-and 0xff x)]
      (aset-byte dst (inc n) x')
      (let [x (unsigned-bit-shift-right x 8)
            x' (bit-and 0xff x)]
        (aset-byte dst (+ n 2) x')
        (let [x (unsigned-bit-shift-right x 8)
              x' (bit-and 0xff x)]
          (aset-byte dst (+ n 3) x')
          (let [x (unsigned-bit-shift-right x 8)
                x' (bit-and 0xff x)]
            (aset-byte dst (+ n 4) x')
            (let [x (unsigned-bit-shift-right x 8)
                  x' (bit-and 0xff x)]
              (aset-byte dst (+ n 5) x')
              (let [x (unsigned-bit-shift-right x 8)
                    x' (bit-and 0xff x)]
                (aset-byte dst (+ n 6) x')
                (let [x (unsigned-bit-shift-right x 8)
                      x' (bit-and 0xff x)]
                  (aset-byte dst (+ n 7) x'))))))))))
