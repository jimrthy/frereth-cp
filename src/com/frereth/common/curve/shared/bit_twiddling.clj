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

(defn extract-rightmost-byte
  "Since bytes are signed in java"
  [n]
  (byte (- (bit-and n 0xff) 128)))

(defn uint64-pack!
  "Sets 8 bytes in dst (starting at offset n) to x

Note that this looks/smells very similar to TweetNaclFast's
Box.generateNonce. It's tempting to try to reuse that
implementation.

But I don't see an obvious way to reverse it, which is where I'm running
into trouble with the unpack counterpart."
  ([^bytes dst ^Long n ^Long x]
   ;; Note that returning a value doesn't make any sense for
   ;; this arity.
   ;; Well, until I can return a sub-array cleanly.
   (log/info "Trying to pack" x "a" (class x) "into offset" n "of"
             (count dst) "bytes at" dst)
   ;; Go ahead and clear the first byte manually, in case it includes
   ;; an initial signed bit
   ;; Actually, this approach can't possibly work.
   ;; Well, it's workable as long as the other side has
   ;; the same offset adjustment hack.
   ;; But it's totally incompatible with the original
   (aset dst n (-> x
                   (bit-and 0xff)
                   (- 128)
                   byte))
   (let [n (unsigned-bit-shift-right n Byte/SIZE)]
     (doseq [i (range (inc n) (+ n Long/BYTES))]
       (let [bits-to-shift (* (- i n) Byte/SIZE)]
         (aset-byte dst i (-> x
                              (unsigned-bit-shift-right bits-to-shift)
                              (bit-and 0xff)
                              (- 128)
                              byte))))))
  ([x]
   (let [dst (byte-array 8)]
     (uint64-pack! dst 0 x)
     dst)))

(s/fdef uint64-unpack
        :args (s/cat :src (and bytes?
                               #(= (count %) 8)))
        ;; TODO: Validate range?
        :ret (s/and int?))
(defn uint64-unpack
  [src]
  (log/warn "This will not work!!")
  (throw (RuntimeException. "Remember to adjust by adding 128 each time!"))
  (let [result (+ (long (aget src 7)) 128)  ; Nope.
        result (bit-or (bit-shift-left result 8) (bit-and (aget src 6) 0xff))
        result (bit-or (bit-shift-left result 8) (bit-and (aget src 5) 0xff))
        result (bit-or (bit-shift-left result 8) (bit-and (aget src 4) 0xff))
        result (bit-or (bit-shift-left result 8) (bit-and (aget src 3) 0xff))
        result (bit-or (bit-shift-left result 8) (bit-and (aget src 2) 0xff))
        result (bit-or (bit-shift-left result 8) (bit-and (aget src 1) 0xff))]
    (bit-or (bit-shift-left result 8) (bit-and (aget src 0) 0xff))))

(comment
  ;; This is producing -128.
  ;; WAT?
  (let [packed (uint64-pack! -84455550510807040)]
    (println (vec packed))
    (uint64-unpack packed))

  ;; Specific problem example:
  (bit-or (bit-shift-left -128 8) -56)
  ;; i.e.
  (bit-or (long -32768) (long -56))
  ;; I think I'm going to have to break down and look at the actual bits to try to make sense of this
  )
