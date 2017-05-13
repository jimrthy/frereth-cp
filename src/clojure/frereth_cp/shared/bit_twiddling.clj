(ns frereth-cp.shared.bit-twiddling
  "Shared functions for fiddling with bits"
  (:require [byte-streams :as b-s]
            [clojure.spec :as s]
            [clojure.tools.logging :as log]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef ->string
        ;; Q: What's legal to send here?
        :args (s/cat :x (s/or :byte-array bytes
                              :byte-buf #(instance? io.netty.buffer.ByteBuf %)))
        :ret string?)
(defn ->string
  [x]
  (with-out-str (b-s/print-bytes x)))

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
  ;; Translated from byte_isequal.c in reference implementation
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

(defn possibly-2s-complement
  "It seems ridiculous to need to do this
Q: Is this valid? It seems overly simplistic.

According to wikipedia, I really need to do
  (let [mask (pow 2 (dec Byte/SIZE))]
    (+ (- (bit-and input mask))
       (bit-and input (bit-not mask))))

Alternatively, it suggests just doing
(-> n bit-not inc)

TODO: Double check the math to verify that I
really *am* doing one or the other.

And, realistically, this is a place where
performance probably matters.

OTOH, I'm only using it for coping with the nonce.
  "
  [n]
  (try
    (byte (if (< n 128)
            n
            ;; Note that we do not want the negative
            ;; equivalent, which is what this would do:
            #_(-> n bit-not inc)
            ;; That could problems when it converted 208
            ;; to -208, which is still out of range.
            (- n 256)))
    (catch IllegalArgumentException ex
      (println "Failed to convert " n)
      (throw ex))))

(defn possibly-2s-uncomplement
  [n]
  (if (<= 0 n)
    n
    (+ n 256)))

(defn uint64-pack!
  "Sets 8 bytes in dst (starting at offset n) to x

Note that this looks/smells very similar to TweetNaclFast's
Box.generateNonce.

But I don't see an obvious way to reverse that, and it's
buried inside a class.

So stick with this translation.
"
  ([^bytes dst ^Long n ^Long x]
   ;; Note that returning a value doesn't make any sense for
   ;; this arity.
   ;; Well, until I can return a sub-array cleanly.
   (doseq [i (range n (+ n Long/BYTES))]
     (let [bits-to-shift (* (- i n) Byte/SIZE)]
       (aset-byte dst i (-> x
                            (unsigned-bit-shift-right bits-to-shift)
                            (bit-and 0xff)
                            possibly-2s-complement)))))
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
  "Unpack an array of 8 bytes into a 64-bit long"
  [src]
  (reduce (fn [acc n]
            (-> acc
                (bit-shift-left Byte/SIZE)
                (bit-or (->> n
                             (aget src)
                             possibly-2s-uncomplement
                             ;; This next line should be redundant
                             (bit-and 0xff)))))
          0
          (range 7 -1 -1)))
