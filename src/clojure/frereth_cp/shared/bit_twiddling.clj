(ns frereth-cp.shared.bit-twiddling
  "Shared functions for fiddling with bits"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.shared.constants :as K]))

(set! *warn-on-reflection* true)

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
  ([dst ^bytes src]
   (let [m (min (count src)
                (count dst))]
     (run! (fn [n]
             (aset-byte dst n (aget src n)))
           (range m))))
  ([dst offset n ^bytes src]
   (run! (fn [m]
           (aset-byte dst (+ m offset) (aget src m)))
         (range n)))
  ([dst offset n ^bytes src src-offset]
   (run! (fn [m]
           (aset-byte dst (+ m offset)
                      (aget src (+ m src-offset))))
         (range n))))

(s/fdef bytes=
        :args (s/cat :x bytes?
                     :y bytes?)
        :ret boolean?)
(defn bytes=
  [^bytes x  ^bytes y]
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
    (and (not= 0 (unsigned-bit-shift-right (- (inc K/max-8-uint) diff) 8))
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
  (byte (- (bit-and n K/max-8-uint) K/max-8-int)))

(defn possibly-2s-complement-8
  "If an unsigned byte is greater than 127, it needs to be negated.

Thanks, java, for having a crippled numeric stack."
  ;; It seems ridiculous to need to do this
  ;; Q: Is this approach valid? It seems overly simplistic.
  ;; According to wikipedia, I really need to do
  ;; (let [mask (pow 2 (dec Byte/SIZE))]
  ;;    (+ (- (bit-and input mask))
  ;;       (bit-and input (bit-not mask))))

  ;; Alternatively, it suggests just doing
  ;; (-> n bit-not inc)

  ;; TODO: Double check the math to verify that I
  ;; really *am* doing one or the other.

  ;; And, realistically, this is a place where
  ;; performance probably matters.
  [n]
  {:pre [(nat-int? n)
         (> 256 n)]}
  (try
    (byte (if (< n K/max-8-int)
            n
            ;; This version just does not work.
            #_(-> n bit-not inc)
            (- n (inc K/max-8-uint))))
    (catch IllegalArgumentException ex
      (println "Failed to convert " n)
      (throw ex))))

(defn possibly-2s-uncomplement-n
  "Uncomplement n, for size maximum"
  [n maximum]
  (if (<= 0 n)
    n
    (+ n maximum)))

;; Q: Would it be worth writing a macro to
;; eliminate the duplication that follows?
(comment
  (defmacro def-2s-uncomplementer
    [docstring size]
    (let [max-sym (symbol )])))

(defn possibly-2s-uncomplement-8
  "Note that this is specifically for a single byte"
  [n]
  (let [^:const k (inc K/max-8-uint)]
    (possibly-2s-uncomplement-n n k)))

(defn possibly-2s-uncomplement-16
  "Note that this is specifically for a pair of bytes"
  [n]
  (let [^:const k (inc K/max-16-uint)]
    (possibly-2s-uncomplement-n n k)))

(defn possibly-2s-uncomplement-32
  "Note that this is specifically for a quad-byte"
  [n]
  (let [^:const k (inc K/max-32-uint)]
    (possibly-2s-uncomplement-n n k)))

(defn possibly-2s-uncomplement-64
  "Note that this is specifically for an 8 byte sequence"
  [n]
  (let [^:const k (inc K/max-64-uint)]
    (possibly-2s-uncomplement-n n k)))

(defn uint16-pack!
  "Sets 2 bytes in dst (starting at offset n) to x"
  [^bytes dst ^Long n ^Short x]
  (doseq [i (range n (+ n Short/BYTES))]
     (let [bits-to-shift (* (- i n) Byte/SIZE)]
       (aset-byte dst i (-> x
                            (unsigned-bit-shift-right bits-to-shift)
                            (bit-and K/max-8-uint)
                            possibly-2s-complement-8)))))

(defn uint32-pack!
  "Sets 4 bytes in dst (starting at offset n) to x"
  [^bytes dst ^Long n ^Integer x]
  (doseq [i (range n (+ n Integer/BYTES))]
     (let [bits-to-shift (* (- i n) Byte/SIZE)]
       (aset-byte dst i (-> x
                            (unsigned-bit-shift-right bits-to-shift)
                            (bit-and 0xff)
                            possibly-2s-complement-8)))))

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
                            possibly-2s-complement-8)))))
  ([x]
   (let [dst (byte-array 8)]
     (uint64-pack! dst 0 x)
     dst)))
(comment
  ;; There's a bug with this implementation.
  ;; FIXME: Sort that out.
  (vec (uint64-pack! 180)))

;; TODO: redo this as a macro to avoid the code
;; duplication.
(s/fdef uint16-unpack
        :args (s/cat :src bytes?)
        ;; TODO: Validate range?
        :ret (s/and int?))
(defn uint16-unpack
  "Unpack an array of 2 bytes into a 16-bit short"
  ([^bytes src offset]
   (reduce (fn [acc n]
             (-> acc
                 (bit-shift-left Byte/SIZE)
                 (bit-or (->> n
                              (+ offset)
                              (aget src)
                              possibly-2s-uncomplement-8
                              ;; This next line should be redundant
                              (bit-and 0xff)))))
           0
           (range 2 -1 -1)))
  ([^bytes src]
   (uint16-unpack src 0)))

(s/fdef uint64-unpack
        :args (s/cat :src (and bytes?
                               #(= (count %) 8)))
        ;; TODO: Validate range?
        :ret (s/and int?))
(defn uint64-unpack
  "Unpack an array of 8 bytes into a 64-bit long"
  [^bytes src]
  (reduce (fn [acc n]
            (-> acc
                (bit-shift-left Byte/SIZE)
                (bit-or (->> n
                             (aget src)
                             possibly-2s-uncomplement-8
                             ;; This next line should be redundant
                             (bit-and 0xff)))))
          0
          (range 7 -1 -1)))
