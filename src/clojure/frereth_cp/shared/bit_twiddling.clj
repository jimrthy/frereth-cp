(ns frereth-cp.shared.bit-twiddling
  "Shared functions for fiddling with bits"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            ;; FIXME: Make this go away
            [clojure.tools.logging :as log]
            [frereth-cp.shared.constants :as K])
  (:import clojure.lang.BigInt
           io.netty.buffer.ByteBuf
           io.netty.buffer.UnpooledByteBufAllocator$InstrumentedUnpooledUnsafeHeapByteBuf
           java.math.BigInteger))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Globals

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

;; byte-streams doesn't seem to get inheritance.
;; TODO: Look into https://github.com/funcool/octet.
;; For that matter, look into byte-streams history.
;; I used to be able to call print-bytes on a ByteBuf.
(b-s/def-conversion [UnpooledByteBufAllocator$InstrumentedUnpooledUnsafeHeapByteBuf bytes]
  [^ByteBuf buf _]
  (println "Converting" buf "into a single byte-array")
  (let [dst (byte-array (.readableBytes buf))]
    (.readBytes buf dst)
    dst))

(b-s/def-conversion [UnpooledByteBufAllocator$InstrumentedUnpooledUnsafeHeapByteBuf (b-s/seq-of bytes)]
  [^ByteBuf buf _]
  (println "Converting" buf "into a sequence of byte-arrays")
  (let [single (b-s/convert buf (class (byte-array 0)))]
    [single]))
(comment
  ;; ByteBuf is definitely in here now
  ;; However:
  (.possible-sources @b-s/conversions)
  (.possible-targets @b-s/conversions)
  ;; Can't do this because ByteBuf isn't a wrapper around b-s.graph/Type
  (.possible-conversions @b-s/conversions ByteBuf)
  (#'b-s/normalize-type-descriptor ByteBuf)
  (.possible-conversions @b-s/conversions (#'b-s/normalize-type-descriptor ByteBuf))
  (count (.possible-conversions @b-s/conversions (#'b-s/normalize-type-descriptor ByteBuf)))
  )


(s/fdef ->string
        ;; Q: What's legal to send here?
        :args (s/cat :x (s/or :byte-array bytes
                              :byte-buf #(instance? ByteBuf %)))
        :ret string?)
(defn ->string
  [x]
  (with-out-str (b-s/print-bytes x)))

(defn byte-copy!
  "Copies the bytes from src to dst"
  ;; TODO: Benchmark this approach against
  ;; System/arraycopy (the latter really should
  ;; kill it...except possibly for small arrays, which is
  ;; really what's involved here).
  ;; If we just need to copy a subset of src
  ;; (as opposed to building dst in fits and starts),
  ;; Arrays/copyOfRange seems to be the way to go.
  ;; TODO: It might also be worth benchmarking
  ;; and trying out loop unrolling and other approaches
  ;; based on size.
  ([dst src]
   (let [dst (bytes dst)
         src (bytes src)
         m (min (count src)
                (count dst))]
     (run! (fn [n]
             (aset-byte dst n (aget src n)))
           (range m))))
  ([dst offset n src]
   (let [src (bytes src)]
     (run! (fn [m]
             (aset-byte dst (+ m offset) (aget src m)))
           (range n))))
  ([dst offset n src src-offset]
   (let [src (bytes src)]
     (run! (fn [m]
             (aset-byte dst (+ m offset)
                        (aget src (+ m src-offset))))
           (range n)))))

(s/fdef bytes=
        :args (s/cat :x bytes?
                     :y bytes?)
        :ret boolean?)
(defn bytes=
  [^bytes x  ^bytes y]
  ;; This has to take constant time.
  ;; No short-cutting!
  ;; Translated from byte_isequal.c in reference implementation
  ;; FIXME: Switch to the weavejester/clojure-crypto-equality
  ;; libraray.
  ;; This is the sort of wheel that should not be reinvented.
  ;; Except that weavejester ignored the constant-time aspects.
  ;; Q: Would he be open to switching to something like this?
  ;; Bigger Q: Is this a faithful translation?
  ;; I run across pieces that compare successfully here but
  ;; absolutely should not.
  ;; FIXME: Verify whether that analysis is true.
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

(defn extract-rightmost-byte
  "Since bytes are signed in java"
  [n]
  (byte (- (bit-and n K/max-8-uint) K/max-8-int)))

(defn possibly-2s-complement-8
  "If an unsigned byte is greater than 127, it needs to be negated to fit into a signed byte.

Thanks, java, for having a crippled numeric stack."
  ;; It seems ridiculous to need to do this.
  ;; Actually, Byte/byteValue would handle this for us, but it would
  ;; involve boxing.

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
  "Convert [signed] complemented n into unsigned that fits maximum"
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

(s/fdef secure-mod
         :args (s/cat :numerator integer?
                      :denominator (s/and integer?
                                          pos?))
         :fn (fn [{:keys [:args]
                   ^BigInt ret :ret}]
               (let [d (biginteger (:denominator args))
                     n (:numerator args)]
                 (if (= n 0)
                   (= ret 0)
                   (<= (.abs (biginteger ret)) (.abs d)))))
         :ret integer?)
(defn secure-mod
  "DJB sort-of uses this approach in randommod.

  Do not use.

  It's significantly slower than ordinary mod

  I'm pretty sure its only purpoe in life is
  that C doesn't support really big numbers.

  On lots of platforms, a long long is only 64 bits.

  Since we're looking at 256 bits right off the
  bat, java wins here."
  [numerator denominator]
  (binding [*out* *err*]
    (println "Deprecated: secure-mod"))
  ;; TODO: Verify with a cryptographer, then delete this.
  (let [^BigInteger numerator (if (instance? BigInteger numerator)
                                numerator
                                (biginteger numerator))
        numerator (.toByteArray numerator)]
    (reduce (fn [acc b]
              ;; Lack of unsigned numeric types strikes again
              (let [unsigned (possibly-2s-uncomplement-8 b)]
                (mod (+ (* acc 256)
                        unsigned)
                     denominator)))
            0N
            numerator)))
(comment
  (secure-mod 144 4857))

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

(defn uint-pack!
  [^bytes dst ^Long index src ^Integer size]
  (doseq [i (range index (+ index size))]
     (let [bits-to-shift (* (- i index) Byte/SIZE)]
       (aset-byte dst i (-> src
                            (unsigned-bit-shift-right bits-to-shift)
                            (bit-and K/max-8-uint)
                            ;; Doing this seems wrong.
                            ;; TODO: Verify against some other implementation.
                            possibly-2s-complement-8))))
  dst)

(defn uint16-pack!
  "Sets 2 bytes in dst (starting at offset n) to x"
  [^bytes dst ^Long index ^Short src]
  (uint-pack! dst index src Short/BYTES))

(defn uint16-pack
  [^Short x]
  (let [dst (byte-array 2)]
    (uint16-pack! dst 0 x)))

(defn uint32-pack!
  "Sets 4 bytes in dst (starting at offset n) to x"
  [^bytes dst ^Long index ^Integer src]
  (uint-pack! dst index src Integer/BYTES))

(defn uint64-pack!
  "Sets 8 bytes in dst (starting at offset n) to x

Note that this looks/smells very similar to TweetNaclFast's
Box.generateNonce.

But I don't see an obvious way to reverse that, and it's
buried inside a class.

So stick with this translation.
"
  ([^bytes dst ^Long index ^Long src]
   (uint-pack! dst index src Long/BYTES))
  ([x]
   ;; FIXME: This arity should go away.
   (log/warn "Deprecation: use uint64-pack instead")
   (let [dst (byte-array 8)]
     (uint64-pack! dst 0 x)
     dst)))

(defn uint64-pack
  [x]
  (let [dst (byte-array 8)]
     (uint64-pack! dst 0 x)
     dst))
(comment
  (vec (uint64-pack 180)))

;; TODO: redo these as a macro to avoid the code
;; duplication.
(s/fdef uint16-unpack
        :args (s/or :arity-1 (s/cat :src bytes?)
                    :arity-2 (s/and (s/cat :src bytes?
                                           :offset (comp int? pos?))
                                    #(> (count (:src %)) (inc (:offset %)))))
        :ret (s/and int?
                    #(<= 0 % 65535)))
(defn uint16-unpack
  "Unpack an array of 2 bytes into a 16-bit short"
  ([^bytes src offset]
   (let [uchar-1 (possibly-2s-uncomplement-8 (aget src 1))
         uchar-2 (possibly-2s-uncomplement-8 (aget src 0))]
     (bit-or
      (bit-shift-left uchar-1 Byte/SIZE)
      uchar-2)))
  ([^bytes src]
   (uint16-unpack src 0)))

(s/fdef uint32-unpack
        :args (s/cat :src (and bytes?
                               #(= (count %) 4)))
        ;; TODO: Validate range?
        :ret int?)
(defn uint32-unpack
  "Unpack an array of 32 bytes into a 32-bit long"
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
          (range 3 -1 -1)))

(s/fdef uint64-unpack
        :args (s/cat :src (and bytes?
                               #(= (count %) 8)))
        ;; TODO: Validate range?
        :ret int?)
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

(defn zero-out!
  "Shove zeros into the byte-array at dst, from offset start to offset end"
  [dst start end]
  (let [n (- end start)]
    (when (<= (count K/all-zeros) n)
      (alter-var-root K/all-zeros
                      (fn [_] (K/zero-bytes n)))))
  (byte-copy! dst start end K/all-zeros))
