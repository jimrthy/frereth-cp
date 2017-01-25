(ns com.frereth.common.curve.shared
  "For pieces shared among client, server, and messaging"
  (:require [clojure.java.io :as io]
            [clojure.spec :as s]
            [clojure.string]
            [gloss.core :as gloss])
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           java.security.SecureRandom))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def box-zero-bytes 16)
(def extension-length 16)
(def key-length 32)
(def nonce-length 24)
(def client-nonce-prefix-length 16)
(def client-nonce-suffix-length 8)
(def server-nonce-prefix-length 8)
(def server-nonce-suffix-length 16)
(def server-cookie-length 96)
(def server-name-length 256)

(def hello-header "QvnQ5XlH")
(def hello-nonce-prefix (.getBytes "CurveCP-client-H"))
(def hello-packet-length 224)
(let [dscr (gloss/ordered-map :prefix (gloss/string :utf-8 :length 8)
                              :srvr-xtn (gloss/finite-block extension-length)
                              :clnt-xtn (gloss/finite-block extension-length)
                              :clnt-short-pk (gloss/finite-block key-length)
                              :zeros (gloss/finite-block 64)
                              :nonce :int64  ;; This is 8 bytes...right?
                              :crypto-box (gloss/finite-block 80))]
  (def hello-packet-dscr (gloss/compile-frame dscr)))

(def cookie-header (.getBytes "RL3aNMXK"))
(def cookie-nonce-prefix (.getBytes "CurveCPK"))
(def cookie-packet-length 200)

(def vouch-nonce-prefix (.getBytes "CurveCPV"))

(def initiate-header (.getBytes "QvnQ5XlI"))
(def initiate-nonce-prefix (.getBytes "CurveCP-client-I"))

(def max-unsigned-long -1)
(def millis-in-second 1000)
(def nanos-in-milli (long (Math/pow 10 9)))
(def nanos-in-second (* nanos-in-milli millis-in-second))

(def max-random-nonce (long (Math/pow 2 48)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::dns-string (s/and string?
                           #(> (count %) 0)
                           #(< (count %) 256)
                           (fn [s]
                             (let [ns (clojure.string/split s #"\.")]
                               (doseq [n ns]
                                 (when (< 63 (count n))
                                   (throw (RuntimeException. (str n " too long"))))))
                             s)))
(s/def ::extension (s/and bytes? #(= (count %) 16)))
;; Q: Worth adding a check to verify that it's a folder that exists on the classpath?
(s/def ::keydir string?)
(s/def ::long-pair #(instance? com.iwebpp.crypto.TweetNaclFast$Box$KeyPair %))
;; This is a name suitable for submitting a DNS query.
;; 1. Its encoder starts with an array of zeros
;; 2. Each name segment is prefixed with the number of bytes
;; 3. No name segment is longer than 63 bytes
(s/def ::server-name (s/and bytes #(= (count %) 256)))
(s/def ::short-pair #(instance? com.iwebpp.crypto.TweetNaclFast$Box$KeyPair %))
(s/def ::client-keys (s/keys :req-un [::long-pair ::short-pair]
                             :opt-un [::keydir]))
(s/def ::server-keys (s/keys :req-un [::long-pair ::name ::short-pair]
                             :opt-un [::keydir]))

(s/def ::my-keys (s/keys :req [::keydir
                               ::long-pair
                               ::server-name
                               ::short-pair]))
;; "Recent" timestamp, in nanoseconds
(s/def ::recent integer?)

;; I think this is a TweetNaclFast$Box
;; TODO: Verify
(s/def ::shared-secret any?)
(s/def ::public-key (s/and bytes? #(= (count %) key-length)))
(s/def ::symmetric-key (s/and bytes? #(= (count %) key-length)))

(s/def ::working-nonce (s/and bytes? #(= (count %) nonce-length)))
(s/def ::text bytes?)
(s/def ::working-area (s/keys :req [::text ::working-nonce]))

(comment
  (s/def ::packet-length (s/and integer?
                                pos?
                                ;; evenly divisible by 16
                                #(= 0 (bit-and % 0xf)))))
(s/def ::packet-nonce integer?)
;; Q: Can I make this any more explicit?
;; This is really arriving as a ByteBuffer. It's tempting to work
;; with that instead, but TweetNacl only handles byte arrays.
;; It's also tempting to shove it into a vector and only use byte
;; arrays/buffers with the low-level java code when I really need it.
;; TODO: Get it working, then see what kind of performance impact
;; that has
(s/def ::packet bytes?)

(s/def ::packet-management (s/keys :req [::packet-nonce
                                         ::packet]))

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

(defn bytes=
  [x y]
  ;; This has to take constant time.
  ;; No short-cutting!
  (let [nx (count x)
        ny (count y)
        diff
        (reduce (fn [acc n]
                  (let [xv (aget x n)
                        yv (aget y n)]
                    (bit-or acc (bit-xor xv yv))))
                0 (range (min nx ny)))]
    (and (not= 0 (unsigned-bit-shift-right (- 256 diff) 8))
         (= nx ny))))

(def cookie-frame (gloss/compile-frame (gloss/ordered-map :header (gloss/string :utf-8 :length 8)
                                                          :client-extension (gloss/finite-block extension-length)
                                                          :server-extension (gloss/finite-block extension-length)
                                                          ;; Implicitly prefixed with "CurveCPK"
                                                          :nonce (gloss/finite-block server-nonce-suffix-length)
                                                          :cookie (gloss/finite-block 144))))

(defn crypto-box-prepare
  [public secret]
  (TweetNaclFast$Box. public secret))

(s/fdef default-packet-management
        :args (s/cat)
        :ret ::packet-management)
(defn default-packet-manager
  []
  {::packet nil
   ;; Note that this is distinct from the working-area's nonce
   ;; And it probably needs to be an atom
   ;; Or maybe even a ref (although STM would be a disaster here...
   ;; actually, trying to cope with this in multiple threads
   ;; seems like a train wreck waiting to happen)
   ::packet-nonce 0})

(s/fdef default-work-area
        :args (s/cat)
        :ret ::working-area)
(defn default-work-area
  []
  {::working-nonce (byte-array nonce-length)
   ::text (byte-array 2048)})

(declare random-key-pair slurp-bytes)
(defn do-load-keypair
  "Honestly, these should be stored with something like base64 encoding.

And encrypted with a passphrase, of course."
  [keydir]
  (if keydir
    (let [secret (slurp-bytes (io/resource (str keydir "/.expertsonly/secretkey")))]
      (TweetNaclFast$Box/keyPair_fromSecretKey secret))
    (random-key-pair)))

(s/fdef encode-server-name
        :args (s/cat :name ::dns-string)
        :ret ::server-name)
(defn encode-server-name
  [name]
  (let [result (byte-array 256 (repeat 0))
        ns (clojure.string/split name #"\.")]
    (let [pos (atom 0)]
      (doseq [n ns]
        (let [length (count n)]
          (when (< 0 length)
            (when (< 63 length)
              (throw (ex-info "Name segment too long" {:encoding name
                                                       :problem n})))
            (aset-byte result @pos (byte length))
            (doseq [c n]
              (swap! pos inc)
              (aset-byte result @pos (byte c)))
            (swap! pos inc)))))
    result))
(comment (let [encoded (encode-server-name "foo..bacon.com")]
           (vec encoded)))

(defn random-bytes!
  "Fills dst with random bytes"
  [#^bytes dst]
  (TweetNaclFast/randombytes dst))

(defn random-array
  "Returns an array of n random bytes"
  [^Long n]
  (TweetNaclFast/randombytes n))

(defn random-key
  "Returns a byte array suitable for use as a random key"
  []
  (random-array key-length))

(s/fdef random-key-pair
        :args (s/cat)
        :ret com.iwebpp.crypto.TweetNaclFast$Box$KeyPair)
(defn random-key-pair
  "Generates a pair of random keys"
  []
  (TweetNaclFast$Box/keyPair))

(defn random-mod
  "Returns a cryptographically secure random number between 0 and n

Or maybe that's (dec n)"
  [n]
  (let [default 0N]
    (if (<= n 1)
      default
      ;; Q: Is this seemingly arbitrary number related to
      ;; key length?
      (let [bs (random-array 32)]
        ;; Q: How does this compare with just calling
        ;; (.nextLong rng) ?
        ;; A (from crypto.stackexchange.com):
        ;; If you start with a (uniform) random number in
        ;; {0, 1, ..., N-1} and take the result module n,
        ;; the result will differ from a uniform distribution
        ;; by statistical distance of less than
        ;; (/ (quot N n) N)
        ;; The actual value needed for that ratio has a lot
        ;; to do with the importance of the data you're trying
        ;; to protect.
        ;; (He recommended 2^-30 for protecting your collection
        ;; of pirated music and 2^-80 for nuclear launch codes.
        ;; Note that this was written several years ago
        ;; So definitely stick with this until an expert tells
        ;; me otherwise
        (reduce (fn [^clojure.lang.BigInt acc ^Byte b]
                  ;; Note that b is signed
                  (mod (+ (* 256 acc) b 128) n))
                default
                bs)))))

(defn random-nonce
  "Generates a number suitable for use as a cryptographically secure random nonce"
  []
  (long (random-mod max-random-nonce)))

(defn safe-nonce
  [dst keydir offset]
  (if keydir
    ;; Read the last saved version from something in keydir
    (throw (RuntimeException. "Get real safe-nonce implementation translated"))
    ;; This is where working with something like a ByteBuf seems like it
    ;; would be much nicer
    (let [n (- (count dst) offset)
          tmp (byte-array n)]
      (.randomBytes tmp)
      (byte-copy! dst offset n tmp))))

(defn slurp-bytes
  "Slurp the bytes from a slurpable thing

Copy/pasted from stackoverflow. Credit: Matt W-D.

alt approach: Add dependency to org.apache.commons.io

Or there's probably something similar in guava"
  [bs]
  (with-open [out (java.io.ByteArrayOutputStream.)]
    (clojure.java.io/copy (clojure.java.io/input-stream bs) out)
    (.toByteArray out)))

(defn spit-bytes
  "Spit bytes to a spittable thing"
  [f bs]
  (with-open [out (clojure.java.io/output-stream f)]
    (with-open [in (clojure.java.io/input-stream bs)]
      (clojure.java.io/copy in out))))

(defn uint64-pack!
  "Sets 8 bytes in dst (starting at offset n) to x

Note that this looks/smells very similar to TweetNaclFast's
Box.generateNonce.

If that's really all this is used for, should definitely use
that implementation instead"
  [^bytes dst n ^Long x]
  ;; This is failing because bit operations aren't supported
  ;; on BigInt.
  ;; Note that I do inherit guava 19.0 from the google closure
  ;; compiler.
  ;; Which is almost an accident from component-dsl including
  ;; clojurescript.
  ;; Guava's unsigned long is slightly slower than using
  ;; primitive longs, with the trade-off of strong typing.
  ;; That seems like a fairly dumb trade-off.
  ;; Especially since the bit twiddling here almost has
  ;; to be for performance/timing reasons.
  ;; Maybe I should just be using primitive longs to start
  ;; with and cope with the way the signed bit works when
  ;; I must.
  (println "Trying to pack" x "a" (class x) "into offset" n "of"
           (count dst) "bytes at" dst)
  (let [x' (bit-and 0xff x)]
    (aset-byte dst n (- x' 128))
    (let [x (unsigned-bit-shift-right x 8)
          x' (bit-and 0xff x)]
      (aset-byte dst (inc n) (- x' 128))
      (let [x (unsigned-bit-shift-right x 8)
            x' (bit-and 0xff x)]
        (aset-byte dst (+ n 2) (- x' 128))
        (let [x (unsigned-bit-shift-right x 8)
              x' (bit-and 0xff x)]
          (aset-byte dst (+ n 3) (- x' 128))
          (let [x (unsigned-bit-shift-right x 8)
                x' (bit-and 0xff x)]
            (aset-byte dst (+ n 4) (- x' 128))
            (let [x (unsigned-bit-shift-right x 8)
                  x' (bit-and 0xff x)]
              (aset-byte dst (+ n 5) (- x' 128))
              (let [x (unsigned-bit-shift-right x 8)
                    x' (bit-and 0xff x)]
                (aset-byte dst (+ n 6) (- x' 128))
                (let [x (unsigned-bit-shift-right x 8)
                      x' (bit-and 0xff x)]
                  (aset-byte dst (+ n 7) (- x' 128)))))))))))

(defn zero-bytes
  [n]
  (byte-array n (repeat 0)))

(def all-zeros
  "To avoid creating this over and over"
  (zero-bytes 128))
