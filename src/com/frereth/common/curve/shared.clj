(ns com.frereth.common.curve.shared
  "For pieces shared among client, server, and messaging"
  (:require [clojure.java.io :as io]
            [clojure.spec :as s]
            [clojure.string]
            [clojure.tools.logging :as log])
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
(def server-name-length 256)

(def header-length 8)
(def client-header-prefix "QvnQ5Xl")
(def hello-header (.getBytes (str client-header-prefix "H")))
(def hello-nonce-prefix (.getBytes "CurveCP-client-H"))
(def hello-packet-length 224)
(def hello-crypto-box-length 80)
;; Q: Is it worth trying to build serialization
;; handlers like gloss/buffy from spec?
;; That *was* one of the awesome features
;; offered/promised by schema.
(def hello-packet-dscr (array-map ::prefix {::type ::bytes ::length 8}
                                  ::srvr-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-short-pk {::type ::bytes ::length key-length}
                                  ::zeros {::type ::zeroes ::length 64}
                                  ;; This gets weird/confusing.
                                  ;; It's a 64-bit number, so 8 octets
                                  ;; But, really, that's just integer?
                                  ;; It would probably be more tempting to
                                  ;; just spec this like that if clojure had
                                  ;; a better numeric tower
                                  ::nonce {::type ::int-64}
                                  ::crypto-box {::type ::bytes
                                                ::length hello-crypto-box-length}))

(def cookie-header (.getBytes "RL3aNMXK"))
(def cookie-nonce-prefix (.getBytes "CurveCPK"))
(def cookie-nonce-minute-prefix (.getBytes "minute-k"))
(def cookie-position-in-packet 80)
(def server-cookie-length 96)
(def cookie-packet-length 200)
(def cookie-frame
  "The boiler plate around a cookie"
  ;; Header is only a "string" in the ASCII sense
  (array-map ::header {::type ::bytes
                       ::length header-length}
             ::client-extension {::type ::bytes
                                 ::length extension-length}
             ::server-extension {::type ::bytes
                                 ::length extension-length}
             ;; Implicitly prefixed with "CurveCPK"
             ::nonce {::type ::bytes
                      ::length server-nonce-suffix-length}
             ::cookie {::type ::bytes
                       ::length 144}))

(def cookie
  (array-map ::s' {::type ::bytes ::length key-length}
             ::black-box {::type ::zeroes ::length 96}))


(def vouch-nonce-prefix (.getBytes "CurveCPV"))

(def initiate-header (.getBytes (str client-header-prefix "I")))
(def initiate-nonce-prefix (.getBytes "CurveCP-client-I"))

(def max-unsigned-long -1)
(def millis-in-second 1000)
(def nanos-in-milli (long (Math/pow 10 6)))
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
(s/def ::secret-key (s/and bytes? #(= (count %) key-length)))
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

;;; Want some sort of URI-foundation scheme for
;;; building the actual connection strings like I
;;; use in cljeromq. This seems like a reasonable
;;; starting point.
;;; Q: Is port really part of it?
(s/def ::url (s/keys :req [::server-name
                           ::extension
                           ::port]))

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

(defn crypto-box-prepare
  ""
  [public secret]
  ;; Q: Do I want to do this?
  ;; Or just use .before?
  ;; Or maybe the key is that I should create
  ;; it and call .before immediately so it's
  ;; ready to use.
  ;; TODO: Need to dig into this particular detail.
  ;; It seems like it's probably really important.
  (TweetNaclFast$Box. public secret))

(defn composition-reduction
  [tmplt fields dst k]
  (let [dscr (k tmplt)
        cnvrtr (::type dscr)
        v (k fields)]
    (try
      (case cnvrtr
        ::bytes (let [n (::length dscr)]
                  (try
                    (.writeBytes dst v 0 n)
                    (catch IllegalArgumentException ex
                      (throw (ex-info "Setting bytes failed"
                                      {::field k
                                       ::length n
                                       ::dst dst
                                       ::dst-length (.capacity dst)
                                       ::src v
                                       ::source-class (class v)
                                       ::description dscr
                                       ::error ex})))))
        ::int-64 (.writeLong dst v)
        ::zeroes (let [n (::length dscr)]
                   (.writeZero dst n)))
      (catch IllegalArgumentException ex
        (throw (ex-info "Missing clause"
                        {::problem ex
                         ::cause cnvrtr
                         ::field k
                         ::description dscr
                         ::source-value v})))
      (catch NullPointerException ex
        (throw (ex-info "NULL"
                        {::problem ex
                         ::cause cnvrtr
                         ::field k
                         ::description dscr
                         ::source-value v}))))))

(defn compose
  [tmplt fields dst]
  (run!
   (partial composition-reduction tmplt fields dst)
   (keys tmplt))
  dst)

(defn decompose
  "Note that this very strongly assumes that I have a ByteBuf here."
  [tmplt src]
  (reduce
   (fn
     [acc k]
     (let [dscr (k tmplt)
           cnvrtr (::type dscr)]
       (assoc acc k (case cnvrtr
                      ;; .readSlice doesn't really seem all that useful here.
                      ;; Then again, there isn't any point to extracting
                      ;; anything I don't really need.
                      ;; By that same token...if I don't really need it, then
                      ;; why did I consume the bandwidth to get it here?
                      ;; (Part of that answer is DoS prevention, for some
                      ;; fields)
                      ;; Need to contemplate this some more
                      ::bytes (.readSlice src (::length dscr))
                      ::int-64 (.readLong src)
                      ::zeroes (.readSlice src (::length dscr))))))
   {}
   (keys tmplt)))

(s/fdef default-packet-management
        :args (s/cat)
        :ret ::packet-management)
(defn default-packet-manager
  []
  ;; Highly important:
  ;; Absolutely must verify that using a directBuffer provides
  ;; a definite speed increase over a heap buffer.
  ;; Or, for that matter, just wrapping a Byte Array.
  {::packet (io.netty.buffer.Unpooled/directBuffer 4096)
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

(defn random-array
  "Returns an array of n random bytes"
  [^Long n]
  (TweetNaclFast/randombytes n))

(defn randomize-buffer!
  "Fills the bytes of dst with crypto-random ints"
  [^io.netty.buffer.ByteBuf dst]
  ;; Move the readable bytes to the beginning of the
  ;; buffer to consolidate the already-read and writeable
  ;; areas.
  ;; Note that this isn't what I actually want to do.
  ;; (if this was called, it's time to wipe the entire
  ;; buffer. Readers missed their chance)
  (.clear dst)
  (.setBytes dst 0 (random-array (.capacity dst))))

(defn random-bytes!
  "Fills dst with random bytes"
  [#^bytes dst]
  (TweetNaclFast/randombytes dst))

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

(defn secret-box
  "Symmetric encryption"
  [dst cleartext length nonce key]
  (TweetNaclFast/crypto_secretbox dst cleartext
                                  length nonce key))

(defn secret-unbox
  "Symmetric-key decryption"
  [dst ciphertext length nonce key]
  (TweetNaclFast/crypto_secretbox_open dst
                                       ciphertext
                                       length
                                       nonce
                                       key))

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
  (log/debug "Trying to pack" x "a" (class x) "into offset" n "of"
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
