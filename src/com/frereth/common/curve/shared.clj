(ns com.frereth.common.curve.shared
  "For pieces shared among client, server, and messaging.

This is getting big enough that I really need to split it up"
  (:require [clojure.java.io :as io]
            [clojure.spec :as s]
            [clojure.string]
            [clojure.tools.logging :as log]
            [com.frereth.common.curve.shared.bit-twiddling :as bit-twiddling]
            [com.frereth.common.curve.shared.constants :as K]
            ;; Honestly, this has no place here.
            ;; But it's useful for refactoring
            [com.frereth.common.curve.shared.crypto :as crypto])
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           java.security.SecureRandom))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants
;;; TODO: Pretty much all of these should move into constants

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
;; Q: Is it worth trying to build serialization
;; handlers like gloss/buffy from spec?
;; That *was* one of the awesome features
;; offered/promised by schema.
(def hello-packet-dscr (array-map ::prefix {::type ::bytes ::length header-length}
                                  ::srvr-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-short-pk {::type ::bytes ::length K/key-length}
                                  ::zeros {::type ::zeroes ::length 64}
                                  ;; This gets weird/confusing.
                                  ;; It's a 64-bit number, so 8 octets
                                  ;; But, really, that's just integer?
                                  ;; It would probably be more tempting to
                                  ;; just spec this like that if clojure had
                                  ;; a better numeric tower
                                  ::nonce {::type ::bytes
                                           ::length client-nonce-suffix-length}
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
  (array-map ::s' {::type ::bytes ::length K/key-length}
             ::black-box {::type ::zeroes ::length 96}))


(def vouch-nonce-prefix (.getBytes "CurveCPV"))

(def initiate-header (.getBytes (str client-header-prefix "I")))
(def initiate-nonce-prefix (.getBytes "CurveCP-client-I"))

(def max-unsigned-long -1)
(def millis-in-second 1000)
(def nanos-in-milli (long (Math/pow 10 6)))
(def nanos-in-second (* nanos-in-milli millis-in-second))

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
(s/def ::public-key (s/and bytes? #(= (count %) K/key-length)))
(s/def ::secret-key (s/and bytes? #(= (count %) K/key-length)))
(s/def ::symmetric-key (s/and bytes? #(= (count %) K/key-length)))

(s/def ::working-nonce (s/and bytes? #(= (count %) K/nonce-length)))
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

(defn composition-reduction
  "Reduction function associated for run!ing from compose."
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
  {::working-nonce (byte-array K/nonce-length)
   ::text (byte-array 2048)})

(declare slurp-bytes)
(defn do-load-keypair
  "Honestly, these should be stored with something like base64 encoding.

And encrypted with a passphrase, of course.

This really belongs in the crypto ns, but then where does slurp-bytes move?"
  [keydir]
  (if keydir
    (let [secret (slurp-bytes (io/resource (str keydir "/.expertsonly/secretkey")))]
      (TweetNaclFast$Box/keyPair_fromSecretKey secret))
    (crypto/random-key-pair)))

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
      (bit-twiddling/byte-copy! dst offset n tmp))))

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

(defn zero-bytes
  [n]
  (byte-array n (repeat 0)))

(def all-zeros
  "To avoid creating this over and over"
  (zero-bytes 128))
