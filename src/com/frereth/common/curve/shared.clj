(ns com.frereth.common.curve.shared
  "For pieces shared among client, server, and messaging"
  (:require [byte-streams :as b-s]
            [clojure.java.io :as io]
            [clojure.pprint :refer (pprint)]
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
           io.netty.buffer.Unpooled
           java.security.SecureRandom))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants
;;; TODO: Pretty much all of these should move into constants

(def hello-header (.getBytes (str K/client-header-prefix "H")))
(def hello-nonce-prefix (.getBytes "CurveCP-client-H"))
(def hello-packet-length 224)

(def cookie-position-in-packet 80)

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
(s/def ::short-pair #(instance? com.iwebpp.crypto.TweetNaclFast$Box$KeyPair %))
(s/def ::client-keys (s/keys :req-un [::long-pair ::short-pair]
                             :opt-un [::keydir]))
(s/def ::server-keys (s/keys :req-un [::long-pair ::name ::short-pair]
                             :opt-un [::keydir]))

(s/def ::my-keys (s/keys :req [::keydir
                               ::long-pair
                               ::K/server-name
                               ::short-pair]))

(s/def ::crypto-key (s/and bytes?
                        #(= (count %) K/key-length)))
(s/def ::long-pk ::crypto-key)
(s/def ::short-pk ::crypto-key)

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
(s/def ::work-area (s/keys :req [::text ::working-nonce]))

(comment
  ;; Q: Why aren't I using this?
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
(s/def ::url (s/keys :req [::K/server-name
                           ::extension
                           ::port]))

(s/def ::client-nonce (s/and bytes?
                             #(= (count %) K/client-nonce-suffix-length)))
(s/def ::server-nonce (s/and bytes?
                             #(= (count %) K/server-nonce-suffix-length)))

(defn composition-reduction
  "Reduction function associated for run!ing from compose.

TODO: Think about a way to do this using specs instead.

Needing to declare these things twice is annoying."
  [tmplt fields dst k]
  (let [dscr (k tmplt)
        cnvrtr (::K/type dscr)
        v (k fields)]
    (try
      (case cnvrtr
        ::K/bytes (let [n (::K/length dscr)
                        beg (.readableBytes dst)]
                    (try
                      (log/info (str "Getting ready to write "
                                     n
                                     " bytes to\n"
                                     dst
                                     "\nfor field "
                                     k))
                      (.writeBytes dst v 0 n)
                      (let [end (.readableBytes dst)]
                        (assert (= (- end beg) n)))
                      (catch IllegalArgumentException ex
                        (log/error ex (str "Trying to write " n " bytes from\n"
                                           v "\nto\n" dst))
                      (throw (ex-info "Setting bytes failed"
                                        {::field k
                                         ::length n
                                         ::dst dst
                                         ::dst-length (.capacity dst)
                                         ::src v
                                         ::source-class (class v)
                                         ::description dscr
                                         ::error ex})))))
        ::K/int-64 (.writeLong dst v)
        ::K/zeroes (let [n (::K/length dscr)]
                     (log/info "Getting ready to write " n " zeros to " dst " based on "
                               (with-out-str (pprint dscr)))
                     (.writeZero dst n))
        (throw (ex-info "No matching clause" dscr)))
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn bytes->string
 [bs]
 (with-out-str (b-s/print-bytes bs)))

(defn compose
  "Convert the map in fields into a ByteBuf in dst, according to the rules described it tmplt

  This should probably be named compose! and return nil"
  [tmplt fields dst]
  (log/info (str "Putting\n" #_(with-out-str (pprint fields)) fields "\ninto\n" dst
                 "\nbased upon\n" (with-out-str (pprint tmplt))))
  ;; Q: How much do I gain by supplying dst?
  ;; It does let callers reuse the buffer, which
  ;; will definitely help with GC pressure.

  (run!
   (partial composition-reduction tmplt fields dst)
   (keys tmplt))
  dst)

(defn build-crypto-box
  "Compose a map into bytes and encrypt it

Really belongs in crypto.

But it depends on compose, which would set up circular dependencies"
  [tmplt src dst key-pair nonce-prefix nonce-suffix]
  {:pre [dst]}
  (let [buffer (Unpooled/wrappedBuffer dst)]
    (.writerIndex buffer 0)
    (compose tmplt src buffer)
    (let [n (.readableBytes buffer)
          nonce (byte-array K/nonce-length)]
      (bit-twiddling/byte-copy! nonce nonce-prefix)
      (bit-twiddling/byte-copy! nonce
                                (count nonce-prefix)
                                (count nonce-suffix)
                                nonce-suffix)
      (crypto/box-after key-pair dst n nonce))))

(defn decompose
  "Note that this very strongly assumes that I have a ByteBuf here.

And that it's a victim of mid-stream refactoring.

Some of the templates are defined here. Others have moved to constants.

TODO: Clean this up and move it (and compose, and helpers) into their
own ns"
  [tmplt src]
  (reduce
   (fn
     [acc k]
     (let [dscr (k tmplt)
           cnvrtr (or (::type dscr)
                      (::K/type dscr))]
       ;; This can no longer decompose cookie packets.
       ;; That packet description has moved over to constants.
       ;; Honestly, it does belong there.
       ;; Can't just convert this to use keywords namespaced only
       ;; there, which is the obvious approach.
       ;; That would break whatever templates I've written and haven't
       ;; moved.
       ;; Can't realistically just translate that template to use this
       ;; namespace for its keywords, since that would mean circular
       ;; imports.
       ;; The correct approach would be to move this (and compose)
       ;; into its own tiny ns that everything else can use.
       ;; That's also more work than I have time for at the moment.
       (assoc acc k (case cnvrtr
                      ::bytes (.readBytes src (::length dscr))
                      ::K/bytes (.readBytes src (::K/length dscr))
                      ::int-64 (.readLong src)
                      ::K/int-64 (.readLong src)
                      ::zeroes (.readSlice src (::length dscr))
                      ::K/zeroes (.readSlice src (::K/length dscr))
                      (throw (ex-info "Missing case clause"
                                      {::failure cnvrtr
                                       ::acc acc
                                       ::key k
                                       ::template tmplt
                                       ::source src}))))))
   {}
   (keys tmplt)))

(s/fdef default-packet-manager
        :args (s/cat)
        :ret ::packet-management)
(defn default-packet-manager
  []
  (let [packet (io.netty.buffer.Unpooled/directBuffer 4096)]
    ;; TODO: Really need a corresponding .release when we're done
    (.retain packet)
    ;; Highly important:
    ;; Absolutely must verify that using a directBuffer provides
    ;; a definite speed increase over a heap buffer.
    ;; Or, for that matter, just wrapping a Byte Array.
    {::packet packet
     ;; Note that this is distinct from the working-area's nonce
     ;; And it probably needs to be an atom
     ;; Or maybe even a ref (although STM would be a disaster here...
     ;; actually, trying to cope with this in multiple threads
     ;; seems like a train wreck waiting to happen)
     ::packet-nonce 0}))

(s/fdef release-packet-manager!
        :args (s/cat :p-m ::packet-management))
(defn release-packet-manager!
  "Be sure to call this when you're done with something
allocated using default-packet-manager"
  [p-m]
  (-> p-m ::packet .release))

(s/fdef default-work-area
        :args (s/cat)
        :ret ::work-area)
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
        :ret ::K/server-name)
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
    ;; TODO: Switch to using ByteBuf for this sort of thing
    (let [n (- (count dst) offset)
          tmp (byte-array n)]
      (crypto/random-bytes! tmp)
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
  "To avoid creating this over and over.
TODO: Refactor this to a function"
  (zero-bytes 128))
