(ns frereth-cp.shared
  "For pieces shared among client, server, and messaging"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.string]
            [clojure.tools.logging :as log]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as util])
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           [io.netty.buffer ByteBuf Unpooled]
           java.security.SecureRandom))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants
;;; TODO: Pretty much all of these should move into constants

;; TODO: Uncomment this...most of the pieces in here are fairly
;; performance-sensitive
(comment) (set! *warn-on-reflection* true)

(def hello-header (.getBytes (str K/client-header-prefix "H")))
(def hello-nonce-prefix (.getBytes "CurveCP-client-H"))
(def hello-packet-length 224)

(def cookie-position-in-packet 80)

(def max-unsigned-long -1)
(def millis-in-second 1000)
(def nanos-in-milli (long (Math/pow 10 6)))
(def nanos-in-second (* nanos-in-milli millis-in-second))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs
;;;; TODO: Refactor these into shared.specs

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

;;; TODO: The specs dealing with crypto things (like keys) belong in
;;; shared.specs

;; Q: Worth adding a check to verify that it's a folder that exists on the classpath?
(s/def ::keydir string?)
;; TODO: Refactor the key specs into shared.specs
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

(s/def ::long-pk ::specs/crypto-key)
(s/def ::short-pk ::specs/crypto-key)

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

(s/def ::host string?)
(s/def ::message bytes?)
(s/def ::port (s/and int?
                     pos?
                     #(< % 65536)))
(s/def ::network-packet (s/keys :req-un [::host ::message ::port]))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn composition-reduction
  "Reduction function associated for run!ing from compose.

TODO: Think about a way to do this using specs instead.

Needing to declare these things twice is annoying."
  [tmplt fields ^ByteBuf dst k]
  (let [dscr (k tmplt)
        cnvrtr (::K/type dscr)
        ^bytes v (k fields)]
    ;; An assertion error here is better than killing the JVM
    ;; through a SIGSEGV, which is what this would do
    (assert (or (= ::K/zeroes cnvrtr)
                v) (str "Composing from '"
                   (pr-str v)
                   "' (a "
                   (pr-str (class v))
                   ")\nbased on "
                   k
                   " among\n"
                   (keys fields)
                   "\nto "
                   dst
                   "\nbased on "
                   cnvrtr
                   "\nfor\n"
                   dscr))
    (try
      (case cnvrtr
        ::K/bytes (let [^Long n (::K/length dscr)
                        beg (.readableBytes dst)]
                    (try
                      (log/debug (str "Getting ready to write "
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
                     (log/debug "Getting ready to write " n " zeros to " dst " based on "
                                (util/pretty dscr))
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

(defn save-byte-buf
  [^ByteBuf b]
  (let [ref-cnt (.refCnt b)]
    (throw (RuntimeException. "Start back here"))
    (if (< 0 ref-cnt)
      {::capacity (.capacity b)
       ::backed-by-array? (.hasArray b)
       ::hash-code (.hashCode b)
       ::has-memory-address (.hasMemoryAddress b)
       ::is-direct (.isDirect b)
       ::readableBytes (.readableBytes b)
       ::ref-cnt ref-cnt
       ::writableBytes (.writableBytes b)}
      ::released)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn bytes->string
 [bs]
 (with-out-str (b-s/print-bytes bs)))

;;; TODO: Refactor compose and decompose (along with their
;;; support functions) into their own ns.
(defn compose
  "Convert the map in fields into a ByteBuf in dst, according to the rules described in tmplt"
  ^ByteBuf [tmplt fields ^ByteBuf dst]
  ;; Q: How much do I gain by supplying dst?
  ;; A: It does let callers reuse the buffer, which
  ;; will definitely help with GC pressure.
  ;; Yes, it's premature optimization. And how
  ;; often will this get used?
  ;; Rename this to compose!
  ;; Add a purely functional version of compose that
  ;; creates the ByteBuf, calls compose! and
  ;; returns dst.
  (run!
   (partial composition-reduction tmplt fields dst)
   (keys tmplt))
  dst)

(s/fdef decompose
        ;; TODO: tmplt needs a spec for the values
        :args (s/cat :template map?
                     :src #(instance? ByteBuf %))
        ;; TODO: Really should match each value in tmplt
        ;; with the corresponding value in ret and clarify
        ;; a type that way.
        :fn #(= (-> % :ret keys)
                (-> % :tmplt keys))
        :ret map?)
(defn decompose
  ;; Q: Is ztellman's vertigo applicable here?
  "Read a C-style ByteBuf struct into a map, based on a template"
  [tmplt ^ByteBuf src]
  (reduce
   (fn
     [acc k]
     (let [dscr (k tmplt)
           cnvrtr (::K/type dscr)]
       ;; The correct approach would be to move this (and compose)
       ;; into its own tiny ns that everything else can use.
       ;; helpers seems like a good choice.
       ;; That's more work than I have time for at the moment.
       (assoc acc k (case cnvrtr
                      ;; .readBytes does not produce a derived buffer.
                      ;; The buffer that gets created here will need to be
                      ;; released separately
                      ::K/bytes (let [^Long len (::K/length dscr)]
                                  (.readBytes src len))
                      ::K/int-64 (.readLong src)
                      ::K/int-32 (.readInt src)
                      ::K/int-16 (.readShort src)
                      ::K/uint-64 (b-t/possibly-2s-uncomplement-64 (.readLong src))
                      ::K/uint-32 (b-t/possibly-2s-uncomplement-32 (.readInt src))
                      ::K/uint-16 (b-t/possibly-2s-uncomplement-16 (.readShort src))
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
  (let [^ByteBuf packet (::packet p-m)]
    (.release packet)))

(s/fdef default-work-area
        :args (s/cat)
        :ret ::work-area)
(defn default-work-area
  []
  {::working-nonce (byte-array K/nonce-length)
   ::text (byte-array 2048)})

;;; encode-server name no longer seems to be used anywhere.
;;; TODO: Verify that and then eliminate it
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

(s/fdef format-map-for-logging
        :args (s/cat :src map?)
        :fn #(= (keys (:ret %))
                (-> % :args :src keys))
        :ret map?)
(defn format-map-for-logging
  "Switches to current values of dangerous fields (like mutable classes)"
  [src]
  (reduce (fn [dst k]
            (assoc dst k
                   (let [klass (class k)
                         v (src k)]
                     (cond
                       (map? v) (format-map-for-logging v)
                       (vector? v) (mapv format-map-for-logging v)
                       ;; Q: What about other seqs?
                       ;; Top of the list is a sorted queue
                       ;; A: Don't particularly care about retaining those
                       ;; sorts of detail for a log message
                       (seq? v) (mapv format-map-for-logging v)
                       (instance? ByteBuf v) (save-byte-buf v)
                       :else v))))
          {}
          (keys src)))

(defn zero-bytes
  [n]
  (byte-array n (repeat 0)))

(def ^{:tag 'bytes} all-zeros
  "To avoid creating this over and over.

Q: Refactor this to a function?
(note that that makes life quite a bit more difficult for zero-out!)"
  (zero-bytes 128))

(defn zero-out!
  "Shove zeros into the byte-array at dst, from indexes start to end"
  [dst start end]
  (let [n (- end start)]
    (when (<= (count all-zeros) n)
      (alter-var-root all-zeros
                      (fn [_] (zero-bytes n)))))
  (b-t/byte-copy! dst start end all-zeros))
