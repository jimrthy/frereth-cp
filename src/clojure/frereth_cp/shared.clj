(ns frereth-cp.shared
  "For pieces shared among client, server, and messaging"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.string]
            [clojure.tools.logging :as log]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.marshal :as marshal]
            [frereth-cp.shared.specs :as specs])
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           [io.netty.buffer ByteBuf Unpooled]))

(set! *warn-on-reflection* true)

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

;;; STARTED: Refactor compose (along with their
;;; support functions) into its own marshalling ns.
(defn compose
  "Convert the map in fields into a ByteBuf in dst, according to the rules described in tmplt"
  ^ByteBuf [tmplt fields ^ByteBuf dst]
  (log/warn "Deprecated: use marshal ns instead")
  (marshal/compose! tmplt fields dst))

;;; STARTED: Refactor into the marshall ns
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
  (log/warn "Use the shared.marshal ns directly instead")
  (marshal/decompose tmplt src))

(s/fdef default-packet-manager
        :args (s/cat)
        :ret ::packet-management)
(defn default-packet-manager
  []
  (let [packet (Unpooled/directBuffer 4096)]
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

(defn zero-out!
  [dst start end]
  (log/warn "Deprecated: Moved to shared.constants")
  (K/zero-out! dst start end))
