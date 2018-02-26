(ns frereth-cp.shared.crypto
  "Wrap up the low-level crypto functions"
  (:require [byte-streams :as b-s]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as util])
  (:import clojure.lang.ExceptionInfo
           [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           [io.netty.buffer ByteBuf Unpooled]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::long-short #{::long ::short})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef box-after
        :args (s/or :offset-0 (s/cat :shared-key (s/and bytes?
                                                        #(= (count %) K/key-length))
                                     :plain-text bytes?
                                     :length integer?
                                     :nonce (s/and bytes?
                                                   #(= (count %) K/nonce-length)))
                    :offset-n (s/cat :shared-key (s/and bytes?
                                                        #(= (count %) K/key-length))
                                     :plain-text bytes?
                                     :offset integer?
                                     :length integer?
                                     :nonce (s/and bytes?
                                                   #(= (count %) K/nonce-length))))
        :fn (s/and #(>= (-> % :args :plain-text count)
                        (+ (-> % :args :length)
                           (or (-> % :args :offset) 0)))
                   #(= (count (:ret %))
                       (+ (-> % :args :plain-text))))
        :ret bytes?)
(defn box-after
  "Accept some plain text and turn it into cipher text"
  ([shared-key plain-text length nonce]
   ;; TODO: Benchmarking to see how much difference it makes
   ;; to have 2 separate implementations that allow this one to
   ;; avoid an extra 0 addition. (As opposed to just having
   ;; this version call the other with offset 0)
   ;; Since this has to touch every single byte that flows through
   ;; the system, it might be noticeable.
   (comment
     (when (and (<= length (count plain-text))
                nonce
                (= (count nonce) K/nonce-length))
       (let [padded-length (+ length K/box-zero-bytes)
             plain-buffer (byte-array padded-length)
             cipher-text (byte-array padded-length)]
         (log/info (str "Encrypting " length " bytes into " padded-length))
         (b-t/byte-copy! plain-buffer K/box-zero-bytes length plain-text)
         (when (= 0
                  (TweetNaclFast/crypto_box_afternm cipher-text plain-buffer padded-length nonce shared-key))
           (b-t/sub-byte-array cipher-text K/box-zero-bytes)))))
   (box-after shared-key plain-text 0 length nonce))
  ([shared-key plain-text offset length nonce]
   (when (and (<= (+ length offset) (count plain-text))
              nonce
              (= (count nonce) K/nonce-length))
     (let [padded-length (+ length K/decrypt-box-zero-bytes)
           cipher-text (byte-array padded-length)
           plain-buffer (byte-array padded-length)]
       (b-t/byte-copy! plain-buffer K/decrypt-box-zero-bytes length plain-text offset)
       (when (= 0 (TweetNaclFast/crypto_box_afternm cipher-text plain-buffer padded-length nonce shared-key))
         ;; After it's encrypted, we can discard the first 16 bytes.
         ;; But not the other extra 16.
         ;; This is an annoying API pitfall that leads to a lot of
         ;; confusion.
         (b-t/sub-byte-array cipher-text K/box-zero-bytes))))))

(defn box-prepare
  "Set up shared secret so I can avoid the if logic to see whether it's been done.
  At least, I think that's the point."
  [public secret]
  (let [shared (byte-array K/shared-key-length)]
    (TweetNaclFast/crypto_box_beforenm shared public secret)
    shared))

(defn build-crypto-box
  "Compose a map into bytes and encrypt it

Really belongs in crypto.

But it depends on compose, which would set up circular dependencies"
  [tmplt src ^ByteBuf dst key-pair nonce-prefix nonce-suffix]
  {:pre [dst]}
  (let [^ByteBuf buffer (Unpooled/wrappedBuffer dst)]
    (.writerIndex buffer 0)
    (shared/compose tmplt src buffer)
    (let [n (.readableBytes buffer)
          nonce (byte-array K/nonce-length)]
      (b-t/byte-copy! nonce nonce-prefix)
      (b-t/byte-copy! nonce
                      (count nonce-prefix)
                      (count nonce-suffix)
                      nonce-suffix)
      (box-after key-pair dst n nonce))))

(s/fdef random-key-pair
        :args (s/cat)
        :ret com.iwebpp.crypto.TweetNaclFast$Box$KeyPair)
(defn random-key-pair
  "Generates a pair of random keys"
  ^com.iwebpp.crypto.TweetNaclFast$Box$KeyPair []
  (TweetNaclFast$Box/keyPair))

(s/fdef random-keys
        :args (s/cat :which ::long-short)
        :ret (s/or :long ::specs/my-long-keys
                   :short ::specs/my-short-keys))
(defn random-keys
  [which]
  (let [pair (random-key-pair)
        namespace "frereth-cp.shared.specs"
        ;; The keys generated here don't really mesh well with the
        ;; way specs is written.
        ;; That really just uses ::public-long and ::public-short
        ;; FIXME: Track down where this is called and switch to
        ;; that simpler/easier approach
        pk (keyword namespace (str "my-" (name which) "-public"))
        sk (keyword namespace (str "my-" (name which) "-secret"))]
    {pk (.getPublicKey pair)
     sk (.getSecretKey pair)}))
(comment
  (random-keys ::long)
  )

(s/fdef do-load-keypair
        :args (s/cat :key-dir-name string?)
        :ret #(instance? com.iwebpp.crypto.TweetNaclFast$Box$KeyPair %))
(defn do-load-keypair
  "Honestly, these should be stored with something like base64 encoding"
  [keydir]
  (if keydir
    (let [secret (util/slurp-bytes (io/resource (str keydir "/.expertsonly/secretkey")))
          pair (TweetNaclFast$Box/keyPair_fromSecretKey secret)]
      ;; TODO: Switch to functional logging
      (log/info "FIXME: Don't record this\n"
                "Loaded secret key from file:\n"
                (b-t/->string secret)
                "which produced the following key pair:\n"
                "Secret:\n"
                (b-t/->string (.getSecretKey pair))
                "Public:\n"
                (b-t/->string (.getPublicKey pair)))
      pair)
    ;; FIXME: This really should call random-keys instead.
    ;; Q: Shouldn't it?
    ;; A: Well, that depends on context
    (random-key-pair)))

(comment
  ;; Cheap way to save a key to disk in a way that's
  ;; easily loadable by do-load-keypair
  (let [pair (random-key-pair)
        public (.getPublicKey pair)
        secret (.getSecretKey pair)]
    (util/spit-bytes "$HOME/projects/snowcrash/cp/test/client-test/.expertsonly/secretkey"
                     secret)))

(s/fdef open-after
        :args (s/cat :box bytes?
                     :box-offset integer?
                     :box-length integer?
                     :nonce bytes?
                     ;; This is a major reason you might use this:
                     ;; Don't go through the overhead of wrapping
                     ;; a byte array inside a class.
                     ;; Plus, there are fewer function calls to get
                     ;; to the point.
                     :shared-key bytes?)
        :fn (s/and #(>= (-> (% :args :box count))
                        (+ (get-in % [:args :box-offset])
                           (get-in % [:args :box-length])))
                   #(= (-> % :args :nonce count) K/nonce-length)
                   #(= (-> % :ret count)
                       (- (+ (-> % :args :box-offset)
                             (-> % :args :box-length))
                          K/nonce-length)))
        :ret vector?)
(defn open-after
  "Low-level direct crypto box opening

  @parameter box: crypto box byte array to open
  @parameter box-offset: first byte of box to start opening
  @parameter box-length: how many bytes of box to open
  @parameter nonce: Number used Once for this specific box
  @parameter shared-key: combination of their-public and my-private

Note that this does cope with the extra required 16 bytes of prefix padding

The parameter order is screwy to match the java API.

Which was probably modeled to match the C API.

It's annoying and subject to change at a a whim. The only
reason it hasn't yet is that I'm giving this entire translation
the white-glove treatment.

If nothing else, the shared-key should come first to match the
instance-level API and allow me to set it up as a partial.

It would also be nice to be able to provide a reusable buffer byte
array destination that could just be reused without GC.

That looks like it would get into the gory implementation details
which I'm really not qualified to touch."
  [^bytes box box-offset box-length nonce shared-key]
  {:pre [(bytes? shared-key)]}
  (if (and (not (nil? box))
           (>= (count box) (+ box-offset box-length))
           (>= box-length K/box-zero-bytes))
    (do
      (log/debug "Box is large enough")
      (let [n (+ box-length K/box-zero-bytes)
            cipher-text (byte-array n)
            plain-text (byte-array n)]
        (doseq [i (range box-length)]
          (aset-byte cipher-text
                     (+ K/box-zero-bytes i)
                     (aget box (+ i box-offset))))
        ;; Q: Where does shared-key come from?
        ;; A: crypto_box_beforenm
        (let [success
              (TweetNaclFast/crypto_box_open_afternm plain-text cipher-text
                                                     n nonce
                                                     shared-key)]
          (when (not= 0 success)
            (throw (ex-info "Opening box failed" {::box (b-t/->string box)
                                                  ::offset box-offset
                                                  ::length box-length
                                                  ::nonce (b-t/->string nonce)
                                                  ::shared-key (b-t/->string shared-key)})))
          ;; TODO: Compare the speed of doing this with allocating a new
          ;; byte array without the 0-prefix padding and copying it back over
          ;; Keep in mind that we're limited to 1088 bytes per message.
          (comment (-> plain-text
                       vec
                       (subvec K/decrypt-box-zero-bytes)))
          (Unpooled/wrappedBuffer plain-text
                                  K/decrypt-box-zero-bytes
                                  ^Long (- box-length K/box-zero-bytes)))))
    (throw (ex-info "Box too small" {::box box
                                     ::offset box-offset
                                     ::length box-length
                                     ::nonce nonce
                                     ::shared-key shared-key}))))

(s/fdef open-crypto-box
        :args (s/cat :prefix-bytes (s/and bytes?
                                          #(= K/client-nonce-prefix-length
                                              (count %)))
                     :suffix-buffer #(instance? ByteBuf %)
                     :crypto-buffer #(instance? ByteBuf %)
                     :shared-key ::specs/crypto-key)
        :ret (s/nilable #(instance? ByteBuf %)))
(defn open-crypto-box
  "Generally, this is probably the least painful method [so far] to open a crypto box"
  [prefix-bytes ^ByteBuf suffix-buffer ^ByteBuf crypto-buffer shared-key]
  (let [nonce (byte-array K/nonce-length)
        crypto-length (.readableBytes crypto-buffer)
        crypto-text (byte-array crypto-length)]
    (b-t/byte-copy! nonce prefix-bytes)
    (let [prefix-length (count prefix-bytes)]
      (.getBytes suffix-buffer
                 0
                 nonce
                 prefix-length
                 ^Long (- K/nonce-length prefix-length)))
    (.getBytes crypto-buffer 0 crypto-text)
    (try
      (open-after crypto-text 0 crypto-length nonce shared-key)
      (catch ExceptionInfo ex
        (log/error ex
                   (str "Failed to open box\n"
                        (util/pretty (.getData ex))))))))

(defn random-array
  "Returns an array of n random bytes"
  ^bytes [^Long n]
  (TweetNaclFast/randombytes n))

(defn random-bytes!
  "Fills dst with random bytes"
  [#^bytes dst]
  (TweetNaclFast/randombytes dst))

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

(defn random-key
  "Returns a byte array suitable for use as a random key"
  []
  (random-array K/key-length))

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
  (long (random-mod K/max-random-nonce)))

(defn safe-nonce
  "Produce a nonce that's theoretically safe.

Either based upon one previously stashed in keydir or random"
  [dst keydir offset]
  (if keydir
    ;; Read the last saved version from something in keydir
    (throw (RuntimeException. "Get real safe-nonce implementation translated"))
    ;; TODO: Switch to using ByteBuf for this sort of thing
    (let [n (- (count dst) offset)
          tmp (byte-array n)]
      (random-bytes! tmp)
      (b-t/byte-copy! dst offset n tmp))))

(defn secret-box
  "Symmetric encryption

Note that this does not do anything about the initial padding.

It may be an implementation detail, but box-after above is really
just a wrapper around this"
  [dst cleartext length nonce key]
  (TweetNaclFast/crypto_secretbox dst cleartext
                                  length nonce key))

(defn secret-unbox
  "Symmetric-key decryption"
  [dst cipher-text length nonce key]
  (when (not= 0
              (TweetNaclFast/crypto_secretbox_open dst
                                                   cipher-text
                                                   length
                                                   nonce
                                                   key))
    (throw (ex-info "Symmetric unboxing failed"
                    {::destination dst
                     ::cipher-text cipher-text
                     ::length length
                     ::nonce nonce
                     ::key key})))
  dst)
