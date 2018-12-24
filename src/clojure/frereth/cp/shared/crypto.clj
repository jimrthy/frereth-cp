(ns frereth.cp.shared.crypto
  "Wrap up the low-level crypto functions"
  (:require [byte-streams :as b-s]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [frereth.cp.shared :as shared]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [serialization :as serial]
             [specs :as specs]
             [templates :as templates]
             [util :as util]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [frereth.cp.shared.templates :as templates])
  (:import clojure.lang.ExceptionInfo
           [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           [io.netty.buffer ByteBuf Unpooled]
           [java.io File IOException RandomAccessFile]
           java.nio.channels.FileChannel
           java.security.SecureRandom
           java.security.spec.AlgorithmParameterSpec
           java.util.Arrays
           [javax.crypto Cipher KeyGenerator SecretKey]
           [javax.crypto.spec IvParameterSpec SecretKeySpec]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic constants

(set! *warn-on-reflection* true)

;;; 192 bits
;;; It seems a little silly to encrypt a 128-bit
;;; block with a 256-bit key, but 128-bit keys don't
;;; have a lot of room for undiscovered vulnerabilities
;; Note that this name is legit: it's a key used to encrypt the next
;; nonce.
(def nonce-key-length 24)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;; 16 bytes is 128 bits.
;; Which is a single block for AES.
;; This seems very sketchy, at best.
;; TODO: Think long and hard about making it
;; go away.
(s/def ::data (s/and bytes?
                     #(= (count %) 16)))
(s/def ::java-key-pair (specs/class-predicate com.iwebpp.crypto.TweetNaclFast$Box$KeyPair))
(s/def ::legal-key-algorithms #{"AES"})
(s/def ::long-short #{::long ::short})
(s/def ::unboxed (s/nilable bytes?))

(s/def ::counter-low nat-int?)
(s/def ::counter-high nat-int?)
(s/def ::key-loaded? boolean?)
(s/def ::nonce-key (s/and bytes?
                          #(= (count %) nonce-key-length)))
(s/def ::nonce-state (s/keys :req [::counter-low
                                   ::counter-high
                                   ::data
                                   ::key-loaded?
                                   ::nonce-key
                                   ::weald/state]))

(s/def ::safe-client-nonce ::specs/client-nonce-prefix)
(s/def ::safe-server-nonce ::specs/server-nonce-suffix)
(s/def ::safe-nonce (s/or ::safe-client-nonce ::safe-server-nonce))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef build-random-iv
        :args (s/cat :n nat-int?)
        :ret #(instance? IvParameterSpec %))
(declare random-array)
(defn build-random-iv
  [n]
  (let [iv-bytes (random-array n)]
    (IvParameterSpec. iv-bytes)))

(s/fdef generate-symmetric-key
        :args (s/or :aes-default (s/cat :bit-size ::aes-key-bit-size)
                    :general (s/cat :argorithm ::legal-key-algorithms
                                    :bit-size ::aes-key-bit-size))
        :ret #(instance? SecretKeySpec %))
(defn generate-symmetric-key
  (^SecretKeySpec [algorithm
                   ^Long bit-size]
   (let [generator (KeyGenerator/getInstance algorithm)]
     (.init generator bit-size)
     (.generateKey generator)))
  (^SecretKeySpec [bit-size]
   (generate-symmetric-key "AES" bit-size)))
(comment
  (let [k (generate-symmetric-key "AES" (* Byte/SIZE nonce-key-length))]
    (count (.getEncoded k))
    (class k)))

(s/fdef initial-nonce-agent-state
        :args nil
        :ret ::nonce-state)
(defn initial-nonce-agent-state
  []
  {::weald/state (log/init ::nonce-agent)
   ::counter-low 0
   ::counter-high 0
   ::data (byte-array 16)
   ::encrypted-nonce nil
   ::key-loaded? (promise)
   ::nonce-key (byte-array K/key-length)})

(s/fdef load-nonce-key
  :args (s/cat :this ::nonce-state
               :logger ::weald/logger
               :key-dir string?)
  :ret ::nonce-state)
(defn load-nonce-key
  [{:keys [::key-loaded?]
    log-state ::weald/state
    :as this}
   logger
   key-dir]
  (let [log-state-atom (atom (log/debug log-state
                                         ::load-nonce-key
                                         ""
                                         {::key-dir key-dir}))]
    (try
      (if-let [file-resource (io/resource (str key-dir
                                               "/.expertsonly/noncekey"))]
        (with-open [key-file (io/input-stream file-resource)]
          (let [raw-nonce-key (byte-array nonce-key-length)
                bytes-read (.read key-file raw-nonce-key)]
            (when (not= bytes-read nonce-key-length)
              (log/flush-logs! logger @log-state-atom)
              (throw (ex-info "Key too short"
                              {::expected K/key-length
                               ::actual bytes-read
                               ::path file-resource
                               ::raw (vec bytes-read)
                               ::read (String. (bytes bytes-read))})))
            (let [nonce-key (SecretKeySpec. raw-nonce-key "AES")]
              (deliver key-loaded? true)
              (assoc this
                     ::nonce-key nonce-key
                     ::weald/state (log/flush-logs! logger log-state)))))
        (do
          (log/flush-logs! logger @log-state-atom)
          (throw (ex-info "Missing noncekey file"
                          {::searching-in key-dir
                           ::log/state log-state})))))))

(comment
  ;; Set up a random nonce for testing
  (let [nonce-key (get-random-bytes nonce-key-length)]
    (with-open [f (io/output-stream "/mnt/share/home/james/projects/programming/snowcrash/cp/test/curve-test/.expertsonly/noncekey")]
      (.write f nonce-key))))

(declare encrypt-block)
(defn obscure-nonce
  "More side effects. Encrypt and increment the nonce counter"
  [{:keys [::counter-low
           ::data
           ::nonce-key]
    :as this}
   random-portion]
  (when-not nonce-key
    (println "Missing key to obscure  nonce\n"
             (keys this)
             "\nin\n"
             this)
    (throw (ex-info "Missing nonce-key" this)))
  (when-not data
    (println "No nonce to obscure among\n"
             (keys this)
             "\nin\n"
             this)
    (throw (ex-info "Missing data" this)))
  (b-t/byte-copy! data random-portion)
  (let [;; Note that this is never(?) decrypted.
        ;; Q: Is there any reason for using this instead
        ;; of something like a SHA-256?
        ;; Obvious A: An attacker that recognizes a single
        ;; nonce hash should be able to predict the next
        ;; ones pretty easily.
        ;; Which doesn't really matter for the attacker's
        ;; data stream, but might provide useful hints
        ;; about other users and the rest of the system.
        ;; This seems like a good reason to implement seperate
        ;; nonce handlers for each connection.
        encrypted-nonce (encrypt-block nonce-key data)]
    ;; This means that I need a destination for storing that
    ;; crypto block
    (-> this
        (update ::counter-low inc)
        (assoc ::encrypted-nonce encrypted-nonce))))

(s/fdef reload-nonce
  :args (s/cat :this ::nonce-state
               :log-state ::weald/log-state
               ;; using a string for this seems dubious, at best
               :key-dir string?
               :long-term? boolean?)
  :ret ::nonce-state)
(defn reload-nonce
  "Do this inside an agent for thread safety"
  [{:keys [::counter-low
           ::counter-high]
    log-state ::weald/state
    data ::data
    :as this}
   logger
   key-dir
   long-term?]
  (let [log-state (log/debug log-state
                             ::reload-nonce
                             "Top")
        raw-path (str key-dir "/.expertsonly/")
        path (io/resource raw-path)]
    (let [f (io/file path "lock")]
      (try
        (.createNewFile f)
        (try
          (let [channel (.getChannel (RandomAccessFile. f "rw"))]
            (try
              (let [lock (.lock channel 0 Long/MAX_VALUE false)
                    log-state (log/info log-state
                                        ::reload-nonce
                                        "Lock acquired")]
                (try
                  (let [nonce-counter (io/file path "noncecounter")]
                    (when-not (.exists nonce-counter)
                      (.createNewFile nonce-counter)
                      (with-open [counter (io/output-stream nonce-counter)]
                        ;; FIXME: What's a good initial value?
                        (.write counter (byte-array 8))))
                    (let [log-state (log/debug log-state
                                               ::reload-nonce
                                               "Opening"
                                               {::nonce-file-name nonce-counter})]
                      (with-open [counter (io/input-stream nonce-counter)]
                        (let [log-state (log/debug log-state
                                                   ::reload-nonce
                                                   "Nonce counter file opened for reading")
                              data (bytes data)
                              bytes-read (.read counter data 0 8)
                              log-state (log/debug log-state
                                                   ::reload-nonce
                                                   "Read bytes"
                                                   {::byte-count bytes-read})]
                          (when (not= bytes-read 8)
                            (log/flush-logs! logger log-state)
                            (throw (ex-info "Nonce counter file too small"
                                            {::contents (b-t/->string data)
                                             ::length bytes-read})))
                          (let [counter-low (b-t/uint64-unpack data)
                                counter-high (+ counter-low (if long-term?
                                                              K/m-1
                                                              1))]
                            (b-t/uint64-pack! data 0 counter-high))
                          (with-open [counter (io/writer nonce-counter)]
                            (.write counter (String. data))
                            (assoc this
                                   ::counter-low counter-low
                                   ::counter-high counter-high
                                   ::weald/state (log/flush-logs! logger log-state)))))))
                  (finally
                    ;; Closing the channel should release the lock,
                    ;; but being explicit about this doesn't hurt
                    (.release lock))))
              (finally
                (.close channel))))
          (catch IOException ex
            (throw (ex-info "Failed to acquire exclusive access to lock file"
                            {::io-path f
                             ::raw-path raw-path
                             ::resource path}
                            ex))))
        (catch IOException ex
          (throw (ex-info "Failed to create a new lock file "
                          {::io-path f
                           ::raw-path raw-path
                           ::resource path}
                          ex)))))))

(declare get-random-bytes)
(s/fdef do-safe-nonce
        :args (s/or :persistent (s/cat :log-state ::weald/state
                                       :dst ::safe-nonce
                                       :key-dir (s/nilable string?)
                                       :offset (complement neg-int?)
                                       :long-term? boolean?)
                    :transient (s/cat :log-state ::weald/state
                                      :dst ::safe-nonce
                                      :offset (complement neg-int?)))
        :ret ::weald/state)
(let [nonce-writer (agent (initial-nonce-agent-state))
      random-portion (byte-array 8)]
  (defn get-nonce-agent-state
    []
    @nonce-writer)
  (comment (get-nonce-agent-state))
  (defn reset-safe-nonce-state!
    []
    (restart-agent nonce-writer (initial-nonce-agent-state)))
  (defn do-safe-nonce
    "Shoves a theoretically safe 16-byte nonce suffix into dst at offset"
    ([logger log-state dst key-dir offset long-term?]
     ;; It's tempting to try to set this up to allow multiple
     ;; nonce trackers. It seems like having a single shared
     ;; one risks leaking information to attackers.
     ;; This current implementation absolutely cannot
     ;; handle that sort of thing. (To be fair, neither can the
     ;; reference implementation).
     ;; Right now, we have one agent with a single nonce key
     ;; (along with counters).
     ;; Maybe it doesn't matter.

     ;; Q: Does this arity make any sense at all?
     ;; As things stand, it doesn't seem like anything uses it outside
     ;; unit tests.

     ;; Then again, I didn't write it for the fun of it.

     (when-let [ex (agent-error nonce-writer)]
       (throw ex))

     ;; Read the last saved version from keydir
     (let [log-state
           (if-not (-> nonce-writer deref ::key-loaded? realized?)
             (let [log-state (log/debug log-state
                                        ::do-safe-nonce
                                        "Triggering nonce-key initial load")]
               (send nonce-writer load-nonce-key logger key-dir)
               log-state)
             log-state)]
       (let [{:keys [::counter-low
                     ::counter-high]} @nonce-writer]
         (when (>= counter-low counter-high)
           (send nonce-writer reload-nonce log-state key-dir long-term?)))
       (send nonce-writer obscure-nonce random-portion)
         ;; Tempting to do an await here, but we're inside an
         ;; agent action, so that isn't legal.
         ;; Q: Is that still true?
         ;; Bigger Q: does an agent really make sense for the
         ;; nonce-writer?

       (if-let [ex (agent-error nonce-writer)]
         (log/exception log-state
                        ex
                        ::do-safe-nonce
                        "System is down")
         log-state)))
    ([log-state dst offset]
     (let [length-to-fill (- (count dst) offset)
           tmp (get-random-bytes length-to-fill)]
       (b-t/byte-copy! dst offset length-to-fill tmp)
       (log/debug log-state
                  ::safe-nonce!
                  "Picked a random nonce")))))
(comment
  (get-nonce-agent-state)
  (reset-safe-nonce-state!))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

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
                       (+ (-> % :args :plain-text) specs/box-zero-bytes)))
        :ret ::specs/byte-array)
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
         (when (zero?
                (TweetNaclFast/crypto_box_afternm cipher-text plain-buffer padded-length nonce shared-key))
           (b-t/sub-byte-array cipher-text K/box-zero-bytes)))))
   (box-after shared-key plain-text 0 length nonce))
  ([shared-key plain-text offset length nonce]
   (if (and (<= (+ length offset) (count plain-text))
            nonce
            (= (count nonce) K/nonce-length))
     (let [padded-length (+ length K/decrypt-box-zero-bytes)
           cipher-text (byte-array padded-length)
           plain-buffer (byte-array padded-length)]
       (b-t/byte-copy! plain-buffer K/decrypt-box-zero-bytes length plain-text offset)
       (let [success (TweetNaclFast/crypto_box_afternm cipher-text plain-buffer padded-length nonce shared-key)]
         (if (zero? success)
           ;; After it's encrypted, we can discard the first 16 bytes.
           ;; But not the other extra 16.
           ;; This is an annoying API pitfall that has lead to a lot of
           ;; confusion for me.
           (b-t/sub-byte-array cipher-text K/box-zero-bytes)
           (throw (ex-info "Boxing failed"
                           {::failure-code success
                            ::cipher-text (vec cipher-text)
                            ::cipher-text-length (count cipher-text)
                            ::clear-text (vec plain-buffer)
                            ::clear-text-length (count plain-buffer)
                            ::bytes-to-encrypt padded-length
                            ::nonce (vec nonce)
                            ::shared-key (vec shared-key)})))))
     (throw (ex-info "Bad pre-conditions for boxing"
                     {::length length
                      ::offset offset
                      ::clear-text-length (count plain-text)
                      ::nonce (vec nonce)})))))

(s/fdef box-prepare
        :args (s/cat :public ::specs/crypto-key
                     :secret ::specs/crypto-key)
        :ret ::specs/crypto-key)
(defn box-prepare
  "Set up shared secret so I can avoid the if logic to see whether it's been done.
  At least, I think that's the point."
  [^bytes public ^bytes secret]
  (let [shared (byte-array K/shared-key-length)]
    (TweetNaclFast/crypto_box_beforenm shared public secret)
    shared))

(s/fdef build-box
  :args (s/cat :log-state ::weald/state
               :template ::templates/pattern
               :source (s/coll-of keyword?)
               :shared-key ::specs/crypto-key
               :nonce-prefix (s/or :server ::specs/server-nonce-prefix
                                   :client ::specs/client-nonce-prefix)
               :nonce-suffix (s/or :server ::specs/server-nonce-suffix
                                   :client ::specs/client-nonce-suffix))
        ;; The length of :ret can be determined by :template.
        ;; But that gets into troublesome details about serialization
  :ret (s/keys :req [::specs/byte-array
                     ::weald/state]))
(defn build-box
  "Compose a map into bytes and encrypt it

  Note that tmplt should *not* include the requisite 32 bytes of 0 padding"
  [log-state tmplt src shared-key nonce-prefix nonce-suffix]
  (let [{clear-text ::specs/byte-array
         log-state ::weald/state} (serial/compose log-state tmplt src)
        nonce (byte-array K/nonce-length)
        nonce-suffix-length (count nonce-suffix)
        nonce-prefix-length (count nonce-prefix)]
    (b-t/byte-copy! nonce nonce-prefix)
    (let [log-state (log/debug log-state
                               ::build-box
                               "Copying"
                               {::source-byte-count nonce-suffix-length
                                ::destination-length K/nonce-length
                                ::offset nonce-prefix-length})]
      (b-t/byte-copy! nonce
                      nonce-prefix-length
                      nonce-suffix-length
                      nonce-suffix)
      {::specs/byte-array (box-after shared-key
                                     clear-text
                                     (count clear-text)
                                     nonce)
       ::weald/state log-state})))

(defn encrypt-block
  "Block-encrypt a byte-array"
  ;; Reference implementation includes these TODO items
  ;; XXX: Switch to crypto_block_aes256
  ;; XXX: Build crypto_stream_aes256 on top of crypto_block_aes256
  ;; I'm going to break with the reference implementation on
  ;; this choice. Rather than translating what it's doing, I'm
  ;; just going to use the built-in AES encryption
  [^SecretKey secret-key
   clear-text]
  (when-not secret-key
    (throw (RuntimeException. "FIXME: What's wrong with the secret-key ?")))
  ;; Q: Which cipher mode is appropriate here?
  (let [clear-text (bytes clear-text)
        cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")
        ;; FIXME: Read https://www.synopsys.com/blogs/software-security/proper-use-of-javas-securerandom/
        ;; This is still almost definitely wrong.
        rng (SecureRandom.)
        ^AlgorithmParameterSpec iv (build-random-iv 16)]
    ;; Q: Does it make sense to create and init a new
    ;; Cipher each time?
    (.init cipher Cipher/ENCRYPT_MODE secret-key iv rng)
    (.doFinal cipher clear-text)))

(s/fdef get-safe-client-nonce-suffix
  :args (s/cat :logger ::weald/logger
               :log-state ::weald/state)
  :ret (s/keys :req [::weald/state
                     ::specs/client-nonce-suffix]))
(defn get-safe-client-nonce-suffix
  "Get a new byte array containing the next client nonce suffix"
  [logger log-state]
  ;; It's tempting to refactor this and get-safe-server-nonce-suffix
  ;; even further to just have a common shared function that takes
  ;; the nonce length, log state, and destination key as parameters.
  ;; Though it does seem a bit silly.
  (let [dst (byte-array specs/client-nonce-suffix-length)
        log-state (do-safe-nonce log-state dst 0)]
    {::weald/state log-state
     ::specs/client-nonce-suffix dst}))

(s/fdef get-safe-server-nonce-suffix
        :args (s/cat :log-state ::weald/state)
        :ret (s/keys :req [::weald/state
                           ::safe-server-nonce]))
(defn get-safe-server-nonce-suffix
  "Get a new byte array containing the next server nonce suffix"
  [log-state]
  (let [dst (byte-array specs/server-nonce-suffix-length)
        log-state (do-safe-nonce log-state dst 0)]
    {::weald/state log-state
     ::specs/server-nonce-suffix dst}))

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
  "Sticks a new random key pair into a map"
  [which]
  (let [pair (random-key-pair)
        namespace "frereth.cp.shared.specs"
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
  (random-keys ::long))

(s/fdef do-load-keypair
  :args (s/cat :log-state ::weald/state
               :key-dir-name string?)
  :ret (s/keys :req [::java-key-pair
                     ::weald/state]))
(defn do-load-keypair
  "Honestly, these should be stored with something like base64 encoding"
  [log-state
   keydir]
  (let [log-state (log/debug log-state
                             ::do-load-keypair
                             "Looking for secretkey"
                             {::directory keydir})]
    (if keydir
      (let [secret (util/slurp-bytes (io/resource (str keydir "/.expertsonly/secretkey")))
            pair (TweetNaclFast$Box/keyPair_fromSecretKey secret)
            log-state (log/info log-state
                                ::do-load-keypair
                                (str "FIXME: Don't record these\n"
                                     "Loaded secret key from file")
                                {::secret-key-contents (b-t/->string secret)
                                 ::specs/secret-long (b-t/->string (.getSecretKey pair))
                                 ::specs/public-long
                                 (b-t/->string (.getPublicKey pair))})]
        {::java-key-pair pair
         ::weald/state log-state})
      ;; FIXME: This really should call random-keys instead.
      ;; Q: Shouldn't it?
      ;; A: Well, that depends on context
      {::java-key-pair (random-key-pair)
       ::weald/state log-state})))

(comment
  ;; Cheap way to save a key to disk in a way that's
  ;; easily loadable by do-load-keypair
  (let [pair (random-key-pair)
        public (.getPublicKey pair)
        secret (.getSecretKey pair)]
    (util/spit-bytes "$HOME/projects/snowcrash/cp/test/client-test/.expertsonly/secretkey"
                     secret)))

(defn new-nonce-key!
  "Generates a new secret nonce key and stores it under key-dir"
  [key-dir]
  (let [k (generate-symmetric-key (* Byte/SIZE nonce-key-length))
        raw (.getEncoded k)]
    (when-not (io/resource key-dir)
      (throw (ex-info (str "Missing folder on CLASSPATH: " key-dir))))
    (let [nonce-key-folder-path (str key-dir "/.expertsonly")
          nonce-key-folder (io/resource nonce-key-folder-path)]
      (when-not nonce-key-folder
          (io/make-parents nonce-key-folder-path)))
    (let [directory (.getPath (io/resource (str key-dir "/.expertsonly")))]
      (with-open [f (io/output-stream (io/file (str directory "/noncekey")))]
        (.write f raw)))))
(comment
  (let [url (io/resource "curve-test")
        path (.getPath url)])
  (new-nonce-key! path))

(s/fdef open-after
        :args (s/cat :log-state ::weald/state
                     :box bytes?
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
        :ret (s/keys :req [::weald/state
                           ::unboxed]))
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
  which I'm really not qualified to touch.

  And it would be premature optimization"
  [log-state
   ;; TODO: Check the clojure docs re: optimizing primitives.
   ;; This seems like it's totally wrong.
   box
   box-offset
   box-length
   nonce
   shared-key]
  {:pre [shared-key
         (bytes? shared-key)]}
  (let [box (bytes box)]
    (if (and box
             (>= (count box) (+ box-offset box-length))
             (>= box-length K/box-zero-bytes))
      (let [log-state (log/debug log-state
                                 ::open-after
                                 "Box is large enough")
            n (+ box-length K/box-zero-bytes)
            cipher-text (byte-array n)
            plain-text (byte-array n)]
        ;; Q: Is this worth being smarter about the array copies?
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
            (throw (ex-info "Opening box failed" {::error-code success
                                                  ::box (b-t/->string box)
                                                  ::offset box-offset
                                                  ::length box-length
                                                  ::nonce (b-t/->string nonce)
                                                  ::shared-key (b-t/->string shared-key)})))
          {::weald/state (log/debug log-state
                                    ::open-after
                                    "Box Opened")
           ;; Odds are, the next step, in general, is to decompose
           ;; what just got unwrapped. So this seems like a premature
           ;; convenience that would make more sense as an extra
           ;; wrapper elsewhere.
           ;; TODO: Look into adding that.

           ;; TODO: Compare the speed of these approaches with allocating a new
           ;; byte array without the 0-prefix padding and copying it back over
           ;; Keep in mind that we're limited to 1088 bytes per message.
           ::unboxed #_(-> plain-text
                           ;; This approach produces a SubVector, which cannot
                           ;; be cast to a [B
                           vec
                           (subvec K/decrypt-box-zero-bytes))
           (Arrays/copyOfRange plain-text
                               K/decrypt-box-zero-bytes
                               (count plain-text))}))
      (throw (ex-info "Box too small" {::box box
                                       ::offset box-offset
                                       ::length box-length
                                       ::nonce nonce
                                       ::shared-key shared-key})))))

(s/fdef open-box
        :args (s/cat :log-state ::weald/state
                     :nonce-prefix (s/and bytes?
                                          #(let [n (count %)]
                                             (or (= specs/client-nonce-prefix-length n)
                                                 (= specs/server-nonce-prefix-length n))))
                     :nonce-suffix (s/and bytes?
                                          #(let [n (count %)]
                                             (or (= specs/client-nonce-suffix-length n)
                                                 (= specs/server-nonce-suffix-length n))))
                     :crypto-buffer bytes?
                     :shared-key ::specs/crypto-key)
        :ret (s/keys :req [::weald/state]
                     :opt [::unboxed]))
(defn open-box
  "Builds a nonce and open a crypto box"
  [log-state nonce-prefix nonce-suffix crypto-box shared-key]
  (let [nonce-suffix (bytes nonce-suffix)
        crypto-box (bytes crypto-box)
        nonce (byte-array K/nonce-length)
        crypto-length (count crypto-box)]
    (b-t/byte-copy! nonce nonce-prefix)
    (let [prefix-length (count nonce-prefix)]
      (b-t/byte-copy! nonce
                      prefix-length
                      ^Long (- K/nonce-length prefix-length)
                      nonce-suffix))
    (try
      (open-after log-state crypto-box 0 crypto-length nonce shared-key)
      (catch Exception ex
        {::weald/state (log/exception log-state
                                      ex
                                      ::open-box
                                      "Failed to open box")}))))


(s/fdef decompose-box
  :args (s/cat :log-state ::weald/state
               :template ::templates/pattern)
  :ret (s/keys :req [::weald/state]
               :opt [::serial/decomposed]))
(defn decompose-box
  [log-state
   template
   nonce-prefix
   nonce-suffix
   crypto-box
   shared-key]
  (let [{plain-text ::unboxed
         log-state ::weald/state} (open-box log-state nonce-prefix nonce-suffix crypto-box shared-key)
        decomposed (serial/decompose template (Unpooled/wrappedBuffer (bytes plain-text)))]
    {::weald/state log-state
     ::serial/decomposed decomposed}))

(s/fdef random-array
  :args (s/cat :n integer?)
  :fn #(= (count (:ret %)) :n)
  :ret bytes?)
(defn random-array
  "Returns an array of n random bytes"
  ^bytes [^Long n]
  ;; Q:
  (TweetNaclFast/randombytes n))

(defn random-bytes!
  ;; FIXME: Make this private. Anything that currently calls it
  ;; should really just use get-random-bytes instead.
  "Fills dst with random bytes"
  [#^bytes dst]
  (TweetNaclFast/randombytes dst))

(s/fdef get-random-bytes
  :args (s/cat :n integer?)
  :ret bytes?)
(defn get-random-bytes
  [n]
  (let [result (byte-array n)]
    (random-bytes! result)
    result))

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

(s/fdef random-mod
        :args (s/cat :n nat-int?)
        :fn (fn [{:keys [:args :ret]}]
              (let [n (:n args)]
                (if (not= n 0)
                  (< ret n)
                  (= ret n))))
        :ret (s/and integer?
                    (complement neg?)))
(let [;; FIXME: Set the seed securely
      ;; This really should be used for anything
      ;; that needs a random number
      rng (java.security.SecureRandom.)]
  (defn random-mod
    "Picks a big random number and securely "
    [denominator]
    (if (not= 0 denominator)
      ;; Using java.util.Random. here seems...wrong
      ;; FIXME: Verify that this uses the secure rng defined
      ;; in the lexical closure.
      ;; FIXME: Look into using weavejester's secure-random
      ;; library instead.
      (let [numerator (BigInteger. 256 (java.util.Random.))]
        (comment
          ;; The reference version actually does this:
          (b-t/secure-mod numerator denominator))
        ;; Note this this approach is significantly
        ;; faster.
        ;; I'm 90% certain that it's just because there's
        ;; nothing built into C to just handle it this way.
        ;; TODO: Check with a cryptographer.
        (mod numerator denominator))
      0)))

;;; TODO: add an optional arity to both this and
;;; secret-unbox to allow the caller to supply a dst parameter that gets
;;; modified in place.
(s/fdef secret-box
        :args (s/cat :cleartext bytes?
                     :length integer?
                     :nonce ::specs/nonce
                     :key ::specs/crypto-key)
        :ret bytes?)
(defn secret-box
  "Symmetric encryption

Note that this does not do anything about the initial padding.

It may be an implementation detail, but box-after above is really
just a wrapper around this"
  [cleartext length nonce key]
  (let [key (bytes key)
        dst (byte-array length)]
    (TweetNaclFast/crypto_secretbox dst cleartext
                                    length nonce key)))

(s/fdef secret-unbox
  :args (s/cat :cipher-text bytes?
               :length integer?
               :nonce ::specs/nonce
               :key ::specs/crypto-key)
  ;; dst has a size relationship to cipher-text.
  ;; TODO: Spec that.
  :ret bytes?)
(defn secret-unbox
  "Symmetric-key decryption"
  [cipher-text length nonce key]
  (let [dst (byte-array length)]
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
    dst))
