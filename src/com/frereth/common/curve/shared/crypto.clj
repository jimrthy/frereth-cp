(ns com.frereth.common.curve.shared.crypto
  "Wrap up the low-level crypto functions"
  (:require [clojure.spec :as s]
            [clojure.tools.logging :as log]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]
            [com.frereth.common.curve.shared.constants :as K])
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn box-after
  ;; TODO: Make sure both these versions work
  ([key plain-text length nonce]
   (when (<= length (count plain-text))
     (let [padded-length (+ length K/box-zero-bytes)
           cipher-text (byte-array padded-length)
           plain-buffer (byte-array padded-length)]
       (b-t/byte-copy! plain-buffer K/box-zero-bytes length plain-text)
       (TweetNaclFast/crypto_box_afternm cipher-text plain-buffer padded-length nonce key)
       cipher-text)))
  ([key plain-text offset length nonce]
   (when (< (+ length offset) (count plain-text))
     (let [padded-length (+ length K/box-zero-bytes)
           cipher-text (byte-array padded-length)
           plain-buffer (byte-array padded-length)]
       (b-t/byte-copy! plain-buffer K/box-zero-bytes length plain-text offset)
       (TweetNaclFast/crypto_box_afternm cipher-text plain-buffer padded-length nonce key)
       cipher-text))))

(defn box-prepare
  "Set up shared secret so I can avoid the if logic to see whether it's been done.
  At least, I think that's the point."
  [public secret]
  (let [shared (byte-array K/shared-key-length)]
    (TweetNaclFast/crypto_box_beforenm shared public secret)
    shared))

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
        :ret vector?)
(defn open-after
  "Low-level direct crypto box opening

parameter box-offset: first byte of box to start opening
parameter box-length: how many bytes of box to open"
  [box box-offset box-length nonce shared-key]
  {:pre [(bytes? shared-key)]}
  (if (and (not (nil? box))
           (>= (count box) (+ box-offset box-length))
           (>= box-length K/box-zero-bytes))
    (do
      (log/info "Box is large enough")
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
            (throw (RuntimeException. "Opening box failed")))
          ;; The * 2 on the zero bytes is important.
          ;; The encryption starts with 0's and prepends them.
          ;; The decryption requires another bunch (of zeros?) in front of that.
          ;; We have to strip them both to get back to the real plain text.
          (comment (log/info "Decrypted" box-length "bytes into" n "starting with" (aget plain-text (* 2 box-zero-bytes))))
          ;; TODO: Compare the speed of doing this with allocating a new
          ;; byte array without the 0-prefix padding and copying it back over
          ;; Keep in mind that we're limited to 1088 bytes per message.
          (-> plain-text
              vec
              (subvec K/decrypt-box-zero-bytes)))))
    (throw (RuntimeException. "Box too small"))))

(defn random-array
  "Returns an array of n random bytes"
  [^Long n]
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
  (long (random-mod K/max-random-nonce)))

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
