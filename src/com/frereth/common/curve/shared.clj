(ns com.frereth.common.curve.shared
  "For pieces shared among client, server, and messaging"
  (:require [clojure.java.io :as io]
            [gloss.core :as gloss])
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           java.security.SecureRandom))

(def hello-header (.getBytes "QvnQ5XlH"))
(def hello-nonce-prefix (.getBytes "CurveCP-client-H"))
(def vouch-nonce-prefix (.getBytes "CurveCPV"))
(def initiate-header (.getBytes "QvnQ5XlI"))
(def initiate-nonce-prefix (.getBytes "CurveCP-client-I"))

(def max-unsigned-long (bigint (Math/pow 2 64)))
(def nanos-in-seconds (long (Math/pow 10 9)))

(defn byte-copy!
  "Copies the bytes from src to dst"
  ([dst src]
   (run! (fn [n]
           (aset dst n (aget src n)))
         (range (count src))))
  ([dst offset n src]
   (run! (fn [m]
           (aset dst (+ m offset) (aget src m)))
         (range n)))
  ([dst offset n src src-offset]
   (run! (fn [m]
           (let [o (+ m offset)]
             (aset dst o
                   (aget src o))))
         (range n))))

(defn bytes=
  [x y]
  (throw (RuntimeException. "Translate this")))

(def cookie-header (.getBytes "RL3aNMXK"))
(def cookie-nonce-prefix (.getBytes "CurveCPK"))

(def cookie-frame (gloss/compile-frame (gloss/ordered-map :header (gloss/string :utf-8 :length 8)
                                                          :client-extension (gloss/finite-block 16)
                                                          :server-extension (gloss/finite-block 16)
                                                          ;; Implicitly prefixed with "CurveCPK"
                                                          :nonce (gloss/finite-block 16)
                                                          :cookie (gloss/finite-block 144))))

(defn crypto-box-prepare
  [public secret]
  (TweetNaclFast$Box. public secret))

(defn random-key-pair
  []
  (TweetNaclFast$Box/keyPair))

(defn slurp-bytes
  "Slurp the bytes from a slurpable thing

Copy/pasted from stackoverflow. Credit: Matt W-D.

alt approach: Add dependency to org.apache.commons.io

Or there's probably something similar in guava"
  [x]
  (with-open [out (java.io.ByteArrayOutputStream.)]
    (clojure.java.io/copy (clojure.java.io/input-stream x) out)
    (.toByteArray out)))

(defn do-load-keypair
  [keydir]
  (if keydir
    (let [secret (slurp-bytes (io/resource (str keydir "/.expertsonly/secretkey")))]
      (TweetNaclFast$Box/keyPair_fromSecretKey secret))
    (random-key-pair)))
(comment (io/resource "curve-test/."))


(defn random-bytes!
  [#^bytes dst]
  (TweetNaclFast/randombytes dst))

(defn random-array
  [^Long n]
  (TweetNaclFast/randombytes n))

(defn random-long
  "This seems like it's really just for generating a nonce.
  Or maybe it isn't being used at all?"
  []
  (throw (RuntimeException. "No matching implementation")))

(defn random-mod
  "Returns a cryptographically secure random number between 0 and n"
  [n]
  (let [default 0N]
    (if (<= n 1)
      default
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
                  (quot (+ (* 256 acc) b) n))
                default
                bs)))))

(defn safe-nonce
  [dst keydir offset]
  (if keydir
    (throw (RuntimeException. "Get real safe-nonce implementation translated"))
    ;; This is where working with something like a ByteBuf seems like it
    ;; would be much nicer
    (let [n (- (count dst) offset)
          tmp (byte-array n)]
      (.randomBytes tmp)
      (byte-copy! dst offset n tmp))))

(defn uint64-pack!
  "Sets 8 bytes in dst (starting at offset n) to x

Note that this looks/smells very similar to TweetNaclFast's
Box.generateNonce.

If that's really all this is used for, should definitely use
that implementation instead"
  [dst n x]
  (let [x' (bit-and 0xff x)]
    (aset dst n x')
    (let [x (unsigned-bit-shift-right x 8)
          x' (bit-and 0xff x)]
      (aset dst (inc n) x')
      (let [x (unsigned-bit-shift-right x 8)
            x' (bit-and 0xff x)]
        (aset dst (+ n 2) x')
        (let [x (unsigned-bit-shift-right x 8)
              x' (bit-and 0xff x)]
          (aset dst (+ n 3) x')
          (let [x (unsigned-bit-shift-right x 8)
                x' (bit-and 0xff x)]
            (aset dst (+ n 4) x')
            (let [x (unsigned-bit-shift-right x 8)
                  x' (bit-and 0xff x)]
              (aset dst (+ n 5) x')
              (let [x (unsigned-bit-shift-right x 8)
                    x' (bit-and 0xff x)]
                (aset dst (+ n 6) x')
                (let [x (unsigned-bit-shift-right x 8)
                      x' (bit-and 0xff x)]
                  (aset dst (+ n 7) x'))))))))))

(defn zero-bytes
  [n]
  (let [result (byte-array n)]
    (java.util.Arrays/fill result (byte 0))))

(def all-zeros
  "To avoid creating this over and over"
  (zero-bytes 128))
