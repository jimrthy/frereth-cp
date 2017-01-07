(ns com.frereth.common.curve.shared
  "For pieces shared among client, server, and messaging"
  (:require [gloss.core :as gloss])
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           java.security.SecureRandom))

(def hello-header (.getBytes "QvnQ5XlH"))
(def hello-nonce-prefix (.getBytes "CurveCP-client-H"))
(def vouch-nonce-prefix (.getBytes "CurveCPV"))

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

(defn do-load-keypair
  [keydir]
  (if keydir
    ;; TODO: Get this translated
    (throw (RuntimeException. "Load from file"))
    (random-key-pair)))

(let [rng (SecureRandom.)]
  (defn random-bytes
    [dst]
    (.nextBytes rng dst)))

(defn random-mod
  "Returns a cryptographically secure random number between 0 and n"
  [n]
  (let [default 0N]
    (if (<= n 1)
      default
      (let [place-holder (byte-array 32)]
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
        ;; So definitely stick with this until an expert tells
        ;; me otherwise
        (random-bytes place-holder)
        (reduce (fn [^clojure.lang.BigInt acc ^Byte b]
                  (quot (+ (* 256 acc) b) n))
                default
                place-holder)))))

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

(defn uint64-pack
  [dst n src]
  (throw (RuntimeException. "Get this translated")))

(defn zero-bytes
  [n]
  (let [result (byte-array n)]
    (java.util.Arrays/fill result (byte 0))))

(def all-zeros
  "To avoid creating this over and over"
  (zero-bytes 128))
