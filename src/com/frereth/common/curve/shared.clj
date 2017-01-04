(ns com.frereth.common.curve.shared
  "For pieces shared among client, server, and messaging"
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]
           java.security.SecureRandom))

(def max-unsigned-long (bigint (Math/pow 2 64)))
(def nanos-in-seconds (long (Math/pow 10 9)))

(defn crypto-box-prepare
  [public secret]
  (TweetNaclFast$Box public secret))

(defn random-key-pair
  []
  (TweetNaclFast$Box/keyPair))

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
        ;; (for now, I'm sticking as closely as possibly
        ;; to straight translation)
        (random-bytes place-holder)
        (reduce (fn [^clojure.lang.BigInt acc ^Byte b]
                  (quot (+ (* 256 acc) b) n))
                default
                place-holder)))))

(defn zero-bytes
  [n]
  (let [result (byte-array n)]
    (java.util.Arrays/fill result (byte 0))))

(def all-zeros
  "To avoid creating this over and over"
  (zero-bytes 128))
