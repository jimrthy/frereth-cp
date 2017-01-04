(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach seems dubious"
  (:require [com.frereth.common.curve.shared :as shared]))

(defn clientextension-init
  "Starting from the assumption that this is neither performance critical
nor subject to timing attacks because it just won't be called very often."
  [{:keys [client-extension
           client-extension-load-time
           recent]
    :as state}]
  (let [reload (>= recent client-extension-load-time)
        client-extension-load-time (if reload
                                     (+ recent (* 30 shared/nanos-in-seconds)
                                        client-extension-load-time))
        client-extension (if-not reload
                           (try (-> "/etc/curvecpextension"
                                    (subs 0 16)
                                    .getBytes)
                                (catch java.io.FileNotFoundException _
                                  (zero-bytes 16)))
                           client-extension)]
    (assoc state
           :client-extension-load-time client-extension-load-time
           :client-extension client-extension)))

(defn update-client-short-term-nonce
  "Using a BigInt for this seems like an obnoxious performance hit.
Using a regular long seems like a recipe for getting it wrong.
Guava specifically has an unsigned long class.
TODO: Switch to that or whatever Bouncy Castle uses"
  [^clojure.lang.BigInt nonce]
  (let [result (inc nonce)]
    ;; In the original C, the nonce is a crypto_uint64.
    ;; So they can just check to see whether it wrapped
    ;; around to 0.
    (when (> result shared/max-unsigned-long)
      (throw (Exception. "nonce space expired"
                         {:must "End communication immediately"})))
    result))

(defn do-load-keypair
  [keydir]
  (if keydir
    ;; TODO: Get this translated
    (throw (RuntimeException. "Not translated"))
    (shared/random-key-pair)))

(defn main
  [{:keys [flag-verbose
           keydir
           server-name
           server-long-term-pk
           server-address
           port
           extension]
    :or {flag-verbose 0}}
   first-msg]
  (assert (and server-name server-long-term-pk server-address port extension))

  (let [long-pair (load-keypair keydir)
        short-pair (shared/random-key-pair)
        short-term-nonce (shared/random-mod 281474976710656N)
        client-short<->server-long (shared/crypto-box-prepare server-long-term-pk (.getSecretKey short-pair))
        client-long<->server-long (shared/crypto-box-prepare server-long-term-pk (.getSecretKey long-pair))
        udpfd (throw (RuntimeException. "start here"))
        recent (System/nanoTime)]
    (throw (RuntimeException. "Not Implemented"))))

(defn basic-test
  []
  (let [client-keys (shared/random-key-pair)
        ;; Q: Do I want to use this or TweetNaclFast/keyPair?
        server-keys (TweetNaclFast$Box/keyPair)
        msg "Hold on, my child needs my attention"
        bs (.getBytes msg)
        ;; This can't possibly be the proper size
        nonce (byte-array [1 2 3 4 5 6 7 8 9 10
                           11 12 13 14 15 16 17
                           18 19 20 21 22 23 24])
        boxer (TweetNaclFast$Box. (.getPublicKey server-keys) (.getSecretKey client-keys))
        ;; This seems likely to get confused due to arity issues
        boxed (.box boxer bs nonce)
        unboxer (TweetNaclFast$Box. (.getPublicKey client-keys) (.getSecretKey server-keys))]
    (String. (.open unboxer boxed nonce))))

(comment (basic-test))
