(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [clojure.core.async :as async]
            [com.frereth.common.curve.shared :as shared]
            [io.netty.buffer ByteBuf]))

(defn clientextension-init
  "Starting from the assumption that this is neither performance critical
nor subject to timing attacks because it just won't be called very often."
  [{:keys [client-extension
           client-extension-load-time
           recent]
    :as state}]
  (assert (and client-extension-load-time recent))
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

(defn build-hello
  [{:keys [client-extension
           nonce
           packet
           short-term-nonce
           text]
    :as state}]
  (let [state (clientextension-init state)
        short-term-nonce (update-client-short-term-nonce short-term-nonce)]
    (shared/byte-copy! nonce (.getBytes "CurveCP-client-H"))
    (throw (RuntimeException. "Finish this"))
    (assoc state
           :short-term-nonce short-term-nonce)))

(defn main
  "This really needs to be some sort of stateful component.
  It almost definitely needs to interact with ByteBuf to
  build up something that's ready to start communicating
  with servers.

  It seems worth working through the implications of
  exactly what makes sense in a clojure context.

  This shouldn't be a cryptographically sensitive
  area, since it's just calling the crypto box
  and key management functions.

  But the functionality it's going to be using has
  been mostly ignored.

  How much difference would it make if I split some
  of the low-level buffer management into its own
  pieces and used clojure's native facilities to
  handle building that?"
  [{:keys [flag-verbose  ; Q: Why?
           keydir
           server-name
           server-long-term-pk
           server-address
           port
           extension]
    :or {flag-verbose 0}}
   ch
   first-msg]
  (assert (and server-name server-long-term-pk server-address port extension))

  (let [long-pair (do-load-keypair keydir)
        short-pair (shared/random-key-pair)
        short-term-nonce (shared/random-mod 281474976710656N)
        client-short<->server-long (shared/crypto-box-prepare server-long-term-pk (.getSecretKey short-pair))
        client-long<->server-long (shared/crypto-box-prepare server-long-term-pk (.getSecretKey long-pair))
        ;; The reference implementation opens a UDP socket here, then loops over
        ;; and sends messages to each of the server sockets (with possible duplicates)
        ;; supplied on the command line.
        ;; Both of those details simply do not seem to fit.
        recent (System/nanoTime)
        state {:client-extension nil
               :client-extension-load-time 0
               :nonce (byte-array 24)
               :packet (byte-array 4096)
               :recent recent
               :short-term-nonce short-term-nonce
               :text (byte-array 2048)}
        state (build-hello state)]
    ;; Q: Is this worth bringing manifold back?
    ;; Or maybe interacting with the socket directly?
    (async/put! ch state)))

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
