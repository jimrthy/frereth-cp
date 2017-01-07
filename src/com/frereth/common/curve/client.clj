(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [com.frereth.common.curve.shared :as shared]
            [gloss.core :as gloss-core]
            [gloss.io :as gloss]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))

(def cookie (gloss-core/compile-frame (gloss-core/ordered-map :s' (gloss-core/finite-block 32)
                                                              :black-box (gloss-core/finite-block 96))))

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
                                  (shared/zero-bytes 16)))
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

(defn decrypt-cookie
  [{:keys [client-extension
           nonce
           packet
           server-extension
           text]}]
  ;; Q: How does packet length actually work?
  (assert (= (count packet) 200))
  (let [rcvd (gloss/decode shared/cookie-frame packet)]
    ;; Reference implementation starts by comparing the
    ;; server IP and port vs. what we received.
    ;; Which we don't have here.
    ;; That's a really important detail.
    ;; We have access to both org.clojure/tools.logging
    ;; (from aleph)
    ;; and commons.logging (looks like I added this one)
    ;; here.
    ;; TODO: Really should log to one or the other
    (println "WARNING: Verify that this packet came from the appropriate server")
    ;; Q: How accurate/useful is this approach?
    ;; A: Not at all.
    ;; (i.e. mostly comparing byte arrays
    (when (and (shared/bytes= shared/cookie-header
                  (String. (:header rcvd)))
               (shared/bytes= client-extension (:client-extension rcvd))
               (shared/bytes= server-extension (:server-extension rcvd)))
      (shared/byte-copy! nonce shared/cookie-nonce-prefix)
      (shared/byte-copy! nonce 8 16 (:nonce rcvd))
      ;; Need to decrypt the actual cookie
      (throw (RuntimeException. "Start here")))))

(defn hand-shake
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
           server-name   ; Q: What's this for?
           server-long-term-pk
           server-address
           port
           server-extension
           timeout]
    :or {flag-verbose 0
         timeout 2500}}
   ch
   first-msg]
  (assert (and server-name server-long-term-pk server-address port server-extension))

  (let [long-pair (do-load-keypair keydir)
        short-pair (shared/random-key-pair)
        ;; Q: What's the magic number?
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
    (let [d (stream/put! ch state)]
      (deferred/chain d
        (fn [sent?]
          (if sent?
            (deferred/timeout! (stream/take! ch) timeout ::hello-timed-out)
            ::hello-send-failed))
        (fn [cookie]
          ;; Q: What is really in cookie now?
          ;; I think it's a ByteBuf.
          (let [state (assoc state :packet cookie)]
            ;; Really just want to break out of the chain
            ;; if this returns nil.
            ;; There's no reason to try to go any further
            ;; Q: What's a good way to handle that?
            (decrypt-cookie state)))
        (fn [decrypted-cookie]
          (when decrypted-cookie
            (throw (RuntimeException. "Keep translating"))))))))

(defn basic-test
  []
  (let [client-keys (shared/random-key-pair)
        ;; Q: Do I want to use this or TweetNaclFast/keyPair?
        server-keys (shared/random-key-pair)
        msg "Hold on, my child needs my attention"
        bs (.getBytes msg)
        ;; This can't possibly be the proper size
        nonce (byte-array [1 2 3 4 5 6 7 8 9 10
                           11 12 13 14 15 16 17
                           18 19 20 21 22 23 24])
        boxer (shared/crypto-box-prepare (.getPublicKey server-keys) (.getSecretKey client-keys))
        ;; This seems likely to get confused due to arity issues
        boxed (.box boxer bs nonce)
        unboxer (shared/crypto-box-prepare (.getPublicKey client-keys) (.getSecretKey server-keys))]
    (String. (.open unboxer boxed nonce))))

(comment (basic-test))
