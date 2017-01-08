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

(defrecord State [client-extension
                  client-extension-load-time
                  client-long<->server-long
                  client-short<->server-long
                  client-short<->server-short
                  keydir
                  long-pair
                  nonce
                  outgoing-message
                  packet
                  port
                  recent
                  server-address
                  server-cookie
                  server-extension
                  server-name
                  server-short-term-pk
                  server-long-term-pk
                  short-pair
                  short-term-nonce
                  text
                  vouch])

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

(defn build-hello
  [{:keys [client-extension
           client-short<->server-long
           nonce
           packet
           server-extension
           short-pair
           short-term-nonce
           text]
    :as state}]
  (let [state (clientextension-init state)
        short-term-nonce (update-client-short-term-nonce short-term-nonce)]
    (shared/byte-copy! nonce shared/hello-nonce-prefix)
    (shared/uint64-pack! nonce 16 short-term-nonce)

    ;; This seems to be screaming for gloss.
    ;; Q: What kind of performance difference would that make?
    (shared/byte-copy! packet shared/hello-header)
    (shared/byte-copy! packet 8 16 server-extension)
    (shared/byte-copy! packet 24 16 client-extension)
    (shared/byte-copy! packet 40 32 (.getPublicKey short-pair))
    (shared/byte-copy! packet 72 64 shared/all-zeros)
    (shared/byte-copy! packet 136 8 nonce 16)
    (let [payload (.after client-short<->server-long packet 144 80 nonce)]
      (shared/byte-copy! packet 144 80 payload)
      (map->State (assoc state
                         :short-term-nonce short-term-nonce)))))

(defn decrypt-actual-cookie
  [{:keys [client-short<->server-long
           nonce
           packet
           server-cookie
           text]
    :as state}
   rcvd]
  (shared/byte-copy! nonce shared/cookie-nonce-prefix)
  (shared/byte-copy! nonce 8 16 (:nonce rcvd))
  (shared/byte-copy! text 0 144 (:cookie packet))
  (let [decrypted (.open_after client-short<->server-long text 0 144 nonce)
        extracted (gloss/decode cookie)
        server-short-term-pk (byte-array 32)]
    (shared/byte-copy! server-short-term-pk (:s' extracted))
    (server-cookie (byte-array 96))
    (shared/byte-copy! server-cookie (:cookie extracted))
    (assoc state
           :server-short-term-pk server-short-term-pk
           :server-cookie server-cookie)))

(defn decrypt-cookie-packet
  [{:keys [client-extension
           nonce
           packet
           server-extension
           text]
    :as state}]
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
      (decrypt-actual-cookie state rcvd))))

(defn build-vouch
  [{:keys [client-long<->server-long
           keydir
           nonce
           short-pair
           text]
    :as state}]
  (shared/byte-copy! nonce shared/vouch-nonce-prefix)
  (shared/safe-nonce nonce keydir 16)

  (shared/byte-copy! text (shared/zero-bytes 32))
  (shared/byte-copy! text 32 32 (.getPublicKey short-pair))
  (let [encrypted (.after client-long<->server-long text 0 64 nonce)
        vouch (byte-array 64)]
    (shared/byte-copy! vouch 0 16 nonce 8)
    (shared/byte-copy! vouch 16 48 encrypted)
    ;; At this point the reference implementation pauses to fire up
    ;; its message-handling child process.
    (throw (RuntimeException. "Finish this"))
    (assoc state :vouch vouch)))

(defn extract-child-message
  "Pretty much blindly translated from the CurveCP reference
implementation. This is code that I don't understand yet"
  [state buffer]
  (let [extracted (reduce (fn [{:keys [buf
                                       buf-len
                                       msg
                                       msg-len
                                       i
                                       state]
                                :as acc}
                               b]
                            (when (or (< msg-len 0)
                                      (> msg-len 2048))
                              (throw (ex-info "done" {})))
                            ;; It seems silly to set this and then check the first byte
                            ;; for the quit signal (assuming that's what it is)
                            ;; every time through the loop.
                            (aset msg msg-len (aget buf i))
                            (let [msg-len (inc msg-len)
                                  length-code (aget msg 0)]
                              (when (bit-and length-code 0x80)
                                (throw (ex-info "done" {})))
                              (if (= msg-len (inc (* 16 length-code)))
                                (let [{:keys [client-extension
                                              client-short<->server-short
                                              long-pair
                                              nonce
                                              server-cookie
                                              server-extension
                                              server-name
                                              short-pair
                                              packet
                                              text
                                              vouch]
                                       :as state} (clientextension-init state)
                                      short-term-nonce (update-client-short-term-nonce
                                                        (:short-term-nonce state))]
                                  (shared/uint64-pack! nonce 16 short-term-nonce)
                                  ;; This is where the original splits, depending on whether
                                  ;; we've received a message back from the server or not.
                                  ;; According to the spec:
                                  ;; The server is free to send any number of Message packets
                                  ;; after it sees the Initiate packet.
                                  ;; The client is free to send any number of Message packets
                                  ;; after it sees the server's first Message packet.
                                  ;; At this point in time, we know we're still building the
                                  ;; Initiate packet.
                                  ;; It's tempting to try to avoid duplication the same
                                  ;; way the reference implementation does, by handling
                                  ;; both logical branches here.
                                  ;; And maybe there's a really good reason for doing so.
                                  ;; But this function feels far too complex as it is.
                                  (let [r (dec msg-len)]
                                    (when (or (< r 16)
                                              (> r 640))
                                      (throw (ex-info "done" {})))
                                    (shared/byte-copy! nonce 0 16 shared/initiate-nonce-prefix)
                                    ;; Reference version starts by zeroing first 32 bytes.
                                    ;; I thought we just needed 16 for the encryption buffer
                                    (shared/byte-copy! text 0 16 shared/all-zeros)
                                    (shared/byte-copy! text 32 32 (.getPublicKey long-pair))
                                    (shared/byte-copy! text 64 64 vouch)
                                    (shared/byte-copy! text 128 256 server-name)
                                    (shared/byte-copy! text 384 r msg 1)
                                    (let [box (.after client-short<->server-short text 0 (+ r 384)
                                                      nonce)]
                                      (shared/byte-copy! packet 0 8 shared/initiate-header)
                                      (shared/byte-copy! packet 8 16 server-extension)
                                      (shared/byte-copy! packet 24 16 client-extension)
                                      (shared/byte-copy! packet 40 32 (.getPublicKey short-pair))
                                      (shared/byte-copy! packet 72 96 server-cookie)
                                      (shared/byte-copy! packet 168 8 nonce 16)
                                      ;; Actually, the original version sends off the packet, updates
                                      ;; msg-len to 0, and goes back to pulling date from child/server.
                                      (throw (ex-info "How should this really work?"
                                                      {:problem "Need to break out of loop here"})))))
                                (assoc acc :msg-len msg-len))))
                          {:buf (byte-array 4096)
                           :buf-len 0
                           :msg (byte-array 2048)
                           :msg-len 0
                           :i 0
                           :state state}
                          buffer)]
    (assoc state :outgoing-message (:child-msg extracted))))

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
           ;; The server's domain name, in DNS format (between 1 and 255 bytes),
           ;; zero-padded to 256 bytes
           server-name
           server-long-term-pk
           server-address
           port
           server-extension
           timeout]
    :or {flag-verbose 0
         timeout 2500}
    :as state}
   server-chan
   client-chan]
  (assert (and server-name server-long-term-pk server-address port server-extension))

  (let [recent (System/nanoTime)
        long-pair (do-load-keypair keydir)
        short-pair (shared/random-key-pair)
        state (assoc state
                     :client-extension nil
                     :client-extension-load-time 0
                     :client-long<->server-long (shared/crypto-box-prepare server-long-term-pk (.getSecretKey short-pair))
                     :client-short<->server-long (shared/crypto-box-prepare server-long-term-pk (.getSecretKey long-pair))
                     :long-pair long-pair
                     :nonce (byte-array 24)
                     :packet (byte-array 4096)
                     :recent recent
                     :short-pair short-pair
                     ;; Q: What's the magic number?
                     :short-term-nonce (shared/random-mod 281474976710656N)
                     :text (byte-array 2048))
        state (build-hello state)]
    ;; The reference implementation mingles networking with this code.
    ;; That seems like it might make sense as an optimization,
    ;; but not until I have convincing numbers that it's needed.
    ;; Of course, I might also be opening things up for timing attacks.
    (let [d (stream/put! server-chan (:packet state))]
      (deferred/chain d
        (fn [sent?]
          (if sent?
            (deferred/timeout! (stream/take! server-chan) timeout ::hello-timed-out)
            ::hello-send-failed))
        (fn [cookie]
          ;; Q: What is really in cookie now?
          ;; (I think it's a netty ByteBuf)
          (let [state (assoc state :packet cookie)]
            ;; Really just want to break out of the chain
            ;; if this returns nil.
            ;; There's no reason to try to go any further
            ;; Q: What's a good way to handle that?
            (decrypt-cookie-packet state)))
        (fn [state-with-decrypted-cookie]
          (when state-with-decrypted-cookie
            (assoc state-with-decrypted-cookie
                   :client-short<->server-short (shared/crypto-box-prepare
                                                 (:server-short-term-pk state-with-decrypted-cookie)
                                                 (.getSecretKey short-pair)))))
        (fn [state-with-keyed-cookie]
          (build-vouch state-with-keyed-cookie))
        (fn [vouched-state]
          (let [future (stream/take! client-chan)
                ;; I'd like to just return that future and
                ;; handle the next pieces separately.
                ;; But then I'd lose the state that I'm
                ;; accumulating
                msg-buffer (deref future timeout ::child-timed-out)]
            (assert (and msg-buffer
                         (not= msg-buffer ::child-timed-out)))
            (let [updated (extract-child-message vouched-state msg-buffer)]
              (assoc updated :initiate-sent? (stream/put! server-chan (:packet updated))))))
        (fn [state]
          (let [success (deref (:initiate-sent? state) timeout ::sending-initiate-failed)]
            (if success
              (dissoc state :initiate-sent?)
              ;; TODO: Really should initiate retries
              ;; But if we failed to send the packet at all, something is badly wrong
              (throw (ex-info "Failed to send initiate" state)))))))))

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
