(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [clojure.spec :as s]
            [com.frereth.common.curve.shared :as shared]
            [com.stuartsierra.component :as cpt]
            [gloss.core :as gloss-core]
            [gloss.io :as gloss]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))

(def cookie (gloss-core/compile-frame (gloss-core/ordered-map :s' (gloss-core/finite-block 32)
                                                              :black-box (gloss-core/finite-block 96))))

(s/def ::server-long-term-pk ::shared/public-key)
(s/def ::server-cookie any?)  ; TODO: Needs a real spec
(s/def ::server-short-term-pk ::shared/public-key)
(s/def ::server-security (s/keys :req [::server-long-term-pk
                                       ::server-cookie
                                       ::shared/server-name
                                       ::server-short-term-pk]))

(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-long<->server-long
                                      ::client-short<->server-long
                                      ::client-short<->server-short]))

(s/def ::state (s/keys :req-un [::shared/packet-management]))

(declare hand-shake)
(defrecord State [child-chan
                  client-extension-load-time
                  extension
                  my-keys
                  outgoing-message
                  packet-management
                  recent
                  server-chan
                  server-extension
                  server-security
                  shared-secrets
                  vouch
                  work-area]
  cpt/Lifecycle
  (start
    [this]
    (hand-shake (assoc this
                       :packet-management (shared/default-packet-manager)
                       :work-area (shared/default-work-area))))
  (stop
    [this]
    this))

(defn clientextension-init
  "Starting from the assumption that this is neither performance critical
nor subject to timing attacks because it just won't be called very often."
  [{:keys [extension
           client-extension-load-time
           recent]
    :as this}]
  (assert (and client-extension-load-time recent))
  (let [reload (>= recent client-extension-load-time)
        client-extension-load-time (if reload
                                     (+ recent (* 30 shared/nanos-in-second)
                                        client-extension-load-time))
        extension (if-not reload
                    (try (-> "/etc/curvecpextension"
                             (subs 0 16)
                             .getBytes)
                         (catch java.io.FileNotFoundException _
                           (shared/zero-bytes 16)))
                    extension)]
    (assoc this
           :client-extension-load-time client-extension-load-time
           :extension extension)))

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

(defn do-build-hello
  [{:keys [extension
           my-keys
           server-extension
           shared-secrets
           short-term-nonce
           text]
    :as this}]
  (let [this (clientextension-init this)
        packet-management (:packet-management this)
        {:keys [::shared/nonce ::shared/packet]} packet-management
        short-term-nonce (update-client-short-term-nonce short-term-nonce)]
    (shared/byte-copy! nonce shared/hello-nonce-prefix)
    (shared/uint64-pack! nonce 16 short-term-nonce)

    ;; This seems to be screaming for gloss.
    ;; Q: What kind of performance difference would that make?
    (shared/byte-copy! packet shared/hello-header)
    (shared/byte-copy! packet 8 shared/extension-length server-extension)
    (shared/byte-copy! packet 24 shared/extension-length extension)
    (shared/byte-copy! packet 40 shared/key-length (.getPublicKey (::short-pair my-keys)))
    (shared/byte-copy! packet 72 64 shared/all-zeros)
    (shared/byte-copy! packet 136 shared/client-nonce-suffix-length
                       nonce
                       shared/client-nonce-prefix-length)
    (let [payload (.after (::client-short<->server-long shared-secrets) packet 144 80 nonce)]
      (shared/byte-copy! packet 144 80 payload)
      (assoc this
             :short-term-nonce short-term-nonce))))

(defn decrypt-actual-cookie
  [{:keys [packet-management
           shared-secrets
           server-security
           text]
    :as this}
   rcvd]
  (let [nonce (::shared/nonce packet-management)]
    (shared/byte-copy! nonce shared/cookie-nonce-prefix)
    (shared/byte-copy! nonce
                       shared/server-nonce-prefix-length
                       shared/server-nonce-suffix-length
                       (:nonce rcvd))
    (shared/byte-copy! text 0 144 (-> packet-management ::shared/packet :cookie))
    (let [decrypted (.open_after (::client-short<->server-long shared-secrets) text 0 144 nonce)
          extracted (gloss/decode cookie decrypted)
          server-short-term-pk (byte-array shared/key-length)
          server-cookie (byte-array 96)
          server-security (assoc (:server-security this)
                                 ::server-short-term-pk server-short-term-pk
                                 ::server-cookie server-cookie)]
      (shared/byte-copy! server-short-term-pk (:s' extracted))
      (shared/byte-copy! server-cookie (:cookie extracted))
      (assoc this :server-security server-security))))

(defn decrypt-cookie-packet
  [{:keys [extension
           packet-management
           server-extension
           text]
    :as this}]
  (let [packet (::shared/packet packet-management)]
    ;; Q: How does packet length actually work?
    (assert (= (count packet) shared/cookie-packet-length))
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
                 (shared/bytes= extension (:client-extension rcvd))
                 (shared/bytes= server-extension (:server-extension rcvd)))
        (decrypt-actual-cookie this rcvd)))))

(defn build-vouch
  [{:keys [packet-management
           my-keys
           shared-secrets
           text]
    :as this}]
  (let [nonce (::shared/nonce packet-management)
        keydir (::keydir my-keys)]
    (shared/byte-copy! nonce shared/vouch-nonce-prefix)
    (shared/safe-nonce nonce keydir shared/client-nonce-prefix-length)

    ;; Q: What's the point to these 32 bytes?
    (shared/byte-copy! text (shared/zero-bytes 32))
    (shared/byte-copy! text shared/key-length shared/key-length (.getPublicKey (::short-pair my-keys)))
    (let [encrypted (.after (::client-long<->server-long shared-secrets) text 0 64 nonce)
          vouch (byte-array 64)]
      (shared/byte-copy! vouch
                         0
                         shared/server-nonce-suffix-length
                         nonce
                         shared/server-nonce-prefix-length)
      (shared/byte-copy! vouch
                         shared/server-nonce-suffix-length
                         48
                         encrypted
                         shared/server-nonce-suffix-length)
      ;; At this point the reference implementation pauses to fire up
      ;; its message-handling child process.
      ;; This should probably construct something like a go loop that
      ;; will occupy the same ecological niche
      (throw (RuntimeException. "Q: How should this work?"))
      (assoc this :vouch vouch))))

(defn extract-child-message
  "Pretty much blindly translated from the CurveCP reference
implementation. This is code that I don't understand yet"
  [this buffer]
  (let [reducer (fn [{:keys [buf
                             buf-len
                             msg
                             msg-len
                             i
                             this]
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
                      (let [{:keys [extension
                                    my-keys
                                    packet-management
                                    server-extension
                                    shared-secrets
                                    server-security
                                    text
                                    vouch
                                    work-area]
                             :as this} (clientextension-init this)
                            {:keys [::shared/packet
                                    ::shared/packet-nonce]} packet-management
                            _ (throw (RuntimeException. "this Component nonce isn't updated"))
                            short-term-nonce (update-client-short-term-nonce
                                              packet-nonce)
                            working-nonce (:shared/working-nonce work-area)]
                        (shared/uint64-pack! working-nonce shared/client-nonce-prefix-length
                                             short-term-nonce)
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
                          (shared/byte-copy! working-nonce 0 shared/client-nonce-prefix-length
                                             shared/initiate-nonce-prefix)
                                    ;; Reference version starts by zeroing first 32 bytes.
                                    ;; I thought we just needed 16 for the encryption buffer
                                    ;; And that doesn't really seem to apply here
                                    ;; Q: What's up with this?
                                    ;; (it doesn't seem to match the spec, either)
                                    (shared/byte-copy! text 0 32 shared/all-zeros)
                                    (shared/byte-copy! text 32 shared/key-length
                                                       (.getPublicKey (::long-pair my-keys)))
                                    (shared/byte-copy! text 64 64 vouch)
                                    (shared/byte-copy! text
                                                       128
                                                       shared/server-name-length
                                                       (::server-name server-security))
                                    ;; First byte is a magical length marker
                                    (shared/byte-copy! text 384 r msg 1)
                                    (let [box (.after (::client-short<->server-short shared-secrets)
                                                      text
                                                      0
                                                      (+ r 384)
                                                      working-nonce)]
                                      (shared/byte-copy! packet
                                                         0
                                                         shared/server-nonce-prefix-length
                                                         shared/initiate-header)
                                      (let [offset shared/server-nonce-prefix-length]
                                        (shared/byte-copy! packet offset
                                                           shared/extension-length server-extension)
                                        (let [offset (+ offset shared/extension-length)]
                                          (shared/byte-copy! packet offset
                                                             shared/extension-length extension)
                                          (let [offset (+ offset shared/extension-length)]
                                            (shared/byte-copy! packet offset shared/key-length
                                                               (.getPublicKey (::short-pair my-keys)))
                                            (let [offset (+ offset shared/key-length)]
                                              (shared/byte-copy! packet
                                                                 offset
                                                                 shared/server-cookie-length
                                                                 (::server-cookie server-security))
                                              (let [offset (+ offset shared/server-cookie-length)]
                                                (shared/byte-copy! packet offset
                                                                   shared/server-nonce-prefix-length
                                                                   working-nonce
                                                                   shared/server-nonce-suffix-length))))))
                                      ;; Actually, the original version sends off the packet, updates
                                      ;; msg-len to 0, and goes back to pulling date from child/server.
                                      (throw (ex-info "How should this really work?"
                                                      {:problem "Need to break out of loop here"})))))
                                (assoc acc :msg-len msg-len))))
        extracted (reduce reducer
                          {:buf (byte-array 4096)
                           :buf-len 0
                           :msg (byte-array 2048)
                           :msg-len 0
                           :i 0
                           :this this}
                          buffer)]
    (assoc this :outgoing-message (:child-msg extracted))))

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
  [{:keys [child-chan  ; Seems wrong. If it's a real child, should spawn it here
           my-keys
           packet-management
           server-chan
           server-extension
           server-security
           timeout]
    :or {timeout 2500}
    :as this}]
  {:pre [(and server-extension
              (::server-long-term-pk server-security))]}
  (let [server-long-term-pk (::server-long-term-pk server-security)
        recent (System/nanoTime)
        long-pair (shared/do-load-keypair (::keydir my-keys))
        short-pair (shared/random-key-pair)
        my-keys (assoc my-keys
                       ::long-pair long-pair
                       ::short-pair short-pair)
        shared-secrets (assoc (:shared-secrets this)
                              ::client-long<->server-long (shared/crypto-box-prepare
                                                                             server-long-term-pk
                                                                             (.getSecretKey short-pair))
                              ::client-short<->server-long (shared/crypto-box-prepare
                                                                              server-long-term-pk
                                                                              (.getSecretKey long-pair)))
        this (-> this
                 (assoc
                  :extension nil
                  :client-extension-load-time 0
                  :recent recent
                  :my-keys my-keys
                  :shared-secrets shared-secrets)
                 do-build-hello)]
    ;; The reference implementation mingles networking with this code.
    ;; That seems like it might make sense as an optimization,
    ;; but not until I have convincing numbers that it's needed.
    ;; Of course, I might also be opening things up for something
    ;; like a timing attack.
    (let [d (stream/put! server-chan (-> this :packet-management ::shared/packet))]
      (deferred/chain d
        (fn [sent?]
          (if sent?
            (deferred/timeout! (stream/take! server-chan) timeout ::hello-timed-out)
            ::hello-send-failed))
        (fn [cookie]
          ;; Q: What is really in cookie now?
          ;; (I think it's a netty ByteBuf)
          (let [this (assoc-in this [:packet-management ::shared/packet] cookie)]
            ;; Really just want to break out of the chain
            ;; if this returns nil.
            ;; There's no reason to try to go any further
            ;; Q: What's a good way to handle that?
            (decrypt-cookie-packet this)))
        (fn [state-with-decrypted-cookie]
          (when state-with-decrypted-cookie
            (assoc-in state-with-decrypted-cookie
                      [:shared-secrets ::client-short<->server-short]
                      (shared/crypto-box-prepare
                       (get-in state-with-decrypted-cookie [:server-security
                                                            ::server-short-term-pk])
                       (.getSecretKey (::short-pair my-keys))))))
        (fn [state-with-keyed-cookie]
          (build-vouch state-with-keyed-cookie))
        (fn [vouched-state]
          (let [future (stream/take! child-chan)
                ;; I'd like to just return that future and
                ;; handle the next pieces separately.
                ;; But then I'd lose the state that I'm
                ;; accumulating
                msg-buffer (deref future timeout ::child-timed-out)]
            (assert (and msg-buffer
                         (not= msg-buffer ::child-timed-out)))
            (let [updated (extract-child-message
                           vouched-state
                           msg-buffer)]
              (assoc updated :initiate-sent? (stream/put! server-chan (:packet updated))))))
        (fn [this]
          (let [success (deref (:initiate-sent? this) timeout ::sending-initiate-failed)]
            (if success
              (dissoc this :initiate-sent?)
              ;; TODO: Really should initiate retries
              ;; But if we failed to send the packet at all, something is badly wrong
              (throw (ex-info "Failed to send initiate" this)))))))))

(defn basic-test
  "This should probably go away"
  []
  (let [client-keys (shared/random-key-pair)
        ;; Q: Do I want to use this or TweetNaclFast/keyPair?
        server-keys (shared/random-key-pair)
        msg "Hold on, my child needs my attention"
        bs (.getBytes msg)
        nonce (byte-array [1 2 3 4 5 6 7 8 9 10
                           11 12 13 14 15 16 17
                           18 19 20 21 22 23 24])
        boxer (shared/crypto-box-prepare (.getPublicKey server-keys) (.getSecretKey client-keys))
        ;; This seems likely to get confused due to arity issues
        boxed (.box boxer bs nonce)
        unboxer (shared/crypto-box-prepare (.getPublicKey client-keys) (.getSecretKey server-keys))]
    (String. (.open unboxer boxed nonce))))
(comment (basic-test))

(defn ctor
  [opts]
  (map->State opts))
