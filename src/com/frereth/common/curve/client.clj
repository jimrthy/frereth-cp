(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [clojure.core.async :as async]
            [clojure.pprint :refer (pprint)]
            [clojure.spec :as s]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.schema :as schema]
            [com.stuartsierra.component :as cpt]
            [gloss.core :as gloss-core]
            [gloss.io :as gloss]
            [manifold.deferred :as deferred]
            ;; Mixing this and core.async seems dubious, at best
            [manifold.stream :as stream]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def heartbeat-interval (* 15 shared/millis-in-second))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(def cookie (gloss-core/compile-frame (gloss-core/ordered-map :s' (gloss-core/finite-block 32)
                                                              :black-box (gloss-core/finite-block 96))))

;; Send messages to the child process
(s/def ::chan->child ::schema/async-channel)
;; Pull messages from the child process
(s/def ::chan<-child ::schema/async-channel)
;; Note that there's a good chance that these are
;; actually instances of manifold.stream/stream.
(s/def ::chan<-server ::schema/async-channel)
(s/def ::chan->server ::schema/async-channel)

;; Periodically pull the client extension from...wherever it comes from.
;; Q: Why?
;; A: Has to do with randomizing and security, like sending from a random
;; UDP port. This will pull in updates when and if some mechanism is
;; added to implement that sort of thing.
;; Actually doing anything useful with this seems like it's probably
;; an exercise that's been left for later
(s/def ::client-extension-load-time integer?)

(s/def ::server-long-term-pk ::shared/public-key)
(s/def ::server-cookie any?)  ; TODO: Needs a real spec
(s/def ::server-short-term-pk ::shared/public-key)
(s/def ::server-security (s/keys :req [::server-long-term-pk
                                       ;; Q: Is there a valid reason for this to live here?
                                       ;; I can discard it after sending the vouch, can't I?
                                       ::server-cookie
                                       ::shared/server-name
                                       ::server-short-term-pk]))

(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-long<->server-long
                                      ::client-short<->server-long
                                      ::client-short<->server-short]))

;; Q: What is this, and how is it used?
;; A: Well, it has something to do with messages from the Child to the Server.
(s/def ::outgoing-message any?)

;; The parts that change really need to be stored in a mutable
;; data structure.
;; An agent really does seem like it was specifically designed
;; for this.
;; Parts of this mutate over time. Others advance with the handshake
;; FSM. And others are really just temporary members.
;; I could also handle this with refs, but combining STM with
;; mutable byte arrays (which is where the "real work"
;; happens) seems like a recipe for disaster.
(s/def ::mutable-state (s/keys :req-un [::client-extension-load-time
                                        ::shared/extension
                                        ::outgoing-message
                                        ::shared/packet-management
                                        ::shared/recent
                                        ::server-security
                                        ::shared-secrets
                                        ::shared/work-area]
                               :opt-un [::chan->child
                                        ::chan<-child
                                        ;; Q: Why am I tempted to store this at all?
                                        ;; A: Well...I might need to resend it if it
                                        ;; gets dropped initially.
                                        ::vouch]))
(s/def ::immutable-value (s/keys :req [::shared/my-keys
                                       ;; Q: How do these mesh with netty's pipeline model?
                                       ;; For that matter, how much sense does the idea of
                                       ;; spawning a child process here?
                                       ::chan->server
                                       ::chan<-server
                                       ::child-spawner
                                       ::server-extension]))
(s/def ::state (s/merge ::mutable-state
                       ::immutable-value))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn hide-long-arrays
  "Make pretty printing a little less verbose"
  [this]
  (-> this
      ;; TODO: Write a mirror image version of dns-encode to just show this
      (assoc-in [:server-security :server-name] "name")
      (assoc-in [:packet-management ::shared/packet] "...packet bytes...")
      (assoc-in [:work-area ::shared/working-nonce] "...FIXME: Decode nonce bytes")
      (assoc-in [:work-area ::shared/text] "...plain/cipher text")))

(defn clientextension-init
  "Starting from the assumption that this is neither performance critical
nor subject to timing attacks because it just won't be called very often."
  [{:keys [extension
           client-extension-load-time
           recent]
    :as this}]
  (assert (and client-extension-load-time recent))
  (let [reload (>= recent client-extension-load-time)
        _ (println "Reloading extension:" reload "(currently:" extension ") in"
                   #_(with-out-str (pprint (hide-long-arrays this)))
                   (keys (hide-long-arrays this)))
        client-extension-load-time (if reload
                                     (+ recent (* 30 shared/nanos-in-second)
                                        client-extension-load-time))
        extension (if reload
                    (try (-> "/etc/curvecpextension"
                             ;; This is pretty inefficient...we really only want 16 bytes.
                             ;; Should be good enough for a starting point, though
                             slurp
                             (subs 0 16)
                             .getBytes)
                         (catch java.io.FileNotFoundException _
                           (println "Missing extension file")
                           (shared/zero-bytes 16)))
                    extension)]
    (assert (= (count extension) shared/extension-length))
    (println "Loaded extension:" (vec extension))
    (assoc this
           :client-extension-load-time client-extension-load-time
           :extension extension)))

(defn update-client-short-term-nonce
  "Using a BigInt for this seems like an obnoxious performance hit.
Using a regular long seems like a recipe for getting it wrong.
Guava specifically has an unsigned long class.
TODO: Switch to that or whatever Bouncy Castle uses"
  [^Long nonce]
  (let [result (unchecked-inc nonce)]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {:must "End communication immediately"})))
    result))

(defn do-build-hello
  [{:keys [my-keys
           packet-management
           server-extension
           shared-secrets
           work-area]
    :as this}]
  (let [this (clientextension-init this)
        ;; There's a good chance this just got replaced
        extension (:extension this)
        working-nonce (::shared/working-nonce work-area)
        {:keys [::shared/packet-nonce ::shared/packet]} (:packet-management this)
        short-term-nonce (update-client-short-term-nonce packet-nonce)]
    (shared/byte-copy! working-nonce shared/hello-nonce-prefix)
    (shared/uint64-pack! working-nonce shared/client-nonce-prefix-length short-term-nonce)

    ;; This seems to be screaming for gloss.
    ;; Q: What kind of performance difference would that make?
    (shared/byte-copy! packet shared/hello-header)
    (shared/byte-copy! packet 8 shared/extension-length server-extension)
    (shared/byte-copy! packet 24 shared/extension-length extension)
    (shared/byte-copy! packet 40 shared/key-length (.getPublicKey (::short-pair my-keys)))
    ;; This is throwing an ArrayIndexOutOfBoundsException
    (shared/byte-copy! packet 72 64 shared/all-zeros)
    (shared/byte-copy! packet 136 shared/client-nonce-suffix-length
                       working-nonce
                       shared/client-nonce-prefix-length)
    (let [payload (.after (::client-short<->server-long shared-secrets) packet 144 80 working-nonce)]
      (shared/byte-copy! packet 144 80 payload)
      (assoc-in this [:packet-management ::shared/packet-nonce] short-term-nonce))))

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

(defn add-child
  [{:keys [::chan<-child
           ::child-spawner]
    :as this}]
  (let [chan->child (async/chan)
        chan<-child (child-spawner)
        child-loop (async/go
                     (loop []
                       (let [[msg ch] (async/alts! [chan<-child
                                                    (async/timeout heartbeat-interval)])]
                         (when msg
                           ;; 2 problems w/ this implementation
                           ;; 1. This needs to pull a stream of bytes,
                           ;; not individual messages
                           ;; 2. Really needs to trigger a send (-off ?)
                           ;; Since this is going to trigger i/o and
                           ;; update the nonce (along with altering
                           ;; the working area).
                           (throw (RuntimeException. "Implement")))
                         (when (or msg
                                   (not= ch chan<-child))
                           (recur))))
                     (print "Child listener exiting"))]
    (throw (Exception. "This still needs work"))))

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
      (let [pregnant (add-child this)]
        (assoc pregnant :vouch vouch)))))

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

(defn load-keys
  [my-keys]
  (let [long-pair (shared/do-load-keypair (::shared/keydir my-keys))
        short-pair (shared/random-key-pair)]
    (assoc my-keys
           ::shared/long-pair long-pair
           ::shared/short-pair short-pair)))

(defn initialize-immutable-values
  "Sets up the immutable value that will be used in tandem with the mutable agent later"
  [this]
  ;; In theory, it seems like it would make sense to -> this through a chain of
  ;; these sorts of initializers.
  ;; In practice, as it stands, it seems a little silly.
  (update this ::shared/my-keys
          load-keys (::shared/my-keys this)))

(defn initialize-mutable-state!
  [{:keys [::shared/my-keys
           ::server-security]}]
  {:pre [(::server-long-term-pk server-security)]}
  (let [server-long-term-pk (::server-long-term-pk server-security)
        long-pair (::long-pair my-keys)
        short-pair (::short-pair my-keys)]
    {::client-extension-load-time 0
     ::recent (System/nanoTime)
     ;; This seems like something that we should be able to set here.
     ;; djb's docs say that it's a security matter, like connecting from a
     ;; random port.
     ;; Hopefully, someday, operating systems will have some mechanism for
     ;; rotating these automatically
     ;; Q: Is this really better than just picking something random here?
     ;; A: Who am I to argue with an expert?
     ::server-security server-security
     ::shared/extension nil
     ::shared-secrets {::client-long<->server-long (shared/crypto-box-prepare
                                                    server-long-term-pk
                                                    (.getSecretKey short-pair))
                       ::client-short<->server-long (shared/crypto-box-prepare
                                                     server-long-term-pk
                                                     (.getSecretKey long-pair))}}))

(defn child-exited!
  [this]
  ::child-exited)

(defn server-closed!
  "This seems pretty meaningless in a UDP context"
  [this]
  ::server-closed)

(s/fdef register-closing-handlers!
        :args (s/cat :this #(instance? clojure.lang.Agent %))
        :ret nil?)
(defn register-closing-handlers-obsolete!
 [this]
 (let [{:keys [::chan<-child  ; TODO: Register this after we create it
               ::chan<-server]} (deref this)]
   (stream/on-drained chan<-child #(send this child-exited!))
   ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

;; Important note:
;; The reference implementation actually loops over several servers
;; so we can rapidly pick the first that responds.
;; This is one of the selling points over TCP, where a connection
;; failure might require 3 minutes to fall back to the backup.
(defn start-handshake!
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
  [{:keys [chan<-child  ; Seems wrong for caller to supply these. If it's a real child, should spawn it here
           chan->child
           my-keys
           packet-management
           chan<-server
           chan->server
           server-extension
           server-security
           timeout]
    :or {timeout 2500}
    :as this}]
  {:pre [server-extension]}
  (let [this (do-build-hello this)]
    (println "Hello built")
    ;; The reference implementation mingles networking with this code.
    ;; That seems like it might make sense as an optimization,
    ;; but not until I have convincing numbers that it's needed.
    ;; Of course, I might also be opening things up for something
    ;; like a timing attack.
    (let [packet (-> this :packet-management ::shared/packet)
          _ (println "Putting" packet "onto" chan->server)
          d (stream/put! chan->server packet)]
      (deferred/chain d
        (fn [sent?]
          (if sent?
            (deferred/timeout! (stream/take! chan<-server) timeout ::hello-timed-out)
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
          (let [future (stream/take! chan<-child)
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
              (assoc updated :initiate-sent? (stream/put! chan->server (:packet updated))))))
        (fn [this]
          (let [success (deref (:initiate-sent? this) timeout ::sending-initiate-failed)]
            (if success
              (dissoc this :initiate-sent?)
              ;; TODO: Really should initiate retries
              ;; But if we failed to send the packet at all, something is badly wrong
              (throw (ex-info "Failed to send initiate" this)))))))))

(defn start!
  "This almost seems like it belongs in ctor.

But not quite, since it's really a side-effect that sets up another.

Q: Is there something equivalent I can set up using core.async?

For that matter, it seems like setting up a watch on an atom that's
specifically for something like this might make a lot more sense.

That way I wouldn't be trying to multi-purpose communications channels.

OTOH, they *are* the trigger for this sort of thing."
  [{:keys [::chan<-server]
    :as this}]
  (stream/on-drained chan<-server #(send this server-closed!)))

(s/fdef ctor
        :args (s/keys :req [::chan<-server
                            ::shared/my-keys
                            ::server-security])
        :ret (s/and #(instance? clojure.lang.Agent %)
                    #(s/valid? ::state (deref %))))
(defn ctor
  [opts]
  (-> (initialize-immutable-values opts)
      (initialize-mutable-state!)
      (assoc
       ;; This seems very cheese-ball, but they
       ;; *do* need to be part of the agent.
       ;; We definitely don't want multiple threads
       ;; messing with them
       ::shared/packet-manager (shared/default-packet-manager)
       ::shared/work-area (shared/default-work-area))
      agent))
