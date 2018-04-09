(ns frereth-cp.client.state
  "Handle the inherently stateful pieces associated with the client side of things.

The fact that this is so big says a lot about needing to re-think my approach"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message :as message]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as util]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(set! *warn-on-reflection* true)

(def default-timeout 2500)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::msg-bytes bytes?)

;; Q: Do these make sense?
;; Realistically, this is how we should be communicating with aleph.
;; Although it might be worth dropping down to a lower-level approach
;; for the sake of netty.
(s/def ::chan->server strm/sinkable?)
(s/def ::chan<-server strm/sourceable?)

;; Periodically pull the client extension from...wherever it comes from.
;; Q: Why?
;; A: Has to do with randomizing and security, like sending from a random
;; UDP port. This will pull in updates when and if some mechanism is
;; added to implement that sort of thing.
;; Actually doing anything useful with this seems like it's probably
;; an exercise that's been left for later
(s/def ::client-extension-load-time nat-int?)

(s/def ::server-extension ::shared/extension)
;; TODO: Needs a real spec
;; Q: Is this the box that we decrypted with the server's
;; short-term public key?
;; Or is it the 96-byte black box that we send back as part of
;; the Vouch?
(s/def ::server-cookie any?)
(s/def ::server-security (s/merge ::specs/peer-keys
                                  (s/keys :req [::specs/srvr-name
                                                ::shared/srvr-port]
                                          ;; Q: Is there a valid reason for this to live here?
                                          ;; Q: I can discard it after sending the vouch, can't I?
                                          ;; A: Yes.
                                          ;; Q: Do I want to?
                                          ;; A: Well...keeping it seems like a potential security hole
                                          ;; TODO: Make it go away
                                          :opt [::server-cookie])))

(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-long<->server-long
                                      ::client-short<->server-long
                                      ::client-short<->server-short]))

;; Q: What is this, and how is it used?
;; A: Well, it has something to do with messages from the Child to the Server.
;; c.f. client/extract-child-message
(s/def ::outgoing-message any?)

;; The circular reference involved here is a red flag.
;; ::state-agent depends on ::state depends on ::mutable-state depends on ::packet-builder
;; This seems like the best option available in a bad situation, but just
;; using a boolean flag and an if check might be better.
(s/def ::packet-builder (s/fspec :args (s/cat :wrapper ::state-agent
                                              :msg-packet bytes?)
                                 :ret ::msg-specs/buf))

;; Because, for now, I need somewhere to hang onto the future
;; Q: So...what is this? a Future?
(s/def ::child any?)

;; The parts that change really need to be stored in a mutable
;; data structure.
;; An agent really does seem like it was specifically designed
;; for this.
;; Parts of this mutate over time. Others advance with the handshake
;; FSM. And others are really just temporary members.
;; I could also handle this with refs, but combining STM with
;; mutable byte arrays (which is where the "real work"
;; happens) seems like a recipe for disaster.
(s/def ::mutable-state (s/keys :req [::client-extension-load-time  ; not really mutable
                                     ;; This isn't mutable
                                     ;; Q: Is it?
                                     ::shared/extension
                                     ::log2/logger
                                     ;; If we track ::msg-specs/state here,
                                     ;; then ::log2/state is, honestly, redundant.
                                     ;; Except that trying to keep them synchronized
                                     ;; is a path to madness, as is tracking
                                     ;; a snapshot of ::msg-specs/state.
                                     ::log2/state
                                     ;; Q: Does this really make any sense?
                                     ;; A: Not in any sane reality.
                                     ::outgoing-message
                                     ::packet-builder
                                     ::shared/packet-management
                                     ::msg-specs/recent
                                     ;; The only thing mutable about this is that I don't have it all in beginning
                                     ::server-security
                                     ;; The only thing mutable about this is that I don't have it all in beginning
                                     ::shared-secrets
                                     ;; FIXME: Tracking this here doesn't really make
                                     ;; any sense at all.
                                     ;; It's really a member variable of the IOLoop
                                     ;; class.
                                     ;; Which seems like an awful way to think about
                                     ;; it, but it's pretty inherently stateful.
                                     ;; At least in the sense that it changes after
                                     ;; pretty much every event through the ioloop.
                                     ;; So maybe it's more like there's a monad in
                                     ;; there that tracks this secretly.
                                     ;; Whatever. It doesn't really make any
                                     ;; sense here.
                                     ;; FIXME: Make it go away.
                                     ::msg-specs/state
                                     ::shared/work-area]
                               :opt [::child
                                     ::specs/io-handle
                                     ;; Q: Why am I tempted to store this at all?
                                     ;; A: Well...I might need to resend it if it
                                     ;; gets dropped initially.
                                     ::vouch]))
(s/def ::immutable-value (s/keys :req [::msg-specs/->child
                                       ::shared/my-keys
                                       ::msg-specs/message-loop-name
                                       ;; UDP packets arrive over this
                                       ::chan<-server
                                       ::server-extension
                                       ::timeout]
                                 ;; This isn't optional as much
                                 ;; as it's just something that isn't
                                 ;; around for the initial creation.
                                 ;; We're responsible for creating
                                 ;; and releasing it, since we're in
                                 ;; control of putting messages into its
                                 ;; source.
                                 ;; This is in direct contrast to
                                 ;; ::chan<-server
                                 :opt [::chan->server]))
(s/def ::state (s/merge ::mutable-state
                        ::immutable-value))

;;; Using an agent here seems like a dubious choice.
;;; After all, they're slow.
;;; But it makes sense for in initial pass:
;;; We have a messaging layer that processes data streams
;;; of data to/from a child. That layer interacts with a
;;; single Client instance, which handles the cryptography
;;; and actual network communication.
;;; We could probably do what we need via atoms, except that
;;; those are for managing state and really should not trigger
;;; side-effects.
;;; Using something like core.async or manifold.streams
;;; is probably "the" proper way to go here. Especially
;;; since, realistically, we want multiple clients speaking
;;; with multiple servers. And it's perfectly reasonable
;;; to expect a single "child" to contact multiple servers.
;;; Actually, that latter point makes this architecture seem
;;; inside-out.
;;; Stick with this for now, but keep in mind that it probably
;;; should change.
(s/def ::state-agent (s/and #(instance? clojure.lang.Agent %)
                            #(s/valid? ::state (deref %))))

(s/def ::child-spawner! (s/fspec :args (s/cat :state-agent ::state-agent)
                                 :ret (s/keys :req [::log2/state
                                                    ::msg-specs/io-handle])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Implementation
;;; Q: How many (if any) of these really belong in here?

;;; Q: Does this really make sense here rather than client.cookie?
(defn decrypt-actual-cookie
  [{:keys [::shared/packet
           ;; Having a shared work-area is probably
           ;; important for avoiding GC.
           ;; At the same time, the mutable state
           ;; causes a lot of trouble.
           ;; Q: Is it worth it?
           ;; A: Need benchmarks!
           ::shared/work-area
           ::server-security
           ::shared-secrets]
    log-state ::log2/state
    :as this}
   {:keys [::K/header
           ::K/client-extension
           ::K/server-extension]
    ^bytes client-nonce-suffix ::K/client-nonce-suffix
    ^bytes cookie ::K/cookie
    :as rcvd}]
  (let [log-state (log2/info log-state
                             ::decrypt-actual-cookie
                             "Getting ready to try to extract cookie"
                             {::raw-cookie cookie
                              ::human-readable (shared/bytes->string cookie)})
        {^bytes text ::shared/text
         ^bytes working-nonce ::shared/working-nonce} work-area]
    (assert working-nonce (str "Missing nonce buffer amongst\n"
                               (keys work-area)
                               "\nin\n"
                               (keys this)))
    (let [log-state (log2/info log-state
                               ::decrypt-actual-cookie
                               "Copying nonce prefix"
                               {::src K/cookie-nonce-prefix
                                ::dst working-nonce})]
      (b-t/byte-copy! working-nonce K/cookie-nonce-prefix)
      (b-t/byte-copy! working-nonce K/server-nonce-prefix-length K/server-nonce-suffix-length client-nonce-suffix)
      (let [log-state (log2/info log-state
                                 ::decrypt-actual-cookie
                                 "Copying encrypted cookie"
                                 {::target text
                                  ::this this
                                  ::my-keys (keys this)})]
        (b-t/byte-copy! text 0 K/cookie-frame-length cookie)
        (let [shared (::client-short<->server-long shared-secrets)
              log-state (log2/info log-state
                                   ::decrypt-actual-cookie
                                   "Trying to decrypt"
                                   {::shared/text  (b-s/print-bytes text)
                                    ::shared/working-nonce (b-s/print-bytes working-nonce)
                                    ::client-short<->server-long (b-s/print-bytes shared)})]
          ;; TODO: If/when an exception is thrown here, it would be nice
          ;; to notify callers immediately
          (try
            (let [{log-state ::log2/state
                   decrypted ::crypto/unboxed} (crypto/open-after log-state text 0 144 working-nonce shared)
                  {server-short-pk ::K/s'
                   server-cookie ::K/black-box
                   :as extracted} (serial/decompose K/cookie decrypted)
                  server-security (assoc (::server-security this)
                                         ::specs/public-short server-short-pk,
                                         ::server-cookie server-cookie)]
              (assoc this
                     ::server-security server-security
                     ::log2/state log-state))
            (catch ExceptionInfo ex
              (assoc this
                     ::log2/state (log2/exception log-state
                                                  ex
                                                  ::decrypt-actual-cookie
                                                  "Decryption failed"
                                                  (.getData ex))))))))))

(defn decrypt-cookie-packet
  [{:keys [::shared/extension
           ::shared/packet
           ::server-extension]
    log-state ::log2/state
    :as this}]
  (when-not (= (count packet) K/cookie-packet-length)
    (let [err {::expected-length K/cookie-packet-length
               ::actual-length (count packet)
               ::packet packet
               ;; Because the stack trace hides
               ::where 'shared.curve.client/decrypt-cookie-packet}]
      (throw (ex-info "Incoming cookie packet illegal" err))))
  (let [log-state (log2/debug log-state
                              ::decrypt-cookie-packet
                              "Incoming packet that looks like it might be a cookie"
                              {::raw-packet packet
                               ::human-readable (shared/bytes->string packet)})
        {:keys [::K/header
                ::K/client-extension
                ::K/server-extension]
         :as rcvd} (serial/decompose-array K/cookie-frame packet)
        log-state (log2/info log-state
                             ::decrypt-cookie-packet
                             "Verifying that decrypted packet looks like a Cookie"
                             {::raw-header header
                              ::human-readable (shared/bytes->string header)})]
    ;; Q: How accurate/useful is this approach?
    ;; (i.e. mostly comparing byte array hashes)
    ;; A: Not at all.
    ;; Well, it's slightly better than nothing.
    ;; But it's trivial to forge.
    ;; Q: How does the reference implementation handle this?
    ;; Well, the proof *is* in the pudding.
    ;; The most important point is whether the other side sent
    ;; us a cookie we can decrypt using our shared key.
    (when (and (b-t/bytes= K/cookie-header header)
               (b-t/bytes= extension client-extension)
               (b-t/bytes= server-extension server-extension))
      (decrypt-actual-cookie (assoc this
                                    ::log2/state log-state)
                             rcvd))))

(s/fdef build-vouch
  :args (s/cat :this ::state)
  :ret (s/keys :req [::inner-i-nonce
                     ::log2/state
                     ::vouch]))
(defn build-vouch
  [{:keys [::shared/packet-management
           ::shared/my-keys
           ::shared-secrets
           ::shared/work-area]
    log-state ::log2/state
    :as this}]
  (let [{:keys [::shared/working-nonce
                ::shared/text]} work-area
        keydir (::shared/keydir my-keys)
        nonce-suffix (byte-array K/server-nonce-suffix-length)]
    (if working-nonce
      (let [log-state (log2/info log-state
                                 ::build-vouch
                                 "Setting up working nonce"
                                 {::shared/working-nonce working-nonce})]
        (b-t/byte-copy! working-nonce K/vouch-nonce-prefix)
        (if keydir
          (crypto/safe-nonce! working-nonce keydir K/server-nonce-prefix-length false)
          (crypto/safe-nonce! working-nonce K/server-nonce-prefix-length))

        (let [^TweetNaclFast$Box$KeyPair short-pair (::shared/short-pair my-keys)]
          (b-t/byte-copy! text 0 K/key-length (.getPublicKey short-pair)))
        (let [shared-secret (::client-long<->server-long shared-secrets)
              ;; This is the inner-most secret that the inner vouch hides.
              ;; I think the main point is to allow the server to verify
              ;; that whoever sent this packet truly has access to the
              ;; secret keys associated with both the long-term and short-
              ;; term key's we're claiming for this session.
              encrypted (crypto/box-after shared-secret
                                          text K/key-length working-nonce)
              vouch (byte-array K/vouch-length)
              log-state (log2/info log-state
                                   ::build-vouch
                                   (str "Just encrypted the inner-most portion of the Initiate's Vouch\n"
                                        "(FIXME: Don't log the shared secret)")
                                   {::shared/working-nonce (b-t/->string working-nonce)
                                    ::shared-secret (b-t/->string shared-secret)})]
          (b-t/byte-copy! vouch
                          0
                          (+ K/box-zero-bytes K/key-length)
                          encrypted)
          {::inner-i-nonce nonce-suffix
           ::log2/state log-state
           ::vouch vouch}))
      (assert false (str "Missing nonce in packet-management:\n"
                         (keys packet-management))))))

(s/fdef cookie->vouch
        :args (s/cat :this ::state
                     :packet ::shared/network-packet)
        :ret ::state)
(defn cookie->vouch
  "Got a cookie from the server.

  Replace those bytes
  in our packet buffer with the vouch bytes we'll use
  as the response.

  Q: How much of a performance hit (if any) am I looking at if I
  make this purely functional instead?"
  [{log-state ::log2/state
    :as this} ; Handling an agent (send), which means `this` is already dereferenced
   {:keys [:host :port]
    ^bytes message :message
    :as cookie-packet}]
  {:pre [cookie-packet]}
  (let [log-state (log2/info log-state
                             ::cookie->vouch
                             "Getting ready to convert cookie into a Vouch"
                             {::raw-cookie message
                              ::human-readable (b-s/print-bytes message)})]
    (if-let [decrypted (decrypt-cookie-packet (assoc (select-keys this
                                                                  [::shared/extension
                                                                   ::shared/work-area
                                                                   ::server-extension
                                                                   ::server-security
                                                                   ::shared-secrets])
                                                     ::log2/state log-state
                                                     ::shared/packet message))]
      (let [this (into this decrypted)
            {:keys [::shared/my-keys]} this
            server-short (get-in this
                                 [::server-security
                                  ::specs/public-short])
            log-state (log2/debug log-state
                                  ::cookie->vouch
                                  "Managed to decrypt the cookie")]
        ;; Next step for reference implementation is to compare the
        ;; server IP and port vs. what we received.
        ;; That info's pretty unreliable/meaningless, but the server
        ;; address probably won't change very often.
        ;; Unless we're communicating with a server on someone's cell
        ;; phone.
        ;; Which, if this is successful, will totally happen.
        ;; FIXME: Verify that
        (assert server-short (str "Missing ::specs/public-short among\n"
                                  (keys (::server-security this))
                                  "\namong bigger-picture\n"
                                  (keys this)))
        (let [^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
              this (assoc-in this
                             [::shared-secrets ::client-short<->server-short]
                             (crypto/box-prepare
                              server-short
                              (.getSecretKey my-short-pair)))
              log-state (log2/debug log-state
                                    ::cookie->vouch
                                    "Prepared shared short-term secret")]
          ;; Note that this supplies new state
          ;; Though whether it should is debatable.
          ;; Q: why would I put this into ::vouch?
          ;; A: In case we need to resend it.
          ;; It's perfectly legal to send as many Initiate
          ;; packets as the client chooses.
          ;; This is especially important before the Server
          ;; has responded with its first Message so the client
          ;; can switch to sending those.
          (into this (build-vouch (assoc this
                                         ::log2/state log-state)))))
      (throw (ex-info
              "Unable to decrypt server cookie"
              (assoc this ::log2/state log-state))))))

(s/fdef load-keys
        :args (s/cat :logger ::log2/state
                     :my-keys ::shared/my-keys)
        :ret (s/keys :req [::log2/state
                           ::shared/my-keys]))
(defn load-keys
  [log-state my-keys]
  (let [key-dir (::shared/keydir my-keys)
        long-pair (crypto/do-load-keypair key-dir)
        short-pair (crypto/random-key-pair)
        log-state (log2/info log-state
                             ::load-keys
                             "Loaded leng-term client key pair"
                             {::shared/keydir key-dir})]
    {::shared/my-keys (assoc my-keys
                             ::shared/long-pair long-pair
                             ::shared/short-pair short-pair)
     ::log2/state log-state}))

(s/fdef initialize-immutable-values
        :args (s/cat :this ::immutable-value
                     :log-initializer (s/fspec :args (s/cat)
                                               :ret ::log2/logger))
        :ret ::immutable-value)
(defn initialize-immutable-values
  "Sets up the immutable value that will be used in tandem with the mutable agent later"
  [{:keys [::msg-specs/message-loop-name
           ::server-extension
           ::chan<-server]
    log-state ::log2/state
    :as this}
   log-initializer]
  {:pre [message-loop-name
         server-extension]}
  (when-not chan<-server
    (throw (ex-info "Missing channel from server"
                    {::keys (keys this)
                     ::big-picture this})))
  (let [logger (log-initializer)]
    (-> this
        (assoc ::log2/logger logger)
        (assoc ::chan->server (strm/stream))
        ;; Can't do this: it involves a circular import
        #_(assoc ::packet-builder initiate/build-initiate-packet!)
        ;; FIXME: This is a cheeseball way to do this.
        ;; Honestly, to follow the "proper" (i.e. established)
        ;; pattern, load-keys should just operate on the full
        ;; ::state map.
        ;; OTOH, I've gotten pretty fierce about how this is a
        ;; terrible approach, and there's no time like the present
        ;; to mend my ways.
        ;; So maybe this is exactly what I want after all.
        (into (load-keys log-state (::shared/my-keys this))))))

(s/fdef initialize-mutable-state!
        :args (s/cat :this ::mutable-state)
        :ret ::mutable-state)
(defn initialize-mutable-state!
  [{:keys [::shared/my-keys
           ::server-security
           ::log2/logger
           ::msg-specs/message-loop-name]
    :as this}]
  (let [log-state (log2/init message-loop-name)
        server-long-term-pk (::specs/public-long server-security)]
    (when-not server-long-term-pk
      (throw (ex-info (str "Missing ::specs/public-long among"
                           (keys server-security))
                      {::have server-security})))
    (let [^TweetNaclFast$Box$KeyPair long-pair (::shared/long-pair my-keys)
          ^TweetNaclFast$Box$KeyPair short-pair (::shared/short-pair my-keys)
          long-shared  (crypto/box-prepare
                        server-long-term-pk
                        (.getSecretKey long-pair))
          log-state (log2/info log-state
                               ::initialize-mutable-state!
                               "Combined keys"
                               {::srvr-long-pk (b-t/->string server-long-term-pk)
                                ::my-long-pk (b-t/->string (.getPublicKey long-pair))
                                ::shared-key (b-t/->string long-shared)})]
      (into this
            {::child-packets []
             ::client-extension-load-time 0
             ::msg-specs/recent (System/nanoTime)
             ;; This seems like something that we should be able to set here.
             ;; djb's docs say that it's a security matter, like connecting
             ;; from a random port.
             ;; Hopefully, someday, operating systems will have some mechanism
             ;; for rotating these automatically
             ;; Q: Is nil really better than just picking something random
             ;; here?
             ;; A: Who am I to argue with one of the experts?
             ::shared/extension nil
             ::shared-secrets {::client-long<->server-long long-shared
                               ::client-short<->server-long (crypto/box-prepare
                                                             server-long-term-pk
                                                             (.getSecretKey short-pair))}
             ::server-security server-security
             ::log2/state log-state}))))

(defn ->message-exchange-mode
  "Just received first real response Message packet from the handshake.
  Now we can start doing something interesting."
  [{:keys [::chan<-server
           ::chan->server
           ::msg-specs/->child]
    :as this}
   wrapper
   initial-server-response]
  ;; Q: Does this function make any sense at all?
  ;; Up until now, we've been funneling messages from the child through
  ;; Initiate packets. Now we can extend that to full-blown Message
  ;; packets.
  ;; And we had a special state flag waiting for the first response back
  ;; from the server, which we've just received.
  ;; So yes. Special things do happen here/now.
  ;; That doesn't mean that any of those special things fit with what
  ;; I've been trying so far.
  (log/warn "->message-exchange-mode deprecated")
  ;; I'm getting an ::interaction-test/timeout here
  (log/info "Initial Response from server:\n" initial-server-response)
  (if (not (keyword? (:message initial-server-response)))
    (if (and ->child chan->server)
      (do
        ;; Q: Do I want to block this thread for this?
        ;; A: As written, we can't. We're already inside an Agent$Action
        (comment (await-for (state/current-timeout wrapper) wrapper))

        ;; Need to wire this up to pretty much just pass messages through
        ;; Actually, this seems totally broken from any angle, since we need
        ;; to handle encryption, at a minimum. (Q: Don't we?)

        (strm/consume (fn [msg]
                        ;; as-written, we have to unwrap the message
                        ;; bytes for the stream from the message
                        ;; packet.
                        #_(send wrapper chan->child %)
                        (->child (:message msg))
                        ;; Q: Is this approach better?
                        ;; A: Well, at least it isn't total nonsense like what I wrote originally
                        #_(send-off wrapper (fn [state]
                                            (let [a
                                                  (update state ::child-packets
                                                          conj {:message msg})]
                                              ;; Well...what did I have planned for this?
                                              #_(send-messages! a)
                                              (throw (RuntimeException. "Well, it's still mostly nonsense"))))))
                      chan<-server))
      (throw (ex-info (str "Missing either/both chan<-child and/or chan->server amongst\n" @this)
                      {::state this})))
    (log/warn "That response to Initiate was a failure")))

(declare current-timeout)
(defn final-wait
  "We've received the cookie and responded with a vouch.
  Now waiting for the server's first real message
  packet so we can switch into the message exchange
  loop"
  [{:keys [::log2/logger]
    log-state ::log2/state
    :as this} wrapper sent]
  (log2/flush-logs! logger
                    (log2/warn log-state
                               ::final-wait
                               "Entering [penultimate] final-wait"))
  (if (not= sent ::sending-vouch-timed-out)
    (let [timeout (current-timeout wrapper)
          chan<-server (::chan<-server this)
          taken (strm/try-take! chan<-server
                                ::drained timeout
                                ::initial-response-timed-out)]
      ;; I have some comment rot here.
      ;; Big Q: Is the comment about waiting for the client's response
      ;; below correct? (The code doesn't look like it, but the behavior I'm
      ;; seeing implies a bug)
      ;; Or is the docstring above?
      (dfrd/on-realized taken
        ;; Using send-off here because it potentially has to block to wait
        ;; for the child's initial message.
        ;; That really should have been ready to go quite a while before,
        ;; but "should" is a bad word.
        #(send-off wrapper (partial ->message-exchange-mode wrapper) %)
        (fn [ex]
          (send wrapper #(throw (ex-info "Server vouch response failed"
                                         (assoc % :problem ex)))))))
    (send wrapper #(throw (ex-info "Timed out trying to send vouch" %)))))

;;; This namespace is too big, and I hate to add this next
;;; function to it.
;;; But there's a circular reference if I try to
;;; add it anywhere else.
;;; fork! needs access to it, while it needs access
;;; to the ::state-agent spec.
;;; Which is a strong argument for refactoring specs like
;;; that into their own namespace.
(s/fdef child->
        :args (s/cat :wrapper ::state-agent
                     :message bytes?)
        ;; Q: What does this return?
        ;; Note that it's called from the child.
        ;; So we really can't count on anything safe happening
        ;; with the return value.
        ;; Although in this case the "child" is the message ioloop,
        ;; so we can couple it as tightly as we like
        :ret dfrd/deferrable?)
(defn child->
  "Handle packets streaming out of child"
  [wrapper
   ^bytes message-block]
  (let [{log-state ::log2/state
         :keys [::chan->server
                ::log2/logger
                ::msg-specs/io-handle
                ::packet-builder
                ::server-security]
         :as state} @wrapper
        {:keys [::specs/srvr-name ::shared/srvr-port]} server-security]
    ;; This flag is stored in the child state.
    ;; I can retrieve that from the io-handle, but that's
    ;; terribly inefficient.
    ;; I could update the API here. Just have the child indicate
    ;; whether it's received a packet back from the server or not.
    ;; That seems like a mistake, but it's probably my simplest
    ;; option.
    ;; Or I could track the basic fact in here.
    ;; That violates DRY, and makes everything more error prone.
    ;; I could totally see a race condition where a packet
    ;; arrives, gets dispatched to the child, and the child starts
    ;; sending back bigger message blocks before the agent here
    ;; has been notified that it needs to switch to sending Message
    ;; packets rather than Initiate ones.
    ;; The reference implementation maintains this flag in both places.
    ;; It just avoids the possibility of race conditions by running
    ;; in a single thread.

    ;; N.B. What gets built very much depends on the current connection
    ;; state.
    ;; According to the spec, the child can send as many Initiate packets as
    ;; it likes, whenever it wants.
    ;; In general, it should only send them up until the point that we
    ;; receive the server's first message packet in response.
    ;; FIXME: When the child receives its first response packet from the
    ;; server (this will be a Message in response to a Vouch), we need to
    ;; swap packet-builder from initiate/build-initiate-packet! to
    ;; some function that I don't think I've written yet that should
    ;; live in client.message.
    (let [message-packet (packet-builder wrapper message-block)
          bundle {:host srvr-name
                  :port srvr-port
                  :message message-packet}
          result (strm/put! chan->server bundle)
          msg-log-state-atom (::log2/state-atom io-handle)
          ;; Actually, this would be a good time to use refs inside a
          ;; transaction.
          [my-log-state msg-log-state] (log2/synchronize log-state @msg-log-state-atom)]
      (send wrapper #(update % ::log2/state
                             (fn [log-sate]
                               (log2/flush-logs! logger log-state))))
      (swap! msg-log-state-atom update ::log2/lamport max (::log2/lamport msg-log-state))
      result)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn current-timeout
  "How long should next step wait before giving up?"
  [wrapper]
  (-> wrapper deref ::timeout
      (or default-timeout)))

(s/fdef clientextension-init
        :args (s/cat :this ::state)
        :ret ::state)
(defn clientextension-init
  ""
  ;; Started from the assumptions that this is neither
  ;; a) performance critical nor
  ;; b)  subject to timing attacks
  ;; because it just won't be called very often.
  ;; Those assumptions are false. This actually gets called
  ;; before pretty much every packet that gets sent.
  ;; However: it only does the reload once every 30 seconds.
  [{:keys [::client-extension-load-time
           ::log2/logger
           ::msg-specs/recent
           ::shared/extension]
    log-state ::log2/state
    :as this}]
  {:pre [(and client-extension-load-time recent)]}
  (let [reload? (>= recent client-extension-load-time)
        log-state (log2/debug log-state
                              ::clientextension-init
                              ""
                              {::reload? reload?
                               ::shared/extension extension
                               ::this this})
        client-extension-load-time (if reload?
                                     (+ recent (* 30 shared/nanos-in-second)
                                        client-extension-load-time))
        extension (if reload?
                    (try (-> "/etc/curvecpextension"
                             ;; This is pretty inefficient...we really only want 16 bytes.
                             ;; Should be good enough for a starting point, though
                             slurp
                             (subs 0 16)
                             .getBytes)
                         (catch java.io.FileNotFoundException _
                           ;; This really isn't all that unexpected
                           ;; The original goal/dream was to get CurveCP
                           ;; added as a standard part of every operating
                           ;; system's network stack
                           (log2/flush-logs! logger (log2/warn (log2/clean-fork log-state
                                                                                ::clientextension-init)
                                                               ::clientextension-init
                                                               "no /etc/curvecpextension file"))
                           (K/zero-bytes 16)))
                    extension)]
    (assert (= (count extension) K/extension-length))
    (log/info "Loaded extension:" (vec extension))
    (assoc this
           ::client-extension-load-time client-extension-load-time
           ::shared/extension extension)))

(s/fdef fork!
        :args (s/cat :wrapper ::state-agent)
        :ret ::state)
(defn fork!
  "This has to 'fork' a child with access to the agent, and update the agent state

So, yes, it *is* weird.

It happens in the agent processing thread pool, during a send operation.

Although send-off might seem more appropriate, it probably isn't.

TODO: Need to ask around about that.

Bigger TODO: This really should be identical to the server implementation.

Which at least implies that the agent approach should go away."
  [{:keys [::msg-specs/->child
           ::log2/logger
           ::msg-specs/message-loop-name]
    initial-msg-state ::msg-specs/state
    log-state ::log2/state
    :as this}
   wrapper]
  {:pre [message-loop-name]}
  (when-not log-state
    (throw (ex-info (str "Missing log state among "
                         (keys this))
                    this)))
  (let [log-state (log2/info log-state ::fork! "Spawning child!!")
        child (message/initial-state message-loop-name
                                     false
                                     (assoc initial-msg-state
                                            ::log2/state log-state)
                                     logger)
        {:keys [::msg-specs/io-handle]
         log-state ::log2/state} (message/start! child
                                                 logger
                                                 (partial child-> wrapper)
                                                 ->child)]
    (let [log-state (log2/debug log-state
                               ::fork!
                               "Child spawned"
                               {::this (dissoc this ::log2/state)
                                ::child (dissoc child ::log2/state)})]
      ;; Q: Do these all *really* belong at the top level?
      ;; I'm torn between the basic fact that flat data structures
      ;; are easier (simpler?) and the fact that namespacing this
      ;; sort of thing makes collisions much less likely.
      ;; Not to mention the whole "What did I mean for this thing
      ;; to be?" question.
      (assoc this
             ::child child
             ::log2/state (log2/flush-logs! logger log-state)
             ::msg-specs/io-handle io-handle))))

(defn send-vouch!
  "Send a Vouch/Initiate packet (along with a Message sub-packet)"
  ;; We may have to send this multiple times, because it could
  ;; very well get dropped.

  ;; Actually, if that happens, we probably need to start over
  ;; from the initial HELLO.

  ;; Depending on how much time we want to spend waiting for the
  ;; initial server message
  ;; (this is one of the big reasons the
  ;; reference implementation starts out trying to contact
  ;; multiple servers).

  ;; It would be very easy to just wait
  ;; for its minute key to definitely time out, though that seems
  ;; like a naive approach with a terrible user experience.
  [{log-state ::log2/state
    :keys [::chan->server
           ::log2/logger]
    packet ::vouch
    :as this}
   wrapper]
  ;; Q: Does it make any sense for this to be different than sending
  ;; any other packet?
  ;; A: No, not really.
  (let [log-state (log2/warn log-state
                             ::send-vouch!
                             "Unify client packet sending")
        d (strm/try-put!
           chan->server
           packet
           (current-timeout wrapper)
           ::sending-vouch-timed-out)]
    ;; Note that this returns a deferred.
    ;; We're inside an agent's send.
    ;; Mixing these two paradigms was a bad idea.
    (dfrd/on-realized d
                      (fn [success]
                        (log2/flush-logs! logger
                                          (log2/info log-state
                                                     ::send-vouch!
                                                     "Initiate packet sent.\nWaiting for 1st message"
                                                     {::success success}))
                        (send-off wrapper final-wait wrapper success))
                      (fn [failure]
                        ;; Extremely unlikely, but
                        ;; just for the sake of paranoia
                        (log2/flush-logs! logger
                                          (log2/exception log-state
                                                          ;; Q: Am I absolutely positive that this will
                                                          ;; always be an exception?
                                                          ;; A: Even if it isn't the logger needs to be
                                                          ;; able to cope with other problems
                                                          failure
                                                          ::send-vouch!
                                                          "Sending Initiate packet failed!"
                                                          {::problem failure}))
                        (throw (ex-info "Timed out sending cookie->vouch response"
                                        (assoc this
                                               :problem failure)))))
    ;; Q: Do I need to hang onto that?
    this))

(defn update-client-short-term-nonce
  "Note that this can loop right back to a negative number."
  [^Long nonce]
  (let [result (unchecked-inc nonce)]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {:must "End communication immediately"})))
    result))

(comment
  (defn wait-for-initial-child-bytes
    [{reader ::chan<-child
      log-state ::log2/state
      :as this}]
    ;; Really need to wait for child callback instead.
    ;; Which really means no waiting.
    ;; Q: Right?
    (throw (RuntimeException. "Deprecated approach"))
    (let [log-state (log2/info log-state
                               ::wait-for-initial-child-bytes
                               "Top"
                               ;; The redundant data seems weird, but sometimes these
                               ;; things look different
                               {::chan<-child reader
                                ::aka (str reader)})])
    (when-not reader
      (throw (ex-info "Missing chan<-child" {::keys (keys this)})))

    ;; The timeout here is a vital detail here, in terms of
    ;; UX responsiveness.
    ;; Half a second seems far too long for the child to
    ;; build its initial message bytes.
    ;; Reference implementation just waits forever.
    @(dfrd/let-flow [available (strm/try-take! reader
                                               ::drained
                                               (util/minute)
                                               ::timed-out)]
       (let [log-state (log2/info log-state
                                  ::wait-for-initial-child-bytes
                                  "Waiting for initial-child-bytes returned"
                                  {::available available})]
         (if-not (keyword? available)
           {::log2/state log-state
            ::msg-bytes available}   ; i.e. success
           (if-not (= available ::drained)
             (if (= available ::timed-out)
               (throw (RuntimeException. "Timed out waiting for child"))
               (throw (RuntimeException. (str "Unknown failure: " available))))
             ;; I have a lot of interaction-test/handshake runs failing because
             ;; of this.
             ;; Q: What's going on?
             ;; (I can usually re-run the test and have it work the next
             ;; time through...it almost seems like a 50/50 thing)
             (throw (RuntimeException. "Stream from child closed"))))))))
