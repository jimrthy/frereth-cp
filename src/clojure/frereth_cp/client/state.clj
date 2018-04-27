(ns frereth-cp.client.state
  "Handle the inherently stateful pieces associated with the client side of things.

The fact that this is so big says a lot about needing to re-think my approach"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth-cp.message :as message]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as util]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(set! *warn-on-reflection* true)

(def default-timeout 2500)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

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
(s/def ::server-ips (s/coll-of ::specs/srvr-ip))
(s/def ::server-security (s/merge ::specs/peer-keys
                                  (s/keys :req [::specs/srvr-name
                                                ::shared/srvr-port]
                                          ;; Q: Is there a valid reason for the server-cookie to live here?
                                          ;; Q: I can discard it after sending the vouch, can't I?
                                          ;; A: Yes.
                                          ;; Q: Do I want to?
                                          ;; A: Well...keeping it seems like a potential security hole
                                          ;; TODO: Make it go away
                                          :opt [::server-cookie
                                                ::specs/srvr-ip])))

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
                                     ::log/logger
                                     ;; If we track ::msg-specs/state here,
                                     ;; then ::log/state is, honestly, redundant.
                                     ;; Except that trying to keep them synchronized
                                     ;; is a path to madness, as is tracking
                                     ;; a snapshot of ::msg-specs/state.
                                     ::log/state
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
                                       ::server-ips
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
                                 :ret (s/keys :req [::log/state
                                                    ::msg-specs/io-handle])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal Implementation

(s/fdef load-keys
        :args (s/cat :logger ::log/state
                     :my-keys ::shared/my-keys)
        :ret (s/keys :req [::log/state
                           ::shared/my-keys]))
(defn load-keys
  [log-state my-keys]
  (let [key-dir (::shared/keydir my-keys)
        long-pair (crypto/do-load-keypair key-dir)
        short-pair (crypto/random-key-pair)
        log-state (log/info log-state
                            ::load-keys
                            "Loaded leng-term client key pair"
                            {::shared/keydir key-dir})]
    {::shared/my-keys (assoc my-keys
                             ::shared/long-pair long-pair
                             ::shared/short-pair short-pair)
     ::log/state log-state}))

(s/fdef initialize-immutable-values
        :args (s/cat :this ::immutable-value
                     :log-initializer (s/fspec :args (s/cat)
                                               :ret ::log/logger))
        :ret ::immutable-value)
(defn initialize-immutable-values
  "Sets up the immutable value that will be used in tandem with the mutable agent later"
  [{:keys [::msg-specs/message-loop-name
           ::chan<-server
           ::server-extension
           ::server-ips]
    log-state ::log/state
    :as this}
   log-initializer]
  {:pre [message-loop-name
         server-extension
         server-ips]}
  (when-not chan<-server
    (throw (ex-info "Missing channel from server"
                    {::keys (keys this)
                     ::big-picture this})))
  (let [logger (log-initializer)]
    (-> this
        (assoc ::log/logger logger)
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
           ::log/logger
           ::msg-specs/message-loop-name]
    :as this}]
  (let [log-state (log/init message-loop-name)
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
          log-state (log/info log-state
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
             ::log/state log-state}))))

(defn ->message-exchange-mode
  "Just received first real response Message packet from the handshake.
  Now we can start doing something interesting."
  [{:keys [::chan<-server
           ::chan->server
           ::msg-specs/->child]
    log-state ::log/state
    :as this}
   wrapper
   initial-server-response]
  (when-not log-state
    (println "Missing log-state among\n"
             (keys this)
             "\nin\n"
             this)
    (throw (ex-info "Missing log-state" this)))
  ;; Q: Does this function make any sense at all?
  ;; Up until now, we've been funneling messages from the child through
  ;; Initiate packets. Now we can extend that to full-blown Message
  ;; packets.
  ;; And we had a special state flag waiting for the first response back
  ;; from the server, which we've just received.
  ;; So yes. Special things do happen here/now.
  ;; That doesn't mean that any of those special things fit with what
  ;; I've been trying so far.
  ;; Except that, last I checked, this basically worked.
  (let [log-state (log/warn log-state
                            ::->message-exchange-mode
                            "deprecated")
        log-state (log/info log-state
                            ::->message-exchange-mode
                            "Initial Response from server"
                            initial-server-response)
        log-state
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
                            chan<-server)
              log-state)
            (throw (ex-info (str "Missing either/both chan<-child and/or chan->server amongst\n" @this)
                            {::state this})))
          (log/warn log-state
                    ::->message-exchange-mode
                    "That response to Initiate was a failure"))]
    ;; This is another example of things falling apart in a multi-threaded
    ;; scenario.
    ;; Honestly, all the log calls that happen here should be updates wrapped
    ;; in a send.
    (send wrapper assoc ::log/state log-state)))

(declare current-timeout)
;; TODO: This needs a spec
(defn final-wait
  "We've received the cookie and responded with a vouch.
  Now waiting for the server's first real message
  packet so we can switch into the message exchange
  loop"
  [wrapper
   sent]
  (let [{:keys [::log/logger]
         log-state ::log/state
         :as this} @wrapper]
    (when-not log-state
      (throw (ex-info
              "Missing log-state"
              {::keys (keys this)
               ::problem this})))
    (log/flush-logs! logger
                     (log/warn log-state
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
                          (fn [success]
                            (send-off wrapper (partial ->message-exchange-mode wrapper) success))
                          (fn [ex]
                            (send wrapper #(throw (ex-info "Server vouch response failed"
                                                           (assoc % :problem ex))))))
        this)
      (do
        (send wrapper #(throw (ex-info "Timed out trying to send vouch" %)))
        this))))

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
  (let [{log-state ::log/state
         :keys [::chan->server
                ::log/logger
                ::msg-specs/io-handle
                ::packet-builder
                ::server-security]
         :as state} @wrapper
        {:keys [::specs/srvr-name ::shared/srvr-port]} server-security]
    (when-not packet-builder
      (throw (ex-info "Missing packet-builder"
                      {::existing-keys (keys state)
                       ::problem (dissoc state ::log/state)})))
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
    (let [message-packet (packet-builder state message-block)
          ;; FIXME: Switch to using do-send-packet
          bundle {:host srvr-name
                  :port srvr-port
                  :message message-packet}
          ;; This pretty much has to be where everything gets busted
          ;; and how I'm sending such weird gibberish to my test.
          ;; This isn't getting converted to a Message/Initiate packet at all.
          ;; OTOH, sometimes it looks reasonable.
          ;; So this is really just Step One.
          _ (println "Client sending a message packet from child->server\n"
                     message-packet)
          result (strm/put! chan->server bundle)
          msg-log-state-atom (::log/state-atom io-handle)
          ;; Actually, this would be a good time to use refs inside a
          ;; transaction.
          [my-log-state msg-log-state] (log/synchronize log-state @msg-log-state-atom)]
      (assert (and srvr-name srvr-port message-packet "Start back here"))
      (swap! msg-log-state-atom #(log/flush-logs! logger %))
      result)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(defn current-timeout
  "How long should next step wait before giving up?"
  [wrapper]
  (-> wrapper deref ::timeout
      (or default-timeout)))

(s/fdef clientextension-init
        :args (s/cat :this ::state)
        :ret ::state)
(defn clientextension-init
  "Initialize the client-extension"
  ;; Started from the assumptions that this is neither
  ;; a) performance critical nor
  ;; b)  subject to timing attacks
  ;; because it just won't be called very often.
  ;; Those assumptions are false. This actually gets called
  ;; before pretty much every packet that gets sent.
  ;; Q: Really?
  ;; However: it only does the reload once every 30 seconds.
  [{:keys [::client-extension-load-time
           ::log/logger
           ::msg-specs/recent
           ::shared/extension]
    log-state ::log/state
    :as this}]
  {:pre [(and client-extension-load-time recent)]}
  (let [reload? (>= recent client-extension-load-time)
        log-state (log/debug log-state
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
                           (log/flush-logs! logger (log/warn (log/clean-fork log-state
                                                                             ::clientextension-init)
                                                             ::clientextension-init
                                                             "no /etc/curvecpextension file"))
                           (K/zero-bytes 16)))
                    extension)]
    (assert (= (count extension) K/extension-length))
    (let [log-state (log/info log-state
                              ::clientextension-init
                              "Loaded extension"
                              {::shared/extension (vec extension)})]
      (assoc this
             ::client-extension-load-time client-extension-load-time
             ::log/state log-state
             ::shared/extension extension))))

(s/fdef fork!
        :args (s/cat :state ::state
                     :wrapper ::state-agent)
        :ret ::state)
(defn fork!
  "This has to 'fork' a child with access to the agent, and update the agent state

So, yes, it *is* weird.

It happens in the agent processing thread pool, during a send operation.

Although send-off might seem more appropriate, it probably isn't.

TODO: Need to ask around about that.

Bigger TODO: This really should be identical to the server implementation.

Which at least implies that the agent approach should go away."
  [{:keys [::log/logger
           ::msg-specs/->child
           ::msg-specs/child-spawner!
           ::msg-specs/message-loop-name]
    initial-msg-state ::msg-specs/state
    log-state ::log/state
    :as this}
   wrapper]
  {:pre [message-loop-name]}
  (when-not log-state
    (throw (ex-info (str "Missing log state among "
                         (keys this))
                    this)))
  ;; This sets up the message loop and callback,
  ;; but it leaves out the actual child part.
  ;; In handshake-test, it's all kicked off by
  ;; calling buffer-response!
  ;; And then the server- or client- -child-processor
  ;; functions handle the actual message exchange.
  (let [log-state (log/info log-state ::fork! "Spawning child!!")
        startable (message/initial-state message-loop-name
                                         false
                                         (assoc initial-msg-state
                                                ::log/state log-state)
                                         logger)
        {:keys [::msg-specs/io-handle]
         log-state ::log/state} (message/do-start startable
                                                  logger
                                                  ;; And this is really why
                                                  ;; I need something stateful
                                                  (partial child-> wrapper)
                                                  ->child)
        log-state (log/debug log-state
                             ::fork!
                             "Child message loop initialized"
                             {::this (dissoc this ::log/state)
                              ::child (dissoc io-handle ::log/state)})]
    (child-spawner! io-handle)
    (assoc this
           ::child io-handle
           ::log/state (log/flush-logs! logger log-state)
           ::msg-specs/io-handle io-handle)))

(s/fdef stop!
        :args (s/cat :this ::state)
        :ret ::log/state)
(defn do-stop
  [{:keys [::child]
    log-state ::log/state
    :as this}]
  (if child
    (let [log-state (log/warn log-state
                              ::do-stop
                              "Halting child's message io-loop")]
      (message/halt! child)
      (log/warn log-state
                ::do-stop
                "Child's message io-loop halted"))
    (log/warn log-state
              ::do-stop
              "No child message io-loop to stop")))

(s/fdef do-send-packet
        :args (s/cat :this ::state
                     :on-success (s/fspec :args (s/cat :result any?)
                                          :ret any?)
                     :on-failure (s/fspec :args (s/cat :failure ::specs/exception-instance)
                                          :ret any?)
                     :chan->server strm/sinkable?
                     :packet (s/or :bytes bytes?
                                   ;; Honestly, an nio.ByteBuffer would probably be
                                   ;; just fine here also
                                   :byte-buf ::specs/byte-buf)
                     :timeout (s/and integer?
                                     (complement neg?))
                     :timeout-key any?)
        :ret ::specs/deferrable)
(defn do-send-packet
  "Send a ByteBuf (et al) as UDP to the server"
  [{log-state ::log/state
    {:keys [::specs/srvr-ip
            ::specs/srvr-port]
     :as server-security} ::server-security
    :keys [::chan->server]
    :as this}
   on-success
   on-failure
   timeout
   timeout-key
   packet]
  (println "do-send-packet server-security:" server-security)
  (let [d (strm/try-put! chan->server
                         {:host srvr-ip
                          :message packet
                          :port srvr-port}
                         timeout
                         timeout-key)]
    (dfrd/on-realized d
                      on-success
                      on-failure)))

(defn update-client-short-term-nonce
  "Note that this can loop right back to a negative number."
  [^Long nonce]
  (let [result (unchecked-inc nonce)]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {:must "End communication immediately"})))
    result))
