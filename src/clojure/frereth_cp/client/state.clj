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
            [manifold.executor :as exec]
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
                                                ::specs/srvr-port]
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

(s/def ::packet-builder (s/fspec :args (s/cat :state ::child-send-state
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
                                     ::specs/executor
                                     ;; This isn't mutable
                                     ;; Q: Is it?
                                     ;; A: Well, technically. Since it's a byte-array.
                                     ;; But, in practice, it will never change over the
                                     ;; course of the client's lifetime
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

;; FIXME: This really should be ::message-building-params.
;; Except that those are different.
(s/def ::initiate-building-params (s/keys :req [::log/logger
                                                ::log/state
                                                ::msg-specs/message-loop-name
                                                ;; Q: Why was this ever here?
                                                #_::chan->server
                                                ;; We still have a circular dependency.
                                                ::packet-builder
                                                ::server-extension
                                                ::server-security
                                                ::shared/extension
                                                ;; Note that this doesn't really make
                                                ;; any sense for message-building.
                                                ;; But it's absolutely vital for
                                                ;; for building the Initiate Packet.
                                                ::specs/inner-i-nonce]))
(s/def ::child-send-state (s/merge ::initiate-building-params
                                   (s/keys :req [::chan->server])))

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
           ::server-ips
           ::specs/executor]
    log-state ::log/state
    ;; TODO: Play with the numbers here to come up with something more reasonable
    :or {executor (exec/utilization-executor 0.5)}
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
        (assoc ::log/logger logger
               ::chan->server (strm/stream)
               ::specs/executor executor)
        ;; Can't do this: it involves a circular import
        #_(assoc ::packet-builder initiate/build-initiate-packet!)
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

(s/fdef ->message-exchange-mode
        :args (s/cat :this ::state
                     :initial-server-response ::specs/network-packet)
        :ret ::state)
;; I think this is the last place where I may somewhat-legitimately
;; be using the agent
(defn ->message-exchange-mode
  "Just received first real response Message packet from the handshake.
  Now we can start doing something interesting."
  [{:keys [::chan<-server
           ::chan->server
           ::msg-specs/->child]
    log-state ::log/state
    :as this}
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
  ;; Q: Is there a better alternative?
  (let [log-state (log/warn log-state
                            ::->message-exchange-mode
                            "I really want to deprecate this. I'm just not sure how.")
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
              (comment (await-for (current-timeout this) wrapper))

              ;; Need to wire this up to pretty much just pass messages through
              ;; Actually, this seems totally broken from any angle, since we need
              ;; to handle decryption, at a minimum.
              ;; Q: Don't we?
              ;; A: Absolutely!
              ;; We have a Server Message Packet here. Have to
              ;; 1. Pull out the Message crypto box
              ;; 2. Decrypt it
              ;; 3. Call ->child
              (strm/consume (fn [msg]
                              ;; as-written, we have to unwrap the message
                              ;; bytes for the stream from the message
                              ;; packet.
                              (->child (:message msg)))
                            chan<-server)
              log-state)
            (throw (ex-info (str "Missing either/both chan<-child and/or chan->server amongst\n" @this)
                            {::state this})))
          (log/warn log-state
                    ::->message-exchange-mode
                    "That response to Initiate was a failure"))]
    (assoc this
           ::packet-builder (fn [_]
                              (throw (RuntimeException. "FIXME: Need a function that mirrors initiate/build-initiate-packet!")))
           ;; This is another example of things falling apart in a multi-threaded
           ;; scenario.
           ;; Honestly, all the log calls that happen here should be updates wrapped
           ;; in a send.
           ::log/state log-state)))

(declare current-timeout)
(s/fdef final-wait
        :args (s/cat :this ::state
                     ;; Q: What is sent?
                     :sent any?)
        :ret ::specs/deferrable)
(defn final-wait
  "We've received the cookie and responded with a vouch.
  Now waiting for the server's first real message
  packet so we can switch into the message exchange
  loop"
  [this
   sent]
  (print "Entering final-wait. sent:" sent)
  (let [{:keys [::log/logger]
         log-state ::log/state} this]
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
      (let [timeout (current-timeout this)
            chan<-server (::chan<-server this)]
        (strm/try-take! chan<-server
                        ::drained timeout
                        ::initial-response-timed-out))
      (throw (ex-info "Timed out trying to send vouch" {::state (dissoc this ::log/state)})))))

(s/fdef extract-child-send-state
        :args (s/cat :state ::state)
        :ret ::child-send-state)
(defn extract-child-send-state
  "Extract the pieces that are actually used to forward a message from the Child"
  [state]
  (select-keys state [::chan->server
                      ::log/logger
                      ::log/state
                      ::msg-specs/message-loop-name
                      ::shared/extension
                      ::shared/my-keys
                      ::shared/work-area
                      ::specs/inner-i-nonce
                      ::specs/vouch
                      ::packet-builder
                      ::shared-secrets
                      ::server-extension
                      ::server-security]))

(s/fdef update-callback!
        :args (s/cat :io-handle ::msg-specs/io-handle
                     :time-out (s/and integer?
                                      (complement neg?))
                     :new-callback ::msg-specs/->parent))
(defn update-callback!
  [io-handle time-out new-callback]
  (message/swap-parent-callback! io-handle
                                 time-out
                                 ::child
                                 new-callback))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef current-timeout
        :args (s/cat :state ::state)
        :ret nat-int?)
(defn current-timeout
  "How long should next step wait before giving up?"
  [this]
  (-> this ::timeout
      (or default-timeout)))

(s/fdef do-send-packet
        :args (s/cat :log-state ::log/state
                     :this ::state
                     :on-success (s/fspec :args (s/cat :result any?)
                                          :ret any?)
                     :on-failure (s/fspec :args (s/cat :failure ::specs/exception-instance)
                                          :ret any?)
                     :chan->server strm/sinkable?
                     :packet (s/or :bytes bytes?
                                   ;; Honestly, an nio.ByteBuffer would probably be
                                   ;; just fine here also
                                   :byte-buf ::specs/byte-buf)
                     :timeout ::specs/timeout
                     :timeout-key any?)
        :ret (s/keys :req [::log/state ::specs/deferrable]))
(defn do-send-packet
  "Send a ByteBuf (et al) as UDP to the server"
  [{log-state ::log/state
    {:keys [::log/logger
            ::specs/srvr-ip
            ::specs/srvr-port]
     :as server-security} ::server-security
    :keys [::chan->server]
    :as this}
   on-success
   on-failure
   timeout
   timeout-key
   packet]
  (when-not packet
    ;; There aren't a lot of details that seem like they'd
    ;; be worth adding to justify switching to ex-info.
    (throw (RuntimeException. "Trying to send nil bytes")))
  (let [log-state (log/debug log-state
                             ::do-send-packet
                             "Incoming message packet. Should be a binary we can put on the wire"
                             {::shared/packet packet
                              ::payload-class (class packet)})
        d (strm/try-put! chan->server
                         {:host srvr-ip
                          :message packet
                          :port srvr-port}
                         timeout
                         timeout-key)
        log-state (log/info log-state
                            ::do-send-packet
                            ""
                            {::server-security server-security
                             ;; Can't do the straightforward approach from
                             ;; a ByteBuf without
                             ;; adding a byte-streams/def-conversion.
                             ;; TODO: I should probably do that.
                             ;; However, there's a different problem here:
                             ;; Sometimes this gets called with packet as a [B.
                             ;; Others, it's the network-packet spec.
                             ::human-readable-message (b-t/->string #_packet
                                                                    (if (bytes? packet)
                                                                      packet
                                                                      (let [^ByteBuf packet packet
                                                                            bs (byte-array (.readableBytes packet))]
                                                                        (.getBytes packet 0 bs)
                                                                        bs)))})]
    {::log/state log-state
     ::specs/deferrable (dfrd/on-realized d
                                          on-success
                                          on-failure)}))

;;; This namespace is too big, and I hate to add this next
;;; function to it.
;;; But there's a circular reference if I try to
;;; add it anywhere else.
;;; fork! needs access to child->, while child-> needs access
;;; to the ::state-agent spec.
;;; Which is a strong argument for refactoring specs like
;;; that into their own namespace.
(s/fdef child->
        :args (s/cat :state ::child-send-state
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
  ;; This function pulls a couple of stateful pieces
  ;; out of the state-agent.
  ;; The first is the packet-builder. We need to start
  ;; by building/sending Initiate packets, until we
  ;; receive a Message packet back from the Server. Then
  ;; we can switch to sending Message packets.
  ;; The caller is tightly coupled with this and has to
  ;; follow the same rules. So we could have it send
  ;; a second parameter which tells us which one to
  ;; create.
  ;; In a lot of ways, this seems like the best option:
  ;; callers should drive the behavior.
  ;; OTOH, I really the "just write bytes" callback
  ;; approach.
  ;; And that really doesn't help much with the point
  ;; that the send timeout is mutable (Q: Should it be?)
  ;; Another approach that seems promising would be to
  ;; add a message signal that lets me update the
  ;; callback function.
  ;; Alternatively, I *could* just check the message size.
  ;; If it's small enough to fit into an Initiate Packet,
  ;; send another.
  ;; That's perfectly legal, but seems wasteful in terms
  ;; of CPU and network.
  [{log-state ::log/state
    :keys [::chan->server
           ::log/logger
           ::packet-builder
           ::server-security]
    :as state}
   timeout
   ^bytes message-block]
  {:pre [packet-builder]}
  (let [log-state (log/do-sync-clock log-state)
        {:keys [::specs/srvr-name ::specs/srvr-port]} server-security]
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
    ;; use message/swap-parent-callback! to swap packet-builder from
    ;; initiate/build-initiate-packet! to
    ;; some function that I don't think I've written yet that should
    ;; live in client.message.
    (let [message-packet (packet-builder (assoc state ::log/state log-state) message-block)
          log-state (log/debug log-state
                               ::child->
                               "Client sending a message packet from child->serve"
                               {::shared/message (if message-packet
                                                   (b-t/->string message-packet)
                                                   "No message packet built")
                                ::server-security server-security})]
      (when-not (and srvr-name srvr-port message-packet)
        (throw (ex-info "Missing something vital"
                        {::specs/srvr-name srvr-name
                         ::specs/srvr-port srvr-port
                         ::shared/message message-packet})))
      (let [composite-result-placeholder
            (do-send-packet state
                            (fn [success]
                              (let [log-state (log/debug log-state
                                                         ::child->
                                                         "Packet sent"
                                                         {::shared/message message-packet
                                                          ::server-security server-security})]
                                (log/flush-logs! logger log-state)))
                            (fn [ex]
                              (let [log-state (log/exception log-state
                                                             ex
                                                             ::child->
                                                             "Sending packet failed"
                                                             {::shared/message message-packet
                                                              ::server-security server-security})]))
                            timeout
                            ::child->timed-out
                            message-packet)
            {log-state ::log/state
             result ::specs/deferrable} composite-result-placeholder]
        result))))

(s/fdef update-timeout!
        :args (s/cat :state-agent ::state-agent
                     :timeout nat-int?)
        :ret any?)
(defn update-timeout!
  [wrapper new-timeout]
  (throw (RuntimeException. "Never should have written this in the first place")))

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
  ;; every time the client forwards us a packet.
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
        [extension log-state] (if reload?
                                (try (-> "/etc/curvecpextension"
                                         ;; This is pretty inefficient...we really only want 16 bytes.
                                         ;; Should be good enough for a starting point, though
                                         slurp
                                         (subs 0 16)
                                         .getBytes)
                                     (catch java.io.FileNotFoundException _
                                       ;; This really isn't all that unexpected.
                                       ;; The original goal/dream was to get CurveCP
                                       ;; added as a standard part of every operating
                                       ;; system's network stack, so that this would
                                       ;; become a part of standard unix-based systems.
                                       ;; This is just a demonstrator of how well that
                                       ;; panned out.
                                       [(K/zero-bytes 16)
                                        (log/flush-logs! logger (log/warn (log/clean-fork log-state
                                                                                          ::clientextension-init)
                                                                          ::clientextension-init
                                                                          "no /etc/curvecpextension file"))]))
                                [extension log-state])]
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
        :args (s/cat :state ::state)
        :ret ::state)
(defn fork!
  ;; TODO: Verify the send-off vs. send. But surely it is.
  "It happens in the agent processing thread pool, during a send-off operation.

  TODO: Move this into shared so the server can use the same code."
  [{:keys [::log/logger
           ::msg-specs/->child
           ::msg-specs/child-spawner!
           ::msg-specs/message-loop-name]
    initial-msg-state ::msg-specs/state
    log-state ::log/state
    :as this}]
  {:pre [message-loop-name]}
  (when-not log-state
    (throw (ex-info (str "Missing log state among "
                         (keys this))
                    this)))
  (let [log-state (log/info log-state ::fork! "Spawning child!!")
        startable (message/initial-state message-loop-name
                                         false
                                         (assoc initial-msg-state
                                                ::log/state log-state)
                                         logger)
        child-send-state (extract-child-send-state this)
        ;; At this point in time, we don't have the inner-i-nonce.
        ;; So of course it can't get passed along to child->
        ;; This must have been something that was getting updated by
        ;; the agent, back when this part seemed to work.
        ;; Actually, it looks like it's much simpler.
        ;; We "just" need to call initiate/build-inner-vouch before
        ;; we get here.
        ;; FIXME: Make that happen.
        _ (assert (::specs/inner-i-nonce child-send-state) (str "Missing inner-i-nonce in child-send-state\n"
                                                              (keys child-send-state)
                                                              "\namong\n"
                                                              child-send-state
                                                              "\nbuilt from\n"
                                                              (keys this)
                                                              "\namong\n"
                                                              this))
        _ (println "state/fork! inner-i-nonce:" (::specs/inner-i-nonce child-send-state))
        {:keys [::msg-specs/io-handle]
         log-state ::log/state} (message/do-start startable
                                                  logger
                                                  (partial child->
                                                           child-send-state
                                                           (current-timeout this))
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

(s/fdef update-client-short-term-nonce
        :args (s/cat :nonce integer?)
        :ret integer?)
(defn update-client-short-term-nonce
  "Note that this can loop right back to a negative number."
  [^Long nonce]
  (let [result (unchecked-inc nonce)]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {:must "End communication immediately"})))
    result))
