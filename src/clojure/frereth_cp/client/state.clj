(ns frereth-cp.client.state
  "Handle the inherently stateful pieces associated with the client side of things.

The fact that this is so big says a lot about needing to re-think my approach"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth-cp.message :as message]
            [frereth-cp.message
             [registry :as registry]
             [specs :as msg-specs]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log]
             [serialization :as serial]
             [specs :as specs]]
            [frereth-cp.util :as util]
            [manifold
             [deferred :as dfrd]
             [executor :as exec]
             [stream :as strm]])
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
;; This seems to have been an aspiration, when DJB hoped the entire idea
;; would get pulled into the Linux kernel.
;; It's just that the idea didn't seem to gain any traction.
(s/def ::client-extension-load-time nat-int?)

(s/def ::server-extension ::shared/extension)
;; 96-byte black box that we send back as part of
;; the Vouch
(s/def ::server-cookie (s/and bytes?
                              #(= (count %) K/server-cookie-length)))
(s/def ::server-ips (s/coll-of ::specs/srvr-ip))
(s/def ::server-security (s/merge ::specs/peer-keys
                                  (s/keys :req [::specs/srvr-name  ;; DNS
                                                ::specs/srvr-port]
                                          ;; Q: Is there a valid reason for the server-cookie to live here?
                                          ;; Q: I can discard it after sending the vouch, can't I?
                                          ;; A: Yes.
                                          ;; Q: Do I want to?
                                          ;; A: Well...keeping it seems like a potential security hole
                                          ;; TODO: Make it go away once I'm done with it.
                                          ;; (i.e. once a server's sent a response to an Initiate
                                          ;; packet).
                                          :opt [::server-cookie
                                                ;; Where we actually communicate
                                                ::specs/srvr-ip])))

(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-long<->server-long
                                      ::client-short<->server-long
                                      ::client-short<->server-short]))

(s/def ::packet-builder (s/fspec :args (s/cat :state ::child-send-state
                                              :msg-packet bytes?)
                                 :ret ::msg-specs/buf))

(s/def ::child ::msg-specs/io-handle)

;; This is for really extreme conditions where sanity has flown
;; out the window.
;; In a standard synchronous application, this is where an assert
;; should fail.
;; Use this when you can't do that meaningfully because you're
;; in an async callback and it will just get swallowed.
;; There's never a valid reason for fulfilling this successfully.
(s/def ::terminated ::specs/deferrable)

;; The parts that change really need to be stored in a mutable
;; data structure.
;; Parts of this mutate over time. Others advance with the handshake
;; FSM. And others are really just temporary members.
;; The distinction from the immutable-state portions makes a lot less sense
;; now that I've eliminated any actual usage of the agent.
(s/def ::mutable-state (s/keys :req [::client-extension-load-time  ; not really mutable
                                     ::specs/executor
                                     ;; This isn't mutable
                                     ;; Q: Is it?
                                     ;; A: Well, technically. Since it's a byte-array.
                                     ;; But, in practice, it will never change over the
                                     ;; course of the client's lifetime
                                     ::shared/extension
                                     ::log/logger
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
                                     ::terminated]
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

;; Returns a deferrable that's waiting on the cookie in
;; response to a hello
(s/def ::cookie-waiter (s/fspec :args (s/cat :this ::state
                                             :timeout ::specs/time
                                             :sent ::specs/network-packet)
                                :ret ::specs/deferrable))

;; Pieces used to initialize the extension
(s/def ::extension-initializers
  (s/keys :req [::client-extension-load-time
                ::log/logger
                ::log/state
                ::msg-specs/recent
                ::shared/extension]))
;; What comes back from extension initialization
(s/def ::extension-initialized (s/keys :req [::client-extension-load-time
                                             ::log/state
                                             ::shared/extension]))

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

;; Refactored from hello so it can be used by ::cookie/success-callback
(s/def ::cookie-response
  ;; This started out as
  #_(s/keys :req [::log/state]
          :opt [::security
                ::shared-secrets
                ::shared/network-packet])
  ;; But that didn't cut it
  (fn [{:keys [::log/state
               ::security
               ::shared-secrets
               ::shared/network-packet]
        :as this}]
    ;; log-state is required
    (when
        (and state
             ;; We must have all or none of these
             (or (and security shared-secrets network-packet)
                 (not security shared-secrets network-packet))
             (let [n (count (keys this))]
               ;; No others allowed.
               ;; This violates some basic principles behind
               ;; spec, but leaving this open has caused
               ;; too much pain.
               (or (= n 1) (= n 4))))
      this)))

(s/def ::valid-outgoing-binary (s/or :bytes bytes?
                                     :byte-buf ::specs/byte-buf
                                     :byte-buffer ::specs/nio-byte-buffer))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Globals

(defonce io-loop-registry (atom (registry/ctor)))
(comment
  @io-loop-registry
  (-> io-loop-registry deref keys)
  (swap! io-loop-registry registry/de-register "client-hand-shaker")
  )

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
  "Sets up the immutable value that will be used in tandem with the mutable state later"
  [{:keys [::msg-specs/message-loop-name
           ::chan<-server
           ::server-extension
           ::server-ips
           ::specs/executor]
    log-state ::log/state
    ;; TODO: Play with the numbers here to come up with something reasonable
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
                                ;; FIXME: Don't log this
                                ::shared-key (b-t/->string long-shared)})
          terminated (dfrd/deferred)]
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
             ::log/state log-state
             ::terminated terminated}))))

(s/fdef ->message-exchange-mode
        :args (s/cat :this ::state
                     :initial-server-response ::specs/network-packet)
        :ret ::state)
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
  (let [log-state (log/info log-state
                            ::->message-exchange-mode
                            "Initial Response from server"
                            initial-server-response)
        log-state
        (if (not (keyword? (:message initial-server-response)))
          (if (and ->child chan->server)
            ;; Note the inherent side-effect that happens in here.
            ;; FIXME: Come up with a better way to handle this.
            (do
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
            (throw (ex-info (str "Missing either/both chan<-child and/or chan->server")
                            {::state this})))
          (log/warn log-state
                    ::->message-exchange-mode
                    "That response to Initiate was a failure"))]
    (assoc this
           ::packet-builder (fn [_]
                              (throw (RuntimeException. "FIXME: Need a function that mirrors initiate/build-initiate-packet!")))
           ;; This is another example of things falling apart in a multi-threaded
           ;; scenario.
           ;; Honestly, all the log calls that happen here should be updates modifying
           ;; an atom.
           ;; Q: Is that really true?
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
                      ::specs/inner-i-nonce
                      ::specs/vouch
                      ::packet-builder
                      ::shared-secrets
                      ::server-extension
                      ::server-security]))

(s/fdef update-callback!
        :args (s/cat :io-handle ::msg-specs/io-handle
                     :time-out ::specs/time
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
        :ret ::specs/time)
(defn current-timeout
  "How long should next step wait before giving up?"
  [this]
  (or (::timeout this)
      default-timeout))

(s/fdef put-packet
        :args (s/cat :chan->server ::chan->server
                     :srvr-ip ::server-ips
                     :packet ::valid-outgoing-binary
                     :srvr-port ::specs/srvr-port
                     :timeout ::specs/timeout
                     :timeout-key any?)
        :ret dfrd/deferrable?)
(defn put-packet
  "Build and put a packet onto channel toward server

  No bells, whistles, or anything else to make it fancier than needed"
  [chan->server srvr-ip packet srvr-port timeout timeout-key]
  (strm/try-put! chan->server
                 {:host srvr-ip
                  :message packet
                  :port srvr-port}
                 timeout
                 timeout-key))

(s/fdef do-send-packet
        :args (s/cat :this ::state
                     :on-success (s/fspec :args (s/cat :result boolean?)
                                          :ret any?)
                     :on-failure (s/fspec :args (s/cat :failure ::specs/exception-instance)
                                          :ret any?)
                     :chan->server strm/sinkable?
                     :packet ::valid-outgoing-binary
                     :timeout ::specs/timeout
                     :timeout-key any?)
        :ret (s/keys :req [::log/state ::specs/deferrable]))
(defn do-send-packet
  "Send a ByteBuf (et al) as UDP to the server

  With lots of bells, whistles, and callbacks"
  ;; Q: How tough to make this generic enough to use
  ;; on both sides?
  ;; Actually, all we really need to do is make the key
  ;; names generic, move this into a shared ns, then make
  ;; the specific versions translate the keys as needed.
  ;; Q: Is it worth making that happen?
  ;; I've already backed off here because put-packet seems
  ;; more usable.
  [{log-state ::log/state
    {:keys [::specs/srvr-ip
            ::specs/srvr-port]
     :as server-security} ::server-security
    :keys [::chan->server
           ::log/logger]
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
                             "Outgoing message packet. Should be a binary we can put on the wire"
                             {::shared/packet packet
                              ::payload-class (class packet)})
        d (put-packet chan->server srvr-ip packet srvr-port timeout timeout-key)
        log-state (log/info log-state
                            ::do-send-packet
                            ""
                            {::server-security server-security
                             ::human-readable-message (b-t/->string (if (bytes? packet)
                                                                      packet
                                                                      (throw (ex-info "Expected [B"
                                                                                      {::actual (class packet)
                                                                                       ::value packet
                                                                                       :log/state log-state}))))})]
    {::log/state log-state
     ::specs/deferrable (dfrd/on-realized d
                                          on-success
                                          on-failure)}))

;;; This namespace is too big, and I hate to add this next
;;; function to it.
;;; But there's a circular reference if I try to
;;; add it anywhere else.
;;; fork! needs access to child->, while child-> needs access
;;; to portions of the ::state spec.
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
        ;; so we can couple it as tightly as we like.
        ;; Still, it would be nice to keep it isolated.
        :ret dfrd/deferrable?)
(defn child->
  "Handle packets streaming out of child"
  ;; This function uses a couple of important pieces
  ;; from the State.

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
  ;; OTOH, I really like the "just write bytes" callback
  ;; approach.
  ;;
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
  (let [{:keys [::server-cookie
                ::specs/srvr-name
                ::specs/srvr-port]} server-security
        log-state (log/flush-logs! logger (log/trace log-state
                                                     ::child->
                                                     "Top"
                                                     {::server-cookie server-cookie}))]
    (when-not server-cookie
      ;; This seems like something that should be debug-only.
      ;; But, honestly, it's a really nice red flag to have around.
      (binding [*out* *err*]
        (println "WARNING: Missing the server-cookie in server-security.\n"
                 "This doesn't matter once we can start sending message\n"
                 "packets, but it means we cannot possibly build an\n"
                 "Initiate.")))

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
    ;; some equivalent function that I haven't written yet. That function should
    ;; live in client.message.

    ;; The flag that controls this is stored in the child state.
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
    ;; sending back bigger message blocks before the real state-tracker
    ;; has been notified that it needs to switch to sending Message
    ;; packets rather than Initiate ones.
    ;; The reference implementation maintains this flag in both places.
    ;; It just avoids the possibility of race conditions by running
    ;; in a single thread.

    ;; This is the point behind ->message-exchange-mode.
    (let [message-packet (bytes (packet-builder (assoc state ::log/state log-state) message-block))
          raw-message-packet (if message-packet
                               (b-s/convert message-packet specs/byte-array-type)
                               (byte-array 0))
          log-state (log/debug log-state
                               ::child->
                               "Client sending a message packet from child->serve"
                               {::shared/message (if message-packet
                                                   (b-t/->string raw-message-packet)
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
                                                         {::shared/message raw-message-packet
                                                          ::server-security server-security})]
                                (log/flush-logs! logger log-state)))
                            (fn [ex]
                              (let [log-state (log/exception log-state
                                                             ex
                                                             ::child->
                                                             "Sending packet failed"
                                                             {::shared/message raw-message-packet
                                                              ::server-security server-security})]))
                            timeout
                            ::child->timed-out
                            raw-message-packet)
            {log-state ::log/state
             result ::specs/deferrable} composite-result-placeholder]
        result))))

(s/fdef clientextension-init
        :args (s/cat :this ::extension-initializers)
        :ret ::extension-initialized)
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
      {::client-extension-load-time client-extension-load-time
       ::log/state log-state
       ::shared/extension extension})))

(s/fdef fork!
        :args (s/cat :state ::state)
        :ret ::state)
(defn fork!
  "Create a new Child to do all the interesting work."
  [{:keys [::log/logger
           ::msg-specs/->child
           ::msg-specs/child-spawner!
           ::msg-specs/message-loop-name]
    log-state ::log/state
    :as this}]
  {:pre [message-loop-name]}
  (when-not log-state
    (throw (ex-info (str "Missing log state among "
                         (keys this))
                    this)))
  (let [log-state (log/info log-state ::fork! "Spawning child!!")
        child-name (str (gensym "child-"))
        startable (message/initial-state message-loop-name
                                         false
                                         {::log/state (log/clean-fork log-state child-name)}
                                         logger)
        child-send-state (extract-child-send-state this)
        _ (assert (::specs/inner-i-nonce child-send-state) (str "Missing inner-i-nonce in child-send-state\n"
                                                              (keys child-send-state)
                                                              "\namong\n"
                                                              child-send-state
                                                              "\nbuilt from\n"
                                                              (keys this)
                                                              "\namong\n"
                                                              this))
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
    (swap! io-loop-registry
           #(registry/register % io-handle))
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
                              "Halting child's message io-loop")
          message-loop-name (::specs/message-loop-name child)]
      (message/halt! child)
      ;; In theory, I should be able to just manually call halt!
      ;; on entries in this registry that don't get stopped when
      ;; things hit a bug.
      ;; In practice, the problems probably go deeper:
      ;; Either from-child or to-parent (more likely) keeps
      ;; feeding un-ackd messages into the queue.
      ;; So I need a way to manually halt that also.

      ;; There are some interrupt functions in the top-level
      ;; frereth-cp.message ns that seem to do the trick.
      ;; It's tempting to expose them.
      ;; Then again, they're a sledge hammer that just stops
      ;; all the message loops.
      ;; Running multiple clients and server connections
      ;; requires a scalpel.
      ;; TODO: Revisit this.
      (swap! io-loop-registry
             #(registry/de-register % message-loop-name))
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
