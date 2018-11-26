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
             [child :as child]
             [constants :as K]
             [crypto :as crypto]
             [serialization :as serial]
             [specs :as specs]]
            [frereth-cp.util :as util]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
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

(def cpu-utilization-target 0.5)

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
;; added to implement that sort of thing at the Operating System level.
;; Actually doing anything useful with this seems like it's probably
;; an exercise that's been left for later.
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
                                 :ret (s/keys :req [::weald/state]
                                              :opt [::shared/packet])))

;; This is for really extreme conditions where sanity has flown
;; out the window.
;; In a standard synchronous application, this is where an assert
;; should fail.
;; Use this when you can't do that meaningfully because you're
;; in an async callback and it will just get swallowed.
;; There's never a valid reason for fulfilling this successfully.
(s/def ::terminated ::specs/deferrable)

;;;; FIXME: Move at least the state-related specs into a shared ns
;;;; to give me the opportunity to split this one up a bit

;; The parts that change really need to be stored in a mutable
;; data structure.
;; Parts of this mutate over time. Others advance with the handshake
;; FSM. And others are really just temporary members.
;; The distinction from the immutable-state portions makes a lot less sense
;; now that I've eliminated any actual usage of the agent.
(s/def ::mutable-state (s/keys :req [::msg-specs/->child
                                     ::client-extension-load-time  ; not really mutable
                                     ::specs/executor
                                     ;; This isn't mutable
                                     ;; Q: Is it?
                                     ;; A: Well, technically. Since it's a byte-array.
                                     ;; But, in practice, it will never change over the
                                     ;; course of the client's lifetime
                                     ::shared/extension
                                     ::weald/logger
                                     ::weald/state
                                     ;; Q: Does this really make any sense?
                                     ;; A: Not in any sane reality.
                                     ::outgoing-message
                                     ::packet-builder
                                     ::msg-specs/recent
                                     ;; The only thing mutable about this is that I don't have it all in beginning
                                     ::server-security
                                     ;; The only thing mutable about this is that I don't have it all in beginning
                                     ::shared-secrets
                                     ::terminated]
                               :opt [::child/state
                                     ::specs/io-handle
                                     ;; Q: Why am I tempted to store this at all?
                                     ;; A: Well...I might need to resend it if it
                                     ;; gets dropped initially.
                                     ::vouch]))
(s/def ::immutable-value (s/keys :req [::shared/my-keys
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
                ::weald/logger
                ::weald/state
                ::msg-specs/recent
                ::shared/extension]))
;; What comes back from extension initialization
(s/def ::extension-initialized (s/keys :req [::client-extension-load-time
                                             ::weald/state
                                             ::shared/extension]))

;; FIXME: This really should be ::message-building-params.
;; Except that those are different.
(s/def ::initiate-building-params (s/keys :req [::weald/logger
                                                ::weald/state
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
  (fn [{:keys [::weald/state
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
;;;; Internal Implementation

(s/fdef load-keys
        :args (s/cat :logger ::weald/state
                     :my-keys ::shared/my-keys)
        :ret (s/keys :req [::weald/state
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
     ::weald/state log-state}))

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
    log-state ::weald/state
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
           ::weald/state log-state)))

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
  (let [{:keys [::weald/logger]
         log-state ::weald/state} this]
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
      (throw (ex-info "Timed out trying to send vouch" {::state (dissoc this ::weald/state)})))))

(s/fdef extract-child-send-state
        :args (s/cat :state ::state)
        :ret ::child-send-state)
(defn extract-child-send-state
  "Extract the pieces that are actually used to forward a message from the Child"
  [state]
  (select-keys state [::chan->server
                      ::weald/logger
                      ::weald/state
                      ::msg-specs/message-loop-name
                      ::shared/extension
                      ::shared/my-keys
                      ::specs/inner-i-nonce
                      ::specs/vouch
                      ::packet-builder
                      ::shared-secrets
                      ::server-extension
                      ::server-security]))

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
        :ret (s/keys :req [::weald/state ::specs/deferrable]))
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
  [{log-state ::weald/state
    {:keys [::specs/srvr-ip
            ::specs/srvr-port]
     :as server-security} ::server-security
    :keys [::chan->server
           ::weald/logger]
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
                                                                                       ::weald/state log-state}))))})]
    {::weald/state log-state
     ::specs/deferrable (dfrd/on-realized d
                                          on-success
                                          on-failure)}))

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
               :timeout number?
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
  [{log-state ::weald/state
    :keys [::chan->server
           ::weald/logger
           ::packet-builder
           ::server-security]
    :as state}
   timeout
   message-block]
  {:pre [packet-builder]}
  (let [message-block (bytes message-block)
        {:keys [::server-cookie
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
    (let [{log-state ::weald/state
           message-packet ::shared/packet} (packet-builder (assoc state ::weald/state log-state)
                                                           message-block)
          raw-message-packet (if message-packet
                               (b-s/convert message-packet specs/byte-array-type)
                               (byte-array 0))
          log-state (log/debug log-state
                               ::child->
                               "Client sending a message packet from child->server"
                               {::shared/message (if message-packet
                                                   (b-t/->string raw-message-packet)
                                                   "No message packet built")
                                ::server-security server-security})
          log-state (log/flush-logs! logger log-state)]
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
            {log-state ::weald/state
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
           ::weald/logger
           ::msg-specs/recent
           ::shared/extension]
    log-state ::weald/state
    :as this}]
  #_{:pre [(and client-extension-load-time recent)]}
  (when-not (and client-extension-load-time recent)
    (when-not client-extension-load-time
      ;; It looks like the key is here, but the value is nil.
      (let [message
            (if (contains? this ::client-extension-load-time)
              "Missing client-extension-load-time"
              "nil-client-extension-load-time")]
        (throw (ex-info message
                        {::problem (keys this)}))))
    (assert recent))
  (let [reload? (>= recent client-extension-load-time)
        log-state (log/debug log-state
                             ::clientextension-init
                             ""
                             {::reload? reload?
                              ::shared/extension extension
                              ::this (dissoc this ::weald/state)})
        client-extension-load-time (if reload?
                                     (+ recent (* 30 shared/nanos-in-second))
                                     client-extension-load-time)
        [extension log-state] (if reload?
                                (try [(-> "/etc/curvecpextension"
                                           ;; This is pretty inefficient...we really only want 16 bytes.
                                           ;; Should be good enough for a starting point, though
                                           slurp
                                           (subs 0 16)
                                           .getBytes)
                                      log-state]
                                     (catch java.io.FileNotFoundException _
                                       ;; This really isn't all that unexpected.
                                       ;; The original goal/dream was to get CurveCP
                                       ;; added as a standard part of every operating
                                       ;; system's network stack, so that this would
                                       ;; become a part of standard unix-based systems.
                                       ;; This is just a demonstrator of how well that
                                       ;; panned out.
                                       [(K/zero-bytes 16)
                                        (log/warn log-state
                                                  ::clientextension-init
                                                  "no /etc/curvecpextension file")]))
                                ;; No reload. Just return what's already here
                                [extension log-state])]
    (assert (= (count extension) K/extension-length))
    (let [log-state (log/info log-state
                              ::clientextension-init
                              "Loaded extension"
                              {::shared/extension (vec extension)})]
      {::client-extension-load-time client-extension-load-time
       ::weald/state log-state
       ::shared/extension extension})))

(s/fdef initialize-immutable-values
        :args (s/cat :this ::immutable-value
                     :log-initializer (s/fspec :args (s/cat)
                                               :ret ::weald/logger))
        :ret ::immutable-value)
(defn initialize-immutable-values
  "Sets up the immutable value that will be used in tandem with the mutable state later"
  [{:keys [::msg-specs/message-loop-name
           ::chan<-server
           ::server-extension
           ::server-ips
           ::specs/executor]
    log-state ::weald/state
    ;; TODO: Play with the numbers here to come up with something reasonable
    :or {executor (exec/utilization-executor cpu-utilization-target)}
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
        (assoc ::weald/logger logger
               ::chan->server (strm/stream)
               ::specs/executor executor)
        (into (load-keys log-state (::shared/my-keys this))))))

(s/fdef initialize-mutable-state!
  :args (s/cat :this ::mutable-state
               :packet-builder ::packet-builder)
  :ret ::mutable-state)
(defn initialize-mutable-state!
  [{:keys [::shared/my-keys
           ::server-security
           ::weald/logger
           ::msg-specs/message-loop-name]
    :as this}
   packet-builder]
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
             ::packet-builder packet-builder
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
             ::weald/state log-state
             ::terminated terminated}))))

(s/fdef fork!
        :args (s/cat :state ::state)
        :ret (s/keys :req [::child/state
                           ::weald/state]))
;; It's tempting to try to deprecate this and just have
;; callers call the version in shared.child instead.
;; That would be a mistake.
;; This serves as an important bridge for helping the
;; coupling between the implementations remain loose.
(defn fork!
  "Create a new Child to do all the interesting work."
  [{:keys [::weald/logger
           ::msg-specs/->child
           ::msg-specs/child-spawner!
           ::msg-specs/message-loop-name]
    log-state ::weald/state
    :as this}]
  {:pre [message-loop-name]}
  (when-not log-state
    (throw (ex-info (str "Missing log state among "
                         (keys this))
                    this)))
  ;; child-send-state is very similar to the idea of immutable
  ;; properties from react.js
  ;; It's tempting to adjust this to that kind of model:
  ;; whatever calls child-> will call it with parameters
  ;; for the immutable properties, along with some kind of
  ;; mutable state that it pulls from a data store.
  ;; Or even dig into the Om Next approach and supply
  ;; query parameters.
  ;; That's really a very different problem domain, but
  ;; it's tempting to consider.
  (let [child-send-state (extract-child-send-state this)
        _ (assert (::specs/inner-i-nonce child-send-state)
                  (str "Missing inner-i-nonce in child-send-state\n"
                       (keys child-send-state)
                       "\namong\n"
                       child-send-state
                       "\nbuilt from\n"
                       (keys this)
                       "\namong\n"
                       this))
        build-params (select-keys this [::weald/logger
                                        ::weald/state
                                        ::msg-specs/->child
                                        ::msg-specs/child-spawner!
                                        ::msg-specs/message-loop-name])
        child-> (partial child->
                         child-send-state
                         (current-timeout this))]
    (into this (child/fork! build-params
                                    child->))))

(s/fdef stop!
        :args (s/cat :this ::state)
        :ret ::weald/state)
(defn do-stop
  [{child-state ::child/state
    log-state ::weald/state
    :as this}]
  (if child-state
    (child/do-halt! log-state child-state)
    (log/warn log-state
              ::do-stop
              "No child message io-loop to stop")))

(s/fdef update-client-short-term-nonce
        :args (s/cat :nonce integer?)
        :ret integer?)
(defn update-client-short-term-nonce
  "Note that this can loop right back to a negative number."
  [nonce]
  (let [result (unchecked-inc (long nonce))]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {::must "End communication immediately"})))
    result))
