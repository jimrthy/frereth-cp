(ns frereth-cp.client.initiate
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.client.message :as message]
            [frereth-cp.client.state :as state]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;; These pieces are about the innermost nonce
(s/def ::vouch-building-params (s/keys :req [::log/logger
                                             ::shared/my-keys
                                             ::shared/packet-management
                                             ::state/shared-secrets
                                             ::shared/work-area]))
(s/def ::vouch-built (s/keys :req [::specs/inner-i-nonce
                                   ::log/state
                                   ::specs/vouch]))

;;; These pieces are about the main message payload
(s/def ::message-building-params (s/keys :req [::log/state
                                               ::specs/inner-i-nonce
                                               ::shared/my-keys
                                               ::shared/work-area
                                               ::specs/vouch
                                               ::state/shared-secrets]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef build-initiate-interior
        :args (s/cat :this ::message-building-params
                     :msg bytes?
                     :outer-nonce-suffix bytes?)
        :ret (s/keys :req [::specs/crypto-box ::log/state]))
(defn build-initiate-interior
  "This is the 368+M cryptographic box that's the real payload/Vouch+message portion of the Initiate pack"
  [{log-state ::log/state
    inner-nonce-suffix ::specs/inner-i-nonce
    {^TweetNaclFast$Box$KeyPair long-pair ::shared/long-pair
     :keys [::specs/srvr-name]} ::shared/my-keys
    :keys [::shared/work-area
           ::specs/vouch
           ::state/shared-secrets]
    :as this}
   msg
   outer-nonce-suffix]
  #_{:pre [inner-nonce-suffix]}
  (assert inner-nonce-suffix (str "Missing ::specs/inner-i-nonce among\n"
                                  (keys this)
                                  "\nin\n"
                                  this))
  ;; Important detail: we can use up to 640 bytes that we've
  ;; received from the client/child.
  (let [msg-length (count msg)
        _ (assert (< 0 msg-length))
        tmplt (assoc-in K/vouch-wrapper [::K/child-message ::K/length] msg-length)]
    (if srvr-name
      (let [src {::K/client-long-term-key (.getPublicKey long-pair)
                 ::K/inner-i-nonce inner-nonce-suffix
                 ::K/inner-vouch vouch
                 ::K/srvr-name srvr-name
                 ::K/child-message msg}
            secret (::state/client-short<->server-short shared-secrets)
            log-state (log/info log-state
                                ::build-initiate-interior
                                "Encrypting\nFIXME: Do not log the shared secret!"
                                {::source src
                                 ::inner-nonce-suffix (if inner-nonce-suffix
                                                        (b-t/->string inner-nonce-suffix)
                                                        (assoc this
                                                               ::problem
                                                               "Missing"))
                                 ::shared-secret (b-t/->string secret)})]
        {::specs/crypto-box (crypto/build-crypto-box tmplt
                                                     src
                                                     secret
                                                     K/initiate-nonce-prefix
                                                     outer-nonce-suffix)
         ::log/state log-state})
      {::log/state (log/warn log-state
                             ::build-initiate-interior
                             "Missing server name"
                             (select-keys this [::shared/my-keys]))})))

(s/fdef build-initiate-packet!
        :args (s/cat :this ::state/initiate-building-params
                     :msg-bytes (s/and ::specs/msg-bytes
                                       ;; Just be explicit about the
                                       ;; the legal incoming length.
                                       ;; This is mostly for the sake of
                                       ;; documentation.
                                       (fn [bs]
                                         (let [{:keys [::message/possible-response]}
                                               (message/filter-initial-message-bytes bs)]
                                           possible-response))))
        :fn (fn [x]
              (let [legal-to-send (-> x
                                      :args
                                      :msg-bytes
                                      message/filter-initial-message-bytes
                                      ::message/possible-response)
                    real-result (-> x
                                    :ret
                                    ::specs/byte-buf)]
                (= (count real-result)
                   (+ 544 (count legal-to-send)))
                true))
        :ret ::specs/byte-buf)
(defn build-initiate-packet!
  "Combine message buffer and client state into an Initiate packet

This is destructive in the sense that it overwrites ::shared/work-area
FIXME: Change that"
  [{log-state ::log/state
    :keys [::log/logger
           ::msg-specs/message-loop-name]
    :as this}
   ^bytes msg]
  (println "Thread:" (utils/get-current-thread)
           "Message Loop:" (if-let [loop-name message-loop-name]
                             loop-name
                             (str "'Name Missing', among:\n" (keys this)))
           "Trying to build initiated packet based on" (count msg)
           "incoming bytes in" msg)
  (when-not msg
    (log/flush-logs! logger log-state)
    (throw (ex-info
            {::specs/msg-bytes msg}))"Missing outgoing message")

  ;; I really don't like this approach to a shared work-area.
  ;; It kind-of made sense with the original approach, which involved
  ;; locking down strict access from a single thread, using an agent.
  ;; Note that this approach is worse than I thought at first glance:
  ;; I'm really just reusing the last-used nonce (which, in theory,
  ;; should be the one sent by the server for its cookie).
  ;; That seems wrong all around. After all, the client can send Initiate
  ;; packets any time it likes.
  ;; c.f. lines 329-334 in the reference spec.
  (let [working-nonce (byte-array K/nonce-length)
        ;; Just reuse a subset of whatever the server sent us.
        ;; Legal for the original Initiate Packet  because
        ;; a) it uses a different prefix and
        ;; b) it's a subset of the bytes the server really used anyway
        ;; Note that this is actually for the *inner* vouch nonce.
        ;; Which gets gets re-encrypted inside the Message chunk
        ;; of the actual Initiate Packet.
        ;; I'm going to trust the cryptographers about safety here.
        nonce-suffix (b-t/sub-byte-array working-nonce
                                         K/client-nonce-prefix-length)
        {:keys [::specs/crypto-box]
         log-state ::log/state
         :as initiate-interior} (build-initiate-interior (select-keys this
                                                                      [::log/state
                                                                       ::shared/my-keys
                                                                       ::shared/work-area
                                                                       ::specs/inner-i-nonce
                                                                       ::specs/vouch
                                                                       ::state/shared-secrets])
                                                         msg
                                                         nonce-suffix)]
    (if crypto-box
      (let [log-state (log/info log-state
                                ::build-initiate-packet!
                                "Stuffing crypto-box into Initiate packet"
                                {::specs/crypto-box (when crypto-box
                                                      (b-t/->string crypto-box))
                                 ::message-length (count crypto-box)})
            dscr (update-in K/initiate-packet-dscr
                            [::K/vouch-wrapper ::K/length]
                            +
                            (count msg))
            ^TweetNaclFast$Box$KeyPair short-pair (get-in this [::shared/my-keys ::shared/short-pair])
            fields #:frereth-cp.shared.constants{:prefix K/initiate-header
                                                 :srvr-xtn (::state/server-extension this)
                                                 :clnt-xtn (::shared/extension this)
                                                 :clnt-short-pk (.getPublicKey short-pair)
                                                 :cookie (get-in this
                                                                 [::state/server-security
                                                                  ::state/server-cookie])
                                                 :outer-i-nonce nonce-suffix
                                                 :vouch-wrapper crypto-box}
            result-bytes (serial/compose dscr
                                         fields)
            {log-state ::log/state
             result ::message/possible-response
             :as filtered} (message/filter-initial-message-bytes log-state
                                                                 result-bytes)]
        (log/flush-logs! logger log-state)
        result)
      (do
        (log/flush-logs! logger log-state)
        (throw (ex-info "Building initiate-interior failed to generate a crypto-box"
                        {::problem (dissoc initiate-interior
                                           ::log/state)}))))))

(s/fdef do-send-vouch
        :args (s/cat :this ::state/state
                     :message ::specs/msg-bytes)
        :ret (s/keys :req [::specs/deferred
                           ::state/state]))
(defn do-send-vouch
  "Send a Vouch/Initiate packet (along with a Message sub-packet)"
  ;; We may have to send this multiple times, because it could
  ;; very well get dropped.

  ;; Actually, if that happens, it might make sense to just start
  ;; over from the initial HELLO.
  ;; Reference implementation doesn't seem to have anything along
  ;; those lines.
  ;; Once a Server sends back a Cookie, it looks as though the
  ;; Client is irrevocably tied to it.
  ;; This seems like a protocol flaw that's better addressed by
  ;; haproxy. Especially since the child's only clue that a
  ;; server has quit responding is that its write buffer is full.

  ;; Depending on how much time we want to spend waiting for the
  ;; initial server message
  ;; (this is one of the big reasons the
  ;; reference implementation starts out trying to contact
  ;; multiple servers).

  ;; It would be very easy to just wait
  ;; for its minute key to definitely time out, though that seems
  ;; like a naive approach with a terrible user experience.
  [{log-state ::log/state
    :keys [::log/logger]
    :as this}
   packet]
  (if packet
    (let [log-state (log/flush-logs! logger log-state)
          this (assoc this ::log/state log-state)
          {log-state ::log/state
           deferred ::specs/deferred}
          ;; FIXME: Instead of this, have HELLO set up a partial or lexical closure
          ;; that we can use to send packets.
          ;; (it's pretty close)
          ;; Honestly, most of what I'm passing along in here is overkill that
          ;; I set up for debugging.
          (state/do-send-packet this
                                (fn [success]
                                  (log/flush-logs! logger
                                                   (log/info log-state
                                                             ::do-send-vouch
                                                             "Initiate packet sent.\nWaiting for 1st message"
                                                             {::success success}))
                                  (state/final-wait this success))
                                (fn [failure]
                                  ;; Extremely unlikely, but
                                  ;; just for the sake of paranoia
                                  (log/flush-logs! logger
                                                   (log/exception log-state
                                                                  ;; Q: Am I absolutely positive that this will
                                                                  ;; always be an exception?
                                                                  ;; A: Even if it isn't the logger needs to be
                                                                  ;; able to cope with other problems
                                                                  failure
                                                                  ::do-send-vouch
                                                                  "Sending Initiate packet failed!"
                                                                  {::problem failure}))
                                  (throw (ex-info "Failed to send cookie->vouch response"
                                                  (assoc this
                                                         :problem failure))))
                                (state/current-timeout this)
                                ::sending-vouch-timed-out
                                packet)]
      {::state/state (assoc this
                            ::log/state log-state)
       ::specs/deferrable deferred})
    (assoc this
           ::log/state (log/warn log-state
                                 ::do-send-vouch
                                 "No message bytes to send")
           ::specs/deferrable (dfrd/success-deferred ::nothing-to-send))))

(s/fdef build-working-nonce!
        :args (s/cat :logger ::log/logger
                     :log-state ::log/state
                     :keydir ::shared/keydir
                     :working-nonce ::shared/working-nonce)
        :ret ::log/state)
(defn build-working-nonce!
  "Destructively build up the nonce used to encrypt the innermost Vouch"
  [logger
   log-state
   keydir
   working-nonce]
  (try
    (b-t/byte-copy! working-nonce K/vouch-nonce-prefix)
    (let [log-state
          (if keydir
            (crypto/do-safe-nonce log-state working-nonce keydir K/server-nonce-prefix-length false)
            (crypto/do-safe-nonce log-state working-nonce K/server-nonce-prefix-length))]
      log-state)
    (catch Exception ex
      (log/flush-logs! logger (log/exception log-state
                                             ex
                                             ::build-vouch
                                             "Setting up working-nonce"))
      (throw ex))))

(s/fdef encrypt-inner-vouch
        :args (s/cat :log-state ::log/state
                     :shared-secret ::shared/shared-secret
                     :working-nonce ::specs/nonce
                     :clear-text ::shared/text))
(defn encrypt-inner-vouch
  "Encrypt the inner-most crypto box"
  [log-state shared-secret working-nonce clear-text]
  ;; This is the inner-most secret that the inner vouch hides.
  ;; The point is to allow the server to verify
  ;; that whoever sent this packet truly has access to the
  ;; secret keys associated with both the long-term and short-
  ;; term key's we're claiming for this session.
  (let [encrypted (crypto/box-after shared-secret
                                    clear-text K/key-length working-nonce)
        vouch (byte-array K/vouch-length)
        log-state (log/info log-state
                            ::build-vouch
                            (str "Just encrypted the inner-most portion of the Initiate's Vouch\n"
                                 "(FIXME: Don't log the shared secret)")
                            {::shared/working-nonce (b-t/->string working-nonce)
                             ::state/shared-secret (b-t/->string shared-secret)
                             ::specs/vouch (b-t/->string vouch)})]
    (b-t/byte-copy! vouch
                    0
                    (+ K/box-zero-bytes K/key-length)
                    encrypted)
    {::log/state log-state
     ::specs/vouch vouch}))

(s/fdef build-inner-vouch
  :args (s/cat :this ::vouch-building-params)
  :ret ::vouch-built)
(defn build-inner-vouch
  "Build the innermost vouch/nonce pair"
  ;; This has really been refactored out of cookie->vouch,
  ;; as a first step toward making the bites a little more
  ;; digestible. TODO: Continue that process.
  [{:keys [::log/logger
           ::shared/my-keys
           ::shared/packet-management
           ::state/shared-secrets
           ::shared/work-area]
    log-state ::log/state
    :as this}]
  (let [{:keys [::shared/working-nonce
                ::shared/text]} work-area
        keydir (::shared/keydir my-keys)
        nonce-suffix (byte-array K/server-nonce-suffix-length)]
    (if working-nonce
      (let [log-state (log/info log-state
                                ::build-vouch
                                "Setting up working nonce"
                                {::shared/working-nonce working-nonce})
            log-state (build-working-nonce! logger
                                            log-state
                                            keydir
                                            working-nonce)
            ;; FIXME: This really belongs inside its own try/catch
            ;; block.
            ;; Unfortunately, that isn't trivial, because the nested
            ;; pieces below here can/will throw their own exceptions.
            ^TweetNaclFast$Box$KeyPair short-pair (::shared/short-pair my-keys)]
        (b-t/byte-copy! text 0 K/key-length (.getPublicKey short-pair))
        (if-let [shared-secret (::state/client-long<->server-long shared-secrets)]
          (let [log-state (log/debug log-state
                                     ::build-vouch
                                     (str "Encrypting the inner-most Initiate Vouch\n"
                                          "FIXME: Don't log the shared secret")
                                     {::state/shared-secret (b-t/->string shared-secret)
                                      ::shared/text text
                                      ::key-length K/key-length
                                      ::shared/working-nonce working-nonce})
                {log-state ::log/state
                 :keys [::specs/vouch]} (encrypt-inner-vouch log-state
                                                             shared-secret
                                                             working-nonce
                                                             text)]
            (comment (throw (RuntimeException. "Start back here.")))
            (assert log-state)
            {::specs/inner-i-nonce nonce-suffix
             ::log/state log-state
             ::specs/vouch vouch})
          (throw (ex-info "Missing long-term shared keys"
                          {::problem shared-secrets}))))
      (assert false (str "Missing nonce in packet-management:\n"
                         (keys packet-management))))))

(s/fdef cookie->initiate
        :args (s/cat :this ::state/state
                     :cookie-packet ::shared/network-packet)
        :ret (s/keys :req [::log/state]
                     :opt [::specs/byte-buf]))
(defn cookie->initiate
  "Got a cookie from the server.

  Replace those bytes
  in our packet buffer with the vouch bytes we'll use
  as the response.

  Q: How much of a performance hit (if any) am I looking at if I
  make this purely functional instead?"
  [{log-state ::log/state
    :as this}
   {:keys [:host :port]
   ^bytes cookie :message
   :as cookie-packet}]
  {:pre [cookie-packet]}
  (let [log-state (log/info log-state
                            ::cookie->vouch
                            "Getting ready to convert cookie into a Vouch"
                            {::human-readable-cookie (b-t/->string cookie)
                             ::shared/network-packet cookie-packet})
        ;; Note that this supplies new state
        ;; Though whether it should is debatable.
        ;; Q: why would I put this into ::vouch?
        ;; A: In case we need to resend it.
        ;; It's perfectly legal to send as many Initiate
        ;; packets as the client chooses.
        ;; This is especially important before the Server
        ;; has responded with its first Message so the client
        ;; can switch to sending those.
        {log-state ::log/state
         :keys [::specs/vouch]
         :as built-vouch} (build-inner-vouch (assoc this
                                                    ::log/state log-state))]
    (assert log-state)
    (assert vouch (str "Missing vouch among\n"
                       (keys built-vouch)
                       "\nin\n"
                       built-vouch))
    (when-not (s/valid? ::specs/vouch vouch)
      (throw (ex-info "Invalid vouch built"
                      {::state/state this
                       ::problem (s/explain-data ::specs/vouch vouch)})))
    ;; I was originally pulling cookie from.
    ;; This makes me doubt my diagnosis about what/where cookie-packet
    ;; is/came from
    (comment (get-in this [::state/server-security ::state/server-cookie]))
    (let [overrides-from-vouch-building (select-keys built-vouch
                                                    [::log/state
                                                     ::shared/my-keys
                                                     ::shared/work-area
                                                     ::specs/inner-i-nonce
                                                     ;; FIXME: Deliberate!
                                                     #_::specs/vouch-broken
                                                     ;; Comment this out to
                                                     ;; kill the stack
                                                     ;; overflow error and
                                                     ;; restore false
                                                     ;; positive for my
                                                     ;; handshake test
                                                     ::specs/vouch
                                                     ::state/server-security
                                                     ::state/shared-secrets])]
      (println "Overrides retrieved from vouch building:\n"
               overrides-from-vouch-building
               "\nbased upon\n"
               (keys built-vouch)
               "\nfrom\n"
               built-vouch
               "\noverriding\n"
               (keys this)
               "\nin\n"
               this)
      (build-initiate-packet! (into this overrides-from-vouch-building)
                              cookie
                              ;; Q: where should this message come from then?
                              ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

;; FIXME: Refactor/rename to do-build-and-send-vouch
;; Because the return value does matter
(s/fdef build-and-send-vouch!
        :args (s/cat :this ::state/state
                     :cookie ::specs/network-packet)
        :ret (s/keys :req [::specs/deferrable
                           ::log/state]))
(defn build-and-send-vouch!
  "@param this: client-state
  @param cookie-packet: first response from the server"
  [this cookie-packet]
  ;; However:
  ;; we do have to set up the packet builder to include the
  ;; cookie packet.
  ;; Right?
  ;; Wrong.
  ;; It's included in (::state/server-security this)
  (throw (RuntimeException. "obsolete"))
  (if cookie-packet
    (let [{log-state ::log/state
           logger ::log/logger} this
          log-state (log/info log-state
                              ::build-and-send-vouch!
                              "Converting cookie->vouch"
                              {::cause "Received cookie"
                               ::effect "Forking child"
                               ::state/state (dissoc this ::log/state)})
          ;; Once we've signaled the child to start doing its own thing,
          ;; cope with the cookie we just received.
          ;; Honestly, we shouldn't send it any more of `this` than
          ;; it absolutely needs
          ;; TODO: Those changes
          {byte-buf ::specs/byte-buf
           log-state ::log/state} (cookie->initiate (assoc this ::log/state log-state)
                                                    cookie-packet)]
      (try
        ;; FIXME: Debug only
        (println "Client built Initiate/Vouch. Sending" byte-buf)
        (let [base-result (do-send-vouch (assoc this
                                                ::log/state
                                                log-state)
                                         byte-buf)]
          (update-in base-result
                     [::state/state ::log/state]
                     #(log/flush-logs! logger %)))
        (catch Exception ex
          (update this
                  ::log/state #(log/flush-logs! logger (log/exception %
                                                                      ex
                                                                      ::build-and-send-vouch!))))))
    (throw (ex-info "Should have a valid cookie response packet, but do not"
                            {::state/state this}))))
