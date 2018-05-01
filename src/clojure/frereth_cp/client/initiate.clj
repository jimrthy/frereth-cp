(ns frereth-cp.client.initiate
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.client.message :as message]
            [frereth-cp.client.state :as state]
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

(s/def ::crypto-box bytes?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef build-initiate-interior
        :args (s/cat :this ::state/state
                     :msg bytes?
                     :outer-nonce-suffix bytes?)
        :ret (s/keys :req [::crypto-box ::log/state]))
(defn build-initiate-interior
  "This is the 368+M cryptographic box that's the real payload/Vouch+message portion of the Initiate pack"
  [{log-state ::log/state
    :as this} msg outer-nonce-suffix]
  ;; Important detail: we can use up to 640 bytes that we've
  ;; received from the client/child.
  (let [msg-length (count msg)
        _ (assert (< 0 msg-length))
        tmplt (assoc-in K/vouch-wrapper [::K/child-message ::K/length] msg-length)
        srvr-name (get-in this [::shared/my-keys ::specs/srvr-name])
        _ (assert srvr-name)
        inner-nonce-suffix (::state/inner-i-nonce this)
        ^TweetNaclFast$Box$KeyPair long-pair (get-in this [::shared/my-keys ::shared/long-pair])
        src {::K/client-long-term-key (.getPublicKey long-pair)
             ::K/inner-i-nonce inner-nonce-suffix
             ::K/inner-vouch (::state/vouch this)
             ::specs/srvr-name srvr-name
             ::K/child-message msg}
        work-area (::shared/work-area this)
        secret (get-in this [::state/shared-secrets ::state/client-short<->server-short])
        log-state (log/info log-state
                            ::build-initiate-interior
                            "Encrypting\nFIXME: Do not log the shared secret!"
                            {::source src
                             ::inner-nonce-suffix (b-t/->string inner-nonce-suffix)
                             ::shared-secret (b-t/->string secret)})]
    {::crypto-box (crypto/build-crypto-box tmplt
                                           src
                                           (::shared/text work-area)
                                           secret
                                           K/initiate-nonce-prefix
                                           outer-nonce-suffix)
     ::log/state log-state}))

(s/fdef build-initiate-packet!
        :args (s/cat :this ::state/state
                     :msg-bytes (s/and bytes?
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
        :ret (s/keys :opt [::specs/byte-buf]
                     :req [::log/state]))
(defn build-initiate-packet!
  "Combine message buffer and client state into an Initiate packet

This was destructive in the sense that it overwrites ::shared/work-area
FIXME: Change that"
  [this msg-bytes]
  (let [{log-state ::log/state
         msg ::message/possible-response} (message/filter-initial-message-bytes this
                                                                                msg-bytes)]
    (if msg
      ;; I really don't like this approach to a shared work-area.
      ;; It kind-of made sense with the original approach, which involved
      ;; locking down strict access from a single thread, using an agent.
      ;; Note that this approach is worse than I thought at first glance:
      ;; I'm really just reusing the last-used nonce.
      ;; That seems wrong all around.
      ;; c.f. lines 329-334.
      (let [working-nonce (byte-array K/nonce-length)
            ;; Just reuse a subset of whatever the server sent us.
            ;; Legal because a) it uses a different prefix and b) it's a different number anyway
            ;; Note that this is actually for the *inner* vouch nonce.
            nonce-suffix (b-t/sub-byte-array working-nonce
                                             K/client-nonce-prefix-length)
            {:keys [::crypto-box]
             log-state ::log/state} (build-initiate-interior this msg nonce-suffix)
            log-state (log/info log-state
                                ::build-initiate-packet!
                                "Stuffing crypto-box into Initiate packet"
                                {::crypto-box (b-t/->string crypto-box)
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
                                                 :cookie (get-in this [::state/server-security ::state/server-cookie])
                                                 :outer-i-nonce nonce-suffix
                                                 :vouch-wrapper crypto-box}]
        {::specs/byte-buf
         (serial/compose dscr
                         fields)
         ::log/state log-state})
      {::log/state log-state})))

(s/fdef send-vouch!
        :args (s/cat :this ::state/state)
        :ret (s/merge ::state/state
                      (s/keys :req [::specs/deferred])))
(defn send-vouch!
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
  [this]
  (let [
        {log-state ::log/state
         :keys [::log/logger]
         packet ::vouch} this
        log-state (log/flush-logs! logger log-state)
        this (assoc this ::log/state log-state)
        {log-state ::log/state
         deferred ::specs/deferred}
        ;; FIXME: Instead of this, have HELLO set up a partial or lexical closure
        ;; that we can use to send packets.
        ;; Honestly, most of what I'm passing along in here is overkill that
        ;; I set up for debugging.
        (state/do-send-packet this
                              (fn [success]
                                (log/flush-logs! logger
                                                 (log/info log-state
                                                           ::send-vouch!
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
                                                                ::send-vouch!
                                                                "Sending Initiate packet failed!"
                                                                {::problem failure}))
                                (throw (ex-info "Failed to send cookie->vouch response"
                                                (assoc this
                                                       :problem failure))))
                              (state/current-timeout this)
                              ::sending-vouch-timed-out
                              packet)]
    (assoc this
           ::log/state log-state
           ::specs/deferred deferred)))

(s/fdef build-vouch
  :args (s/cat :this ::state/state)
  :ret (s/keys :req [::inner-i-nonce
                     ::log/state
                     ::state/vouch]))
(defn build-vouch
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
            log-state (try
                        (b-t/byte-copy! working-nonce K/vouch-nonce-prefix)
                        (let [log-state
                              (if keydir
                                (crypto/do-safe-nonce log-state working-nonce keydir K/server-nonce-prefix-length false)
                                (crypto/do-safe-nonce log-state working-nonce K/server-nonce-prefix-length))
                              ^TweetNaclFast$Box$KeyPair short-pair (::shared/short-pair my-keys)]
                          (b-t/byte-copy! text 0 K/key-length (.getPublicKey short-pair))
                          log-state)
                        (catch Exception ex
                          (log/flush-logs! logger (log/exception log-state
                                                                 ex
                                                                 ::build-vouch
                                                                 "Setting up working-nonce or short-pair"))
                          (throw ex)))]
        (if-let [shared-secret (::state/client-long<->server-long shared-secrets)]
          (let [log-state (log/trace log-state
                                   ::build-vouch
                                   (str "Encrypting the inner-most Initiate Vouch\n"
                                        "FIXME: Don't log the shared secret")
                                   {::state/shared-secret (b-t/->string shared-secret)
                                    ::shared/text text
                                    ::key-length K/key-length
                                    ::shared/working-nonce working-nonce})
              log-state (log/flush-logs! logger log-state)
              ;; This is the inner-most secret that the inner vouch hides.
              ;; The point is to allow the server to verify
              ;; that whoever sent this packet truly has access to the
              ;; secret keys associated with both the long-term and short-
              ;; term key's we're claiming for this session.
              encrypted (crypto/box-after shared-secret
                                          text K/key-length working-nonce)
              vouch (byte-array K/vouch-length)
              log-state (log/info log-state
                                  ::build-vouch
                                  (str "Just encrypted the inner-most portion of the Initiate's Vouch\n"
                                       "(FIXME: Don't log the shared secret)")
                                  {::shared/working-nonce (b-t/->string working-nonce)
                                   ::state/shared-secret (b-t/->string shared-secret)})]
            (b-t/byte-copy! vouch
                            0
                            (+ K/box-zero-bytes K/key-length)
                            encrypted)
            {::inner-i-nonce nonce-suffix
             ::log/state log-state
             ::state/vouch vouch})
          (throw (ex-info "Missing long-term shared keys"
                          {::problem shared-secrets}))))
      (assert false (str "Missing nonce in packet-management:\n"
                         (keys packet-management))))))

(s/fdef cookie->vouch
        :args (s/cat :this ::state/state
                     :packet ::shared/network-packet)
        :ret ::state/state)
(defn cookie->vouch
  "Got a cookie from the server.

  Replace those bytes
  in our packet buffer with the vouch bytes we'll use
  as the response.

  Q: How much of a performance hit (if any) am I looking at if I
  make this purely functional instead?"
  [{log-state ::log/state
    :as this}
   {:keys [:host :port]
    ^bytes message :message
    :as cookie-packet}]
  {:pre [cookie-packet]}
  (let [log-state (log/info log-state
                            ::cookie->vouch
                            "Getting ready to convert cookie into a Vouch"
                            {::human-readable-cookie (b-t/->string message)
                             ::shared/network-packet cookie-packet})]
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
                                   ::log/state log-state)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef build-and-send-vouch!
        :args (s/cat :this ::state/state
                     :cookie ::specs/network-packet)
        :ret (s/merge ::state/state
                      (s/keys :req [::specs/deferred])))
(defn build-and-send-vouch!
  "@param this: client-state
  @param cookie-packet: first response from the server

  The current implementation is built around side-effects.

  We send a request to the agent in wrapper to update its state with the
  Vouch, based on the cookie packet. Then we do another send to get it to
  send the vouch.

  This matches the original implementation, but it seems like a really
  terrible approach in an environment that's intended to multi-thread."
  [this cookie-packet]
  (if cookie-packet
    (let [{log-state ::log/state
           logger ::log/logger} this
          ;; Once we've signaled the child to start doing its own thing,
          ;; cope with the cookie we just received.
          this (cookie->vouch (update this
                                      ::log/state
                                      #(log/info %
                                                 ::build-and-send-vouch
                                                 "Converting cookie->vouch"
                                                 {::cause "Received cookie"
                                                  ::effect "Forking child"
                                                  ::state/state (dissoc this ::log/state)}))
                              cookie-packet)
          this (update this
                       ::log/state
                       #(log/flush-logs! logger (log/debug %
                                                           ::build-and-send-vouch
                                                           "cookie converted to vouch")))]
      ;; FIXME: Debug only
      (println "Client built Initiate/Vouch. Sending it")
      (send-vouch! this))
    (throw (ex-info "Should have a valid cookie response packet, but do not"
                            {::state/state this}))))
