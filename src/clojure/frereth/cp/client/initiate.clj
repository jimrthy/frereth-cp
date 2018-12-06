(ns frereth.cp.client.initiate
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth.cp
             [shared :as shared]]
            [frereth.cp.client
             [message :as message]
             [state :as state]]
            [frereth.cp.message.specs :as msg-specs]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [serialization :as serial]
             [specs :as specs]
             [util :as utils]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
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
(s/def ::vouch-building-params (s/keys :req [::weald/logger
                                             ::shared/my-keys
                                             ::state/shared-secrets]))

(s/def ::vouch-encryption-response (s/keys :req [::weald/state
                                                 ::specs/vouch]))
(s/def ::vouch-built (s/merge ::vouch-encryption-respons
                              (s/keys :req [::specs/inner-i-nonce])))

;;; These pieces are about the main message payload
(s/def ::message-building-params (s/merge ::vouch-built
                                          (s/keys :req [::shared/my-keys
                                                        ::state/shared-secrets])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef build-initiate-interior
        :args (s/cat :this ::message-building-params
                     :msg bytes?
                     :outer-nonce-suffix bytes?)
        :ret (s/keys :req [::specs/crypto-box ::weald/state]))
(defn build-initiate-interior
  "This is the 368+M cryptographic box that's the real payload/Vouch+message portion of the Initiate pack"
  [{log-state ::weald/state
    inner-nonce-suffix ::specs/inner-i-nonce
    {^TweetNaclFast$Box$KeyPair long-pair ::shared/long-pair
     :keys [::specs/srvr-name]} ::shared/my-keys
    :keys [::specs/vouch
           ::state/shared-secrets]
    :as this}
   msg
   outer-nonce-suffix]
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
      (let [my-long-pk (.getPublicKey long-pair)
            src {::K/client-long-term-key my-long-pk
                 ;; FIXME: Need to verify that the inner vouch portions
                 ;; are OK to resend and don't compromise anything.
                 ;; (soon)
                 ;; I'm pretty sure this is a faithful translation
                 ;; of what the reference implementation does, but
                 ;; I could very well have misunderstood this part
                 ;; originally.
                 ::K/inner-i-nonce inner-nonce-suffix
                 ::K/inner-vouch vouch
                 ::K/srvr-name srvr-name
                 ::K/child-message msg}
            secret (::state/client-short<->server-short shared-secrets)
            _ (assert secret (str "Missing shared-short secret among '"
                                  shared-secrets
                                  "'\nin\n"
                                  this))
            crypto-box (crypto/build-box tmplt
                                         src
                                         secret
                                         K/initiate-nonce-prefix
                                         outer-nonce-suffix)
            log-state (log/info log-state
                                ::build-initiate-interior
                                "Encrypting\nFIXME: Do not log the shared secret!"
                                {::my-long-pk (b-t/->string my-long-pk)
                                 ::K/inner-i-nonce (if inner-nonce-suffix
                                                     (b-t/->string inner-nonce-suffix)
                                                     (assoc this
                                                            ::problem
                                                            "Missing"))
                                 ::shared-secret (b-t/->string secret)
                                 ::specs/crypto-box (b-t/->string crypto-box)})]
        {::specs/crypto-box crypto-box
         ::weald/state log-state})
      {::weald/state (log/warn log-state
                             ::build-initiate-interior
                             "Missing server name"
                             (select-keys this [::shared/my-keys]))})))

(s/fdef build-initiate-packet
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
        :ret (s/keys :req [::weald/state]
                     :opt [::shared/packet]))
(defn build-initiate-packet
  "Combine message buffer and client state into an Initiate packet"
  [{log-state ::weald/state
    :keys [::weald/logger
           ::msg-specs/message-loop-name
           ::state/server-security]
    :as this}
   ^bytes msg]
  (let [log-state (log/debug log-state
                             ::build-initiate-packet
                             "Trying to build initiated packet"
                             {::msg-specs/message-loop-name (or message-loop-name
                                                                (str "'Name Missing', among:\n" (keys this)))
                              ::message-length (count msg)
                              ::incoming-bytes-in msg})
        {:keys [::state/server-cookie]} server-security]
    (when-not server-cookie
      (throw (ex-info "Missing server-cookie"
                      {::state/server-security server-security})))
    (if msg
      (if (K/legal-vouch-message-length? msg)
        ;; c.f. lines 329-334 in the reference spec.
        (let [{log-state ::weald/state
               nonce-suffix ::specs/client-nonce-suffix} (crypto/get-safe-client-nonce-suffix log-state)
              {:keys [::specs/crypto-box]
               log-state ::weald/state
               :as initiate-interior} (build-initiate-interior (select-keys this
                                                                            [::weald/state
                                                                             ::shared/my-keys
                                                                             ::specs/inner-i-nonce
                                                                             ::specs/vouch
                                                                             ::state/shared-secrets])
                                                               msg
                                                               nonce-suffix)]
          (if crypto-box
            (let [log-state (log/info log-state
                                      ::build-initiate-packet
                                      "Stuffing crypto-box into Initiate packet"
                                      {::specs/crypto-box (when crypto-box
                                                            (b-t/->string crypto-box))
                                       ::message-length (count crypto-box)})
                  dscr (update-in K/initiate-packet-dscr
                                  [::K/vouch-wrapper ::K/length]
                                  +
                                  (count msg))
                  ^TweetNaclFast$Box$KeyPair short-pair (get-in this [::shared/my-keys ::shared/short-pair])
                  fields #:frereth.cp.shared.constants{:prefix K/initiate-header
                                                       :srvr-xtn (::state/server-extension this)
                                                       :clnt-xtn (::shared/extension this)
                                                       :clnt-short-pk (.getPublicKey short-pair)
                                                       :cookie (get-in this
                                                                       [::state/server-security
                                                                        ::state/server-cookie])
                                                       :outer-i-nonce nonce-suffix
                                                       :vouch-wrapper crypto-box}
                  raw-result-bytes (serial/compose dscr
                                                   fields)
                  result-bytes (b-s/convert raw-result-bytes specs/byte-array-type)
                  {log-state ::weald/state
                   result ::message/possible-response
                   :as filtered} (message/filter-initial-message-bytes log-state
                                                                       result-bytes)]
              {::weald/state (log/debug log-state
                                        ::build-initiate-packet
                                        ""
                                        {::filtered filtered})
               ::shared/packet result})
            (do
              (log/flush-logs! logger log-state)
              (throw (ex-info "Building initiate-interior failed to generate a crypto-box"
                              {::problem (dissoc initiate-interior
                                                 ::weald/state)})))))
        {::weald/state (log/warn log-state
                                 ::build-initiate-packet
                                 "Invalid message length from child"
                                 {::message-length (count msg)})})
      (do
        (log/flush-logs! logger log-state)
        (throw (ex-info "Missing outgoing message"
                {::specs/msg-bytes msg}))))))

(s/fdef encrypt-inner-vouch
        :args (s/cat :log-state ::weald/state
                     :shared-secret ::shared/shared-secret
                     :nonce-suffix ::specs/server-nonce-suffix
                     :clear-text ::shared/text)
        :ret ::vouch-encryption-response)
(defn encrypt-inner-vouch
  "Encrypt the inner-most crypto box"
  [log-state shared-secret nonce-suffix clear-text]
  ;; This is the inner-most secret that the inner vouch hides.
  ;; The point is to allow the server to verify
  ;; that whoever sent this packet truly has access to the
  ;; secret keys associated with both the long-term and short-
  ;; term key's we're claiming for this session.
  (let [nonce (byte-array K/nonce-length)]
    (b-t/byte-copy! nonce K/vouch-nonce-prefix)
    (b-t/byte-copy! nonce
                    specs/server-nonce-prefix-length
                    specs/server-nonce-suffix-length
                    nonce-suffix)
    (let [vouch (crypto/box-after shared-secret
                                  clear-text
                                  K/key-length  ; looks weird, but we're encrypting a key
                                  nonce)
          log-state (log/info log-state
                              ::encrypt-inner-vouch
                              (str "Just encrypted the inner-most portion of the Initiate's Vouch\n"
                                   "(FIXME: Don't log the shared secret)")
                              {::shared/safe-nonce (b-t/->string nonce)
                               ::state/shared-secret (b-t/->string shared-secret)
                               ::specs/vouch (b-t/->string vouch)})]
      {::weald/state log-state
       ::specs/vouch vouch})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef build-inner-vouch
  :args (s/cat :this ::vouch-building-params)
  :ret ::vouch-built)
(defn build-inner-vouch
  "Build the innermost vouch/nonce pair"
  [{:keys [::shared/my-keys
           ::state/shared-secrets]
    log-state ::weald/state
    :as this}]
  (let [{log-state ::weald/state
         nonce-suffix ::specs/server-nonce-suffix} (crypto/get-safe-server-nonce-suffix log-state)
        ;; FIXME: This really belongs inside its own try/catch
        ;; block.
        ;; Unfortunately, that isn't trivial, because the nested
        ;; pieces below here can/will throw their own exceptions
        ;; that I don't want to handle.
        ^TweetNaclFast$Box$KeyPair short-pair (::shared/short-pair my-keys)
        clear-text (byte-array K/key-length)]
    (b-t/byte-copy! clear-text 0 K/key-length (.getPublicKey short-pair))
    (if-let [shared-secret (::state/client-long<->server-long shared-secrets)]
      (let [{log-state ::weald/state
             :keys [::specs/vouch]} (encrypt-inner-vouch log-state
                                                         shared-secret
                                                         nonce-suffix
                                                         clear-text)]
        (assert log-state)
        {::specs/inner-i-nonce nonce-suffix
         ::weald/state log-state
         ::specs/vouch vouch})
      (throw (ex-info "Missing long-term shared keys"
                      {::problem shared-secrets})))))

(s/fdef initial-packet-sent
        :args (s/cat :logger ::weald/logger
                     :log-state-atom ::weald/state-atom
                     :this ::state/state)
        :ret ::state/state)
(defn initial-packet-sent
  "Initiate packet was put onto wire"
  [{log-state ::weald/state
    :keys [::weald/logger]
    :as this}]
  {:pre [log-state]}
  (if (not (or (= this ::state/sending-vouch-timed-out)
               (= this ::state/drained)))
    (let [log-state (log/flush-logs! logger
                                     (log/info log-state
                                               ::initial-packet-sent
                                               "Vouch sent (maybe)"
                                               {::sent this}))]
      ;; These parameters are wrong
      ;; And we can't do this yet: have to wait for a Message
      ;; Packet to come back.
      (state/->message-exchange-mode  (assoc this
                                             ::weald/state log-state)
                                      ;; Q: When/where does this message actually
                                      ;; arrive?
                                      #_(throw (RuntimeException. "This parameter should be the initial response Message"))
                                      nil))
    (let [failure (ex-info "Something about polling/sending Initiate failed"
                           {::problem this})]
      (update this ::weald/state #(log/flush-logs! logger
                                                   (log/exception %
                                                                  failure
                                                                  ::initial-packet-sent))))))
