(ns frereth-cp.server.hello
  "For coping with incoming HELLO packets"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.server.cookie :as cookie]
            [frereth-cp.server.helpers :as helpers]
            [frereth-cp.server.shared-specs :as srvr-specs]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream])
  (:import com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::opened (s/nilable ::crypto/unboxed))
(s/def ::shared-secret ::specs/crypto-key)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef open-hello-crypto-box
        :args (s/cat :state ::state/state
                     :message any?
                     :crypto-box ::K/crypto-box)
        :ret (s/keys :req [::log2/state ::opened ::shared-secret]))
(defn open-hello-crypto-box
  [{:keys [::client-short-pk
           ::state/cookie-cutter]
    ^bytes nonce-suffix ::nonce-suffix
    {^TweetNaclFast$Box$KeyPair long-keys ::shared/long-pair
     :as my-keys} ::shared/my-keys
    log-state ::log2/state
    :as state}
   message
   ^bytes crypto-box]
  {:pre [log-state]}
  (when-not long-keys
    ;; Log whichever was missing and throw
    (let [log-state
          (if my-keys
            (log2/error log-state
                        ::open-hello-crypto-box
                        "Missing ::shared/long-pair"
                        {::available-keys (keys my-keys)})
            (log2/error log-state
                        "Missing ::shared/my-keys"
                        {::available-keys (keys state)}))])
    (throw (ex-info "Missing long-term keypair" log-state)))
  (let [my-sk (.getSecretKey long-keys)
        ;; Q: Is this worth saving? It's used again for
        ;; the outer crypto-box in the Cookie from the server
        shared-secret (crypto/box-prepare client-short-pk my-sk)
        log-state (log2/debug log-state
                              ::open-hello-crypto-box
                              "Incoming HELLO"
                              {::client-short-pk (with-out-str (b-s/print-bytes client-short-pk))
                               ::my-long-pk (with-out-str (b-s/print-bytes (.getPublicKey long-keys)))})
        log-state (log2/debug log-state
                              ::open-hello-crypto-box
                              "Trying to open"
                              {::box-length K/hello-crypto-box-length
                               ::crypto-box (with-out-str (b-s/print-bytes crypto-box))
                               ::shared/nonce-suffix (with-out-str (b-s/print-bytes nonce-suffix))})
        {:keys [::log2/state ::crypto/unboxed]} (crypto/open-crypto-box
                                                 log-state
                                                 K/hello-nonce-prefix
                                                 nonce-suffix
                                                 crypto-box
                                                 shared-secret)]
    {::log2/state log-state
     ::opened unboxed
     ::shared-secret shared-secret}))

(s/fdef open-packet
        ;; The thing about this approach is that, realistically,
        ;; we also need all the pieces in ::state/state
        ;; that open-hello-crypto-box needs.
        ;; Q: Would s/and make sense to emphasize that we
        ;; really want to be positive that we have log-state here?
        :args (s/cat :state (s/keys :req [::log2/state
                                          ::state/current-client])
                     :message bytes?)
        :ret (s/keys :req [::K/hello-spec ::log2/state ::opened ::shared-secret]))
(defn open-packet
  [{:keys [::state/current-client]
    log-state ::log2/state
    :as state}
   ^bytes message]
  (let [length (count message)]
    (if (= length K/hello-packet-length)
      (let [log-state (log2/info log-state
                                 ::open-packet
                                 "This is the correct size")
            ;; Q: Is the convenience here worth the [hypothetical] performance hit of using decompose?
            {:keys [::K/clnt-xtn
                    ::K/crypto-box
                    ::K/client-nonce-suffix
                    ::K/srvr-xtn]
             ^bytes clnt-short-pk ::K/clnt-short-pk
             :as decomposed} (serial/decompose-array K/hello-packet-dscr message)
            ;; We're keeping a ByteArray around for storing the key received by the current message.
            ;; The reference implementation just stores it in a global.
            ;; This undeniably has some impact on GC.
            ;; Q: Is it enough to justify doing something this unusual?
            ;; (it probably makes a lot more sense in C where you don't have a lot of great alternatives)
            ;; TODO: Get benchmarks both ways.
            ;; I'm very skeptical that this is worth the wonkiness, but I'm also
            ;; very skeptical about messing around with the reference implementation.
            ^bytes client-short-pk (get-in state [::state/current-client ::state/client-security ::shared/short-pk])]
        (when (not client-short-pk)
          (let [log-state
                (if current-client
                  (if-let [sec (::state/client-security current-client)]
                    (if-let [short-pk (::shared/short-pk sec)]
                      (log2/error log-state
                                  ::open-packet
                                  "Don't understand why we're about to have a problem. It's right here"
                                  (helpers/hide-long-arrays state))
                      (log2/error log-state
                                  ::open-packet
                                  "Missing short-term public-key array among"
                                  sec))
                    (log2/error log-state
                                ::open-packet
                                "Missing :client-security among"
                                current-client))
                  (log2/error log-state
                              ::open-packet
                              "Missing :current-client among"
                              state))]
            (throw (ex-info "Missing spot for client short-term public key" (assoc state ::log2/state log-state)))))
        (when (not clnt-short-pk)
          (throw (ex-info "HELLO packet missed client short-term pk" decomposed)))
        ;; Q: Is there any real point to this?
        (log/info "Copying incoming short-pk bytes from" clnt-short-pk "a" (class clnt-short-pk))
        ;; Destructively overwriting the contents of the destination B] absolutely reeks.
        ;; It seems like it would be much better to just assoc in the new B] containing
        ;; the key and move along.
        ;; Then again, this entire giant side-effecting mess is awful.
        (b-t/byte-copy! client-short-pk clnt-short-pk)
        (assoc
         (open-hello-crypto-box (assoc state
                                       ::client-short-pk client-short-pk
                                       ::nonce-suffix client-nonce-suffix)
                                message
                                crypto-box)
         ::K/hello-spec decomposed))
      (throw (ex-info "Wrong size for a HELLO packet"
                      {::actual (count message)
                       ::expected K/hello-packet-length})))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-handle
        ;; Passing around ::state/state everywhere was lazy/dumb.
        ;; TODO: Be more explicit about which keys we really and truly need.
        :args (s/cat :state ::state/state
                     :packet ::shared/message)
        :ret (s/keys :opt [::K/hello-spec ::srvr-specs/cookie-components]
                     :req [::log2/state]))
(defn do-handle
  [{:keys [::shared/working-area]
    log-state ::log2/state
    :as state}
   ;; TODO: Evaluate the impact of just using bytes instead
   ^ByteBuf message]
  (log/debug "Have what looks like a HELLO packet")
  (let [{:keys [::shared-secret]
         clear-text ::opened
         {:keys [::K/clnt-short-pk
                 ::K/clnt-xtn
                 ::K/srvr-xtn
                 ::K/crypto-box]
          :as fields} ::K/hello-spec
         :as unboxed} (open-packet state message)
        log-state (log2/info log-state
                             ::do-handle
                             "box opened successfully")]
    ;; We don't actually care about the contents of the bytes we just decrypted.
    ;; They should be all zeroes for now, but that's really an area for possible future
    ;; expansion.
    ;; For now, the point is that they unboxed correctly, so the client has our public
    ;; key and the short-term private key so it didn't just send us random garbage.
    (if clear-text
      (let [minute-key (get-in state [::state/cookie-cutter ::state/minute-key])
            {:keys [::shared/text
                    ::shared/working-nonce]} working-area]
        (assert minute-key (str "Missing minute-key among "
                                (keys state)))
        {::srvr-specs/cookie-components {::state/client-short<->server-long shared-secret
                                         ::state/client-short-pk clnt-short-pk
                                         ::state/minute-key minute-key
                                         ::srvr-specs/clear-text clear-text
                                         ::shared/text text
                                         ::shared/working-nonce working-nonce}
         ::K/hello-spec fields
         ::log2/state log-state})
      {::log2/state (log2/warn log-state
                               ::do-handle
                               "Unable to open the HELLO crypto-box: dropping")})))
