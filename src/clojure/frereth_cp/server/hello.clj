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
        :ret (s/keys :req [::opened ::shared-secret]))
(defn open-hello-crypto-box
  [{:keys [::client-short-pk
           ::state/cookie-cutter]
    ^bytes nonce-suffix ::nonce-suffix
    {^TweetNaclFast$Box$KeyPair long-keys ::shared/long-pair
     :as my-keys} ::shared/my-keys
    :as state}
   message
   ^bytes crypto-box]
  (when-not long-keys
    ;; Log whichever was missing and throw
    (if my-keys
      (log/error "Missing ::shared/long-pair among" (keys my-keys))
      (log/error "Missing ::shared/my-keys among" (keys state)))
    (throw (ex-info "Missing long-term keypair" state)))
  (let [my-sk (.getSecretKey long-keys)
        ;; Q: Is this worth saving? It's used again for
        ;; the outer crypto-box in the Cookie from the server
        shared-secret (crypto/box-prepare client-short-pk my-sk)]
    (log/debug (str "Incoming HELLO\n"
                    "Client short-term PK:\n"
                    (with-out-str (b-s/print-bytes client-short-pk))
                    "\nMy long-term PK:\n"
                    (with-out-str (b-s/print-bytes (.getPublicKey long-keys)))))
    (let [msg (str "Trying to open "
                   K/hello-crypto-box-length
                   " bytes of\n"
                   (with-out-str (b-s/print-bytes crypto-box))
                   "\nusing nonce suffix\n"
                   (with-out-str (b-s/print-bytes nonce-suffix))
                   "\nencrypted from\n"
                   (with-out-str (b-s/print-bytes client-short-pk)))]
      (log/debug msg))
    {::opened (crypto/open-crypto-box
               shared/hello-nonce-prefix
               nonce-suffix
               crypto-box
               shared-secret)
     ::shared-secret shared-secret}))

(s/fdef open-packet
        :args (s/cat :state ::state/state :message ::specs/byte-buf)
        :ret (s/keys :req [::K/hello-spec ::opened ::shared-secret]))
(defn open-packet
  [{:keys [::state/current-client]
    :as state}
   ;; FIXME: This really should be bytes
   ;; That has broader implications, since it really means updating
   ;; serialization/decompose again. So maybe not.
   ^ByteBuf message]
  (if (= (.readableBytes message) shared/hello-packet-length)
    (do
      (log/info "This is the correct size")
      (let [;; Q: Is the convenience here worth the [hypothetical] performance hit of using decompose?
            {:keys [::K/clnt-xtn
                    ::K/crypto-box
                    ::K/client-nonce-suffix
                    ::K/srvr-xtn]
             ^bytes clnt-short-pk ::K/clnt-short-pk
             :as decomposed} (serial/decompose K/hello-packet-dscr message)
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
          (if current-client
            (if-let [sec (::state/client-security current-client)]
              (if-let [short-pk (::shared/short-pk sec)]
                (log/error (str "Don't understand why we're about to have a problem. It's right here:\n"
                                (util/pretty (helpers/hide-long-arrays state))))
                (log/error (str "Missing short-term public-key array among\n"
                                (util/pretty sec))))
              (log/error (str "Missing :client-security among\n"
                              (util/pretty current-client))))
            (log/error (str "Missing :current-client among\n"
                            (util/pretty state))))
          (throw (ex-info "Missing spot for client short-term public key" state)))
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
         ::K/hello-spec decomposed)))
    (throw (ex-info "Wrong size for a HELLO packet"
                    {::actual (.readableBytes message)
                     ::expected shared/hello-packet-length}))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-handle
        :args (s/cat :state ::state/state
                     :packet ::shared/message)
        :ret (s/keys :req [::K/hello-spec ::srvr-specs/cookie-components]))
(defn do-handle
  [{:keys [::shared/working-area]
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
         :as unboxed} (open-packet state message)]
    ;; We don't actually care about the contents of the bytes we just decrypted.
    ;; They should be all zeroes for now, but that's really an area for possible future
    ;; expansion.
    ;; For now, the point is that they unboxed correctly, so the client has our public
    ;; key and the short-term private key so it didn't just send us random garbage.
    (log/info "box opened successfully")
    (.release message)
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
         ::K/hello-spec fields})
      (do
        (log/warn "Unable to open the HELLO crypto-box: dropping")
        nil))))
