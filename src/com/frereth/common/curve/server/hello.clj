(ns com.frereth.common.curve.server.hello
  "For coping with incoming HELLO packets"
  (:require [byte-streams :as b-s]
            [clojure.tools.logging :as log]
            [com.frereth.common.curve.server.cookie :as cookie]
            [com.frereth.common.curve.server.helpers :as helpers]
            [com.frereth.common.curve.server.state :as state]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]
            [com.frereth.common.curve.shared.constants :as K]
            [com.frereth.common.curve.shared.crypto :as crypto]
            [com.frereth.common.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn open-hello-crypto-box
  [{:keys [::client-short-pk
           ::state/cookie-cutter
           ::nonce-suffix
           ::shared/my-keys
           ::shared/working-area]
    :as state}
   message
   crypto-box]
  (log/warn "Depcecated. Use crypto/open-crypto-box instead")
  (let [long-keys (::shared/long-pair my-keys)]
    (when-not long-keys
      ;; Log whichever was missing and throw
      (if my-keys
        (log/error "Missing ::shared/long-pair among" (keys my-keys))
        (log/error "Missing ::shared/my-keys among" (keys state)))
      (throw (ex-info "Missing long-term keypair" state)))
    (let [my-sk (.getSecretKey long-keys)
          shared-secret (crypto/box-prepare client-short-pk my-sk)
          ;; Q: How do I combine these to handle this all at once?
          ;; I think I should be able to do something like:
          ;; {:keys [{:keys [::text ::working-nonce] :as ::work-area}]}
          ;; state
          ;; (that fails spec validation)
          ;; Better Q: Would that a good idea, if it worked?
          ;; (Pretty sure this is/was the main thrust behind a plumatic library)
          {:keys [::shared/text ::shared/working-nonce]} working-area]
      (log/debug (str "Incoming HELLO\n"
                      "Client short-term PK:\n"
                      (with-out-str (b-s/print-bytes client-short-pk))
                      "\nMy long-term PK:\n"
                      (with-out-str (b-s/print-bytes (.getPublicKey long-keys)))))
      (b-t/byte-copy! working-nonce
                      shared/hello-nonce-prefix)
      (.readBytes nonce-suffix working-nonce K/client-nonce-prefix-length K/client-nonce-suffix-length)
      (.readBytes crypto-box text #_K/decrypt-box-zero-bytes 0 K/hello-crypto-box-length)
      (let [msg (str "Trying to open "
                     K/hello-crypto-box-length
                     " bytes of\n"
                     (with-out-str (b-s/print-bytes (b-t/sub-byte-array text 0 (+ 32 K/hello-crypto-box-length))))
                     "\nusing nonce\n"
                     (with-out-str (b-s/print-bytes working-nonce))
                     "\nencrypted from\n"
                     (with-out-str (b-s/print-bytes client-short-pk))
                     "\nto\n"
                     (with-out-str (b-s/print-bytes (.getPublicKey long-keys))))]
        (log/debug msg))
      {::opened (crypto/open-after
                 text
                 0
                 K/hello-crypto-box-length
                 working-nonce
                 shared-secret)
       ::shared-secret shared-secret})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn handle!
  [{:keys [::shared/working-area]
    :as state}
   {:keys [host message port]
    :as packet}]
  (log/debug "Have what looks like a HELLO packet")
  (if (= (.readableBytes message) shared/hello-packet-length)
    (do
      (log/info "This is the correct size")
      (let [;; Q: Is the convenience here worth the performance hit of using decompose?
            {:keys [::K/clnt-xtn
                    ::K/clnt-short-pk
                    ::K/crypto-box
                    ::K/client-nonce-suffix
                    ::K/srvr-xtn]
             :as decomposed} (shared/decompose K/hello-packet-dscr message)
            ;; We're keeping a ByteArray around for storing the key received by the current message.
            ;; The reference implementation just stores it in a global.
            ;; This undeniably has some impact on GC.
            ;; Q: Is it enough to justify doing something this unusual?
            ;; (it probably makes a lot more sense in C where you don't have a lot of great alternatives)
            ;; TODO: Get benchmarks both ways.
            ;; I'm very skeptical that this is worth the wonkiness, but I'm also
            ;; very skeptical about messing around with the reference implementation.
            client-short-pk (get-in state [::state/current-client ::state/client-security ::shared/short-pk])]
        (when (not client-short-pk)
              (if-let [current-client (::state/current-client state)]
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
        (.getBytes clnt-short-pk 0 client-short-pk)
        ;; FIXME: This can't be/isn't right
        ;; (except for the basic fact that it works)
        ;; TODO: switch to crypto/open-crypto-box
        (let [unboxed (open-hello-crypto-box (assoc state
                                                    ::client-short-pk client-short-pk
                                                    ::nonce-suffix client-nonce-suffix)
                                             message
                                             crypto-box)
              clear-text (::opened unboxed)]
          (log/info "box opened successfully")
          (if clear-text
            (let [shared-secret (::shared-secret unboxed)
                  minute-key (get-in state [::state/cookie-cutter ::state/minute-key])
                  {:keys [::shared/text
                          ::shared/working-nonce]} working-area]
              (log/debug "asserting minute-key" minute-key "among" (keys state))
              (assert minute-key)
              (log/info "Preparing cookie")
              ;; We don't actually care about the contents of the bytes we just decrypted.
              ;; They should be all zeroes for now, but that's really an area for possible future
              ;; expansion.
              ;; For now, the point is that they unbox correctly on the other side
              (let [crypto-box
                    (cookie/prepare-cookie! {::state/client-short<->server-long shared-secret
                                             ::state/client-short-pk clnt-short-pk
                                             ::state/minute-key minute-key
                                             ::cookie/clear-text clear-text
                                             ::shared/text text
                                             ::shared/working-nonce working-nonce})]
                ;; Note that this overrides the incoming message in place
                ;; Which seems dangerous, but it very deliberately is longer than
                ;; our response.
                ;; And it does save a malloc/GC.
                ;; Important note: I'm deliberately not releasing this, because I'm sending it back.
                (.clear message)
                (let [response
                      (cookie/build-cookie-packet message clnt-xtn srvr-xtn working-nonce crypto-box)]
                  (log/info (str "Cookie packet built. Returning it."))
                  (try
                    (let [dst (get-in state [::state/client-write-chan :chan])]
                      (when-not dst
                        (log/warn "Missing destination")
                        (if-let [write-chan (::state/client-write-chan state)]
                          (if-let [chan (:chan write-chan)]
                            (log/error "Ummm...what's the problem?")
                            (log/error (str "Missing the :chan in\n"
                                            (util/pretty write-chan))))
                          (log/error (str "Missing ::state/client-write-chan in\n"
                                          (util/pretty (helpers/hide-long-arrays state))))))
                      (let [put-future (stream/try-put! dst
                                                        (assoc packet
                                                               :message response)
                                                        ;; TODO: This really needs to be part of
                                                        ;; state so it can be tuned while running
                                                        cookie/send-timeout
                                                        ::timed-out)]
                        (log/info "Cookie packet scheduled to send")
                        (deferred/on-realized put-future
                          (fn [success]
                            (if success
                              (log/info "Sending Cookie succeeded")
                              (log/error "Sending Cookie failed"))
                            ;; TODO: Make sure this does get released!
                            ;; The caller has to handle that, though.
                            ;; It can't be released until after it's been put
                            ;; on the socket.
                            (comment (.release response)))
                          (fn [err]
                            (log/error "Sending Cookie failed:" err)
                            (.release response)))
                        state))
                    (catch Exception ex
                      (log/error ex "Failed to send Cookie response")
                      state)))))
            (do
              (log/warn "Unable to open the HELLO crypto-box: dropping")
              state)))))
    (log/warn "Wrong size for a HELLO packet. Need"
              shared/hello-packet-length
              "got"
              (.readableBytes message))))
