(ns frereth-cp.server.hello
  "For coping with incoming HELLO packets"
  (:require [byte-streams :as b-s]
            [clojure.tools.logging :as log]
            [frereth-cp.server.cookie :as cookie]
            [frereth-cp.server.helpers :as helpers]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream])
  (:import com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn open-hello-crypto-box
  [{:keys [::client-short-pk
           ::state/cookie-cutter
           ::shared/my-keys]
    ^bytes nonce-suffix ::nonce-suffix
    :as state}
   message
   ^bytes crypto-box]
  (let [^TweetNaclFast$Box$KeyPair long-keys (::shared/long-pair my-keys)]
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
       ::shared-secret shared-secret})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn handle!
  [{:keys [::shared/working-area]
    :as state}
   {:keys [:host :port]
    ^ByteBuf message :message
    :as packet}]
  (log/debug "Have what looks like a HELLO packet")
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
        ;; Destructively overwriting the contents of the destination B] absolutely reeks.
        ;; It seems like it would be much better to just assoc in the new B] containing
        ;; the key and move along.
        ;; Then again, this entire giant side-effecting mess is awful.
        (b-t/byte-copy! client-short-pk clnt-short-pk)
        (let [{clear-text ::opened
               shared-secret ::shared-secret :as unboxed} (open-hello-crypto-box (assoc state
                                                                                        ::client-short-pk client-short-pk
                                                                                        ::nonce-suffix client-nonce-suffix)
                                                                                 message
                                                                                 crypto-box)]
          (log/info "box opened successfully")
          (if clear-text
            (let [minute-key (get-in state [::state/cookie-cutter ::state/minute-key])
                  {:keys [::shared/text
                          ::shared/working-nonce]} working-area]
              (assert minute-key (str "Missing minute-key among "
                                      (keys state)))
              (log/info "Preparing cookie")
              ;; We don't actually care about the contents of the bytes we just decrypted.
              ;; They should be all zeroes for now, but that's really an area for possible future
              ;; expansion.
              ;; For now, the point is that they unboxed correctly, so the client has our public
              ;; key and the short-term private key so it didn't just send us random garbage.
              ;; FIXME: This next section really deserves its own function.
              ;; In the cookie ns.
              (let [crypto-box
                    (cookie/prepare-cookie! {::state/client-short<->server-long shared-secret
                                             ::state/client-short-pk clnt-short-pk
                                             ::state/minute-key minute-key
                                             ::cookie/clear-text clear-text
                                             ::shared/text text
                                             ::shared/working-nonce working-nonce})]
                ;; Note that the reference implementation overwrites this incoming message in place.
                ;; That seems dangerous, but it very deliberately is longer than
                ;; our response.
                ;; And it does save a malloc/GC.
                ;; I can't do that, because of the way compose works.
                ;; TODO: Revisit this decision if/when the GC turns into a problem.
                (.release message)
                (let [^ByteBuf response
                      (cookie/build-cookie-packet clnt-xtn srvr-xtn working-nonce crypto-box)]
                  (log/info (str "Cookie packet built. Sending it."))
                  (try
                    (let [dst (get-in state [::state/client-write-chan ::state/chan])]
                      (when-not dst
                        (throw (ex-info "Missing destination"
                                        (or (::state/client-write-chan state)
                                            {::problem "No client-write-chan"
                                             ::keys (keys state)
                                             ::actual state}))))
                      ;; And this is why I need to refactor this. There's so much going
                      ;; on in here that it's tough to remember that this is sending back
                      ;; a map. It has to, since that's the way aleph handles
                      ;; UDP connections, but it really shouldn't need to: that's the sort
                      ;; of tightly coupled implementation detail that I can push further
                      ;; to the boundary.
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
