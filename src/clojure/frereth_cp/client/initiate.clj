(ns frereth-cp.client.initiate
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.client.message :as message]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K])
  (:import io.netty.buffer.ByteBuf))

(defn build-initiate-interior
  "This is the 368+M cryptographic box that's the real payload/Vouch+message portion of the Initiate pack"
  [this msg outer-nonce-suffix]
  ;; Important detail: we can use up to 640 bytes that we've
  ;; received from the client/child.
  (let [msg-length (count msg)
        _ (assert (< 0 msg-length))
        tmplt (assoc-in K/vouch-wrapper [::K/child-message ::K/length] msg-length)
        server-name (get-in this [::shared/my-keys ::K/server-name])
        _ (assert server-name)
        inner-nonce-suffix (::state/inner-i-nonce this)
        src {::K/client-long-term-key (.getPublicKey (get-in this [::shared/my-keys ::shared/long-pair]))
             ::K/inner-i-nonce inner-nonce-suffix
             ::K/inner-vouch (::state/vouch this)
             ::K/server-name server-name
             ::K/child-message msg}
        work-area (::shared/work-area this)
        secret (get-in this [::state/shared-secrets ::state/client-short<->server-short])]
    (log/info (str "Encrypting:\n"
                   src
                   "\nInner Nonce Suffix:\n" (b-t/->string inner-nonce-suffix)
                   "FIXME: Do not log this!!\n"
                   "Shared secret:\n" (b-t/->string secret)))
    (shared/build-crypto-box tmplt
                             src
                             (::shared/text work-area)
                             secret
                             K/initiate-nonce-prefix
                             outer-nonce-suffix)))

;; TODO: Surely I have a ByteBuf spec somewhere.
(s/fdef build-initiate-packet!
        :args (s/cat :this ::state/state
                     :msg-byte-buf #(instance? ByteBuf %))
        :fn #(= (count (:ret %)) (+ 544 (count (-> % :args :msg-byte-buf K/initiate-message-length-filter))))
        :ret #(instance? ByteBuf %))
(defn build-initiate-packet!
  "This is destructive in the sense that it reads from msg-byte-buf"
  [wrapper msg-byte-buf]
  (let [this @wrapper
        msg (message/pull-initial-message-bytes wrapper msg-byte-buf)
        work-area (::shared/work-area this)
        ;; Just reuse a subset of whatever the server sent us.
        ;; Legal because a) it uses a different prefix and b) it's a different number anyway
        ;; Note that this is actually for the *outer* nonce.
        nonce-suffix (b-t/sub-byte-array (::shared/working-nonce work-area) K/client-nonce-prefix-length)
        crypto-box (build-initiate-interior this msg nonce-suffix)]
    (log/info (str "Stuffing\n"
                   (b-t/->string crypto-box)
                   "which is " (count crypto-box) " bytes long\n"
                   "into the initiate packet"))
    (let [dscr (update-in K/initiate-packet-dscr [::K/vouch-wrapper ::K/length] + (count msg))
          fields #::K{:prefix K/initiate-header
                      :srvr-xtn (::state/server-extension this)
                      :clnt-xtn (::shared/extension this)
                      :clnt-short-pk (.getPublicKey (get-in this [::shared/my-keys ::shared/short-pair]))
                      :cookie (get-in this [::state/server-security ::state/server-cookie])
                      :outer-i-nonce nonce-suffix
                      :vouch-wrapper crypto-box}]
      (shared/compose dscr
                      fields
                      (get-in this [::shared/packet-management ::shared/packet])))))

(defn build-and-send-vouch
"param wrapper: the agent that's managing the state
param cookie-packet: what arrived over the stream

The current implementation is based on the assumption that cookie-packet
is either a byte stream or a byte array.

And that I can just write the response byte-buffer back to the output
stream.

That assumption does not seem valid at all.

I have to have an address/port destination so the stream can know
where to route the message.

According to the Aleph docs, cookie-packet really should be a map that
includes :address and :port keys, along with the :message value which is
the actual byte-array (ByteBuf?).

That's what I've set up the server side to send, so that's what I'm
currently receiving here.

TODO: Need to validate that assumption.

To make matters worse, this entire premise is built around side-effects.

We send a request to the agent in wrapper to update its state with the
Vouch, based on the cookie packet. Then we do another send to get it to
send the vouch

This matches the original implementation, but it seems like a really
terrible approach in an environment that's intended to multi-thread."
  [wrapper cookie-packet]
  (if (and (not= cookie-packet ::hello-response-timed-out)
           (not= cookie-packet ::drained))
    (do
      (assert cookie-packet)
      (log/info "Received cookie in " wrapper ". Forking child")
      ;; Got a Cookie response packet from server.
      ;; Theory in the reference implementation is that this is
      ;; a good signal that it's time to spawn the child to do
      ;; the real work.
      ;; That really seems to complect the concerns.
      ;; Q: Why not set up the child in its own thread and start
      ;; listening for its activity now?
      ;; Partial Answer: original version is geared toward converting
      ;; existing apps that pipe data over STDIN/OUT so they don't
      ;; have to be changed at all.
      (send wrapper state/fork wrapper)

      ;; Once that that's ready to start doing its own thing,
      ;; cope with the cookie we just received.
      ;; Doing this statefully seems like a terrible
      ;; idea, but I don't want to go back and rewrite it
      ;; until I have a working prototype
      (log/info "send cookie->vouch")
      (send wrapper state/cookie->vouch cookie-packet)
      (let [timeout (state/current-timeout wrapper)]
        ;; Give the other thread(s) a chance to catch up and get
        ;; the incoming cookie converted into a Vouch
        (if (await-for timeout wrapper)
          (let [this @wrapper
                initial-bytes (state/wait-for-initial-child-bytes this)
                vouch (build-initiate-packet! wrapper initial-bytes)]
            (log/info "send-off send-vouch!")
            (send-off wrapper state/send-vouch! wrapper vouch))
          (do
            (log/error (str "Converting cookie to vouch took longer than "
                            timeout
                            " milliseconds."))
            (if (agent-error wrapper)
              (log/info "Agent failed while we were waiting")
              (do
                (log/warn "Switching agent into an error state")
                (send wrapper
                      #(throw (ex-info "cookie->vouch timed out" %)))))))))
    (send wrapper #(throw (ex-info (str cookie-packet " waiting for Cookie")
                                   (assoc %
                                          :problem (if (= cookie-packet ::drained)
                                                     ::server-closed
                                                     ::response-timeout)))))))
