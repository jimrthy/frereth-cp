(ns frereth-cp.client.initiate
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.client.message :as message]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as utils])
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
        :ret (s/keys :req [::crypto-box ::log2/state]))
(defn build-initiate-interior
  "This is the 368+M cryptographic box that's the real payload/Vouch+message portion of the Initiate pack"
  [{log-state ::log2/state
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
        log-state (log2/info log-state
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
     ::log2/state log-state}))

;; TODO: Surely I have a ByteBuf spec somewhere.
(s/fdef build-initiate-packet!
        :args (s/cat :this ::state/state
                     ;; FIXME: This really should be a B]
                     :msg-byte-buf #(instance? ByteBuf %))
        :fn #(= (count (:ret %)) (+ 544 (count (-> % :args :msg-byte-buf K/initiate-message-length-filter))))
        :ret ::specs/byte-buf)
(defn build-initiate-packet!
  "Combine message buffer and client state into an Initiate packet

This is destructive in the sense that it reads from msg-byte-buf"
  [wrapper msg-byte-buf]
  (let [this @wrapper
        msg (message/pull-initial-message-bytes wrapper msg-byte-buf)
        work-area (::shared/work-area this)
        ;; Just reuse a subset of whatever the server sent us.
        ;; Legal because a) it uses a different prefix and b) it's a different number anyway
        ;; Note that this is actually for the *outer* nonce.
        nonce-suffix (b-t/sub-byte-array (::shared/working-nonce work-area) K/client-nonce-prefix-length)
        {:keys [::crypto-box]
         log-state ::log2/state} (build-initiate-interior this msg nonce-suffix)
        log-state (log2/info log-state
                             ::build-initiate-packet!
                             "Stuffing crypto-box into Initiate packet"
                             {::crypto-box (b-t/->string crypto-box)
                              ::message-length (count crypto-box)})
        dscr (update-in K/initiate-packet-dscr [::K/vouch-wrapper ::K/length] + (count msg))
        ^TweetNaclFast$Box$KeyPair short-pair (get-in this [::shared/my-keys ::shared/short-pair])
        fields #::K{:prefix K/initiate-header
                    :srvr-xtn (::state/server-extension this)
                    :clnt-xtn (::shared/extension this)
                    :clnt-short-pk (.getPublicKey short-pair)
                    :cookie (get-in this [::state/server-security ::state/server-cookie])
                    :outer-i-nonce nonce-suffix
                    :vouch-wrapper crypto-box}]
    (shared/compose dscr
                    fields
                    (get-in this [::shared/packet-management ::shared/packet]))))

(defn build-and-send-vouch
  "param wrapper: the agent that's managing the state
  param cookie-packet: first response from the server

  The current implementation is based on the assumption that cookie-packet
  is either a byte stream or a byte array.

  And that I can just write the response byte-buffer back to the output
  stream.

  That assumption does not seem valid at all.

  I have to have an address/port destination so the stream can know
  where to route the message.

  According to the Aleph docs, cookie-packet really should be a map that
  includes :address and :port keys, along with the :message value which is
  something that can be easily transformed into the ByteBuf that it needs
  to send.

  To make matters worse, this entire premise is built around side-effects.

  We send a request to the agent in wrapper to update its state with the
  Vouch, based on the cookie packet. Then we do another send to get it to
  send the vouch

  This matches the original implementation, but it seems like a really
  terrible approach in an environment that's intended to multi-thread."
  [wrapper cookie-packet]
  (let [{log-state ::log2/state
         :as state} @wrapper]
    (if (and (not= cookie-packet ::hello-response-timed-out)
             (not= cookie-packet ::drained))
      (let [log-state (log2/info log-state
                                 ::build-and-send-vouch
                                 ""
                                 {::cause "Received cookie"
                                  ::effect "Forking child"
                                  ::state/state state
                                  ::state/state-agent wrapper})]
        (assert cookie-packet)
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
        ;; Full Answer: That's actually what I want to do here.
        ;; Except that "listening" doesn't really make any sense.
        (send wrapper state/fork! wrapper)

        ;; Once we've signaled the child to start doing its own thing,
        ;; cope with the cookie we just received.
        ;; Doing this statefully seems like a terrible
        ;; idea, but I don't want to go back and rewrite it
        ;; until I have a working prototype.
        (let [log-state (log2/info log-state
                                   ::build-and-send-vouch
                                   "send cookie->vouch")]
          (send wrapper state/cookie->vouch cookie-packet)
          (let [timeout (state/current-timeout wrapper)]
            ;; Give the other thread(s) a chance to catch up and get
            ;; the incoming cookie converted into a Vouch
            (when-not (await-for timeout wrapper)
              (let [log-updates [#(log2/error %
                                               ::build-and-send-vouch
                                               (str "Converting cookie to vouch took longer than "
                                                    timeout
                                                    " milliseconds."))]
                    log-updates (conj log-updates
                                      (if-let [ex (agent-error wrapper)]
                                        (let [log-update #(log2/exception %
                                                                          ex
                                                                          ::build-and-send-vouch
                                                                          "Agent failed while we were waiting")]
                                          ;; Craziness: The failed assertion isn't interrupting my test.
                                          ;; FIXME: Actually, something like this does need to be
                                          ;; fatal. At least for this client.
                                          ;; It's tempting to just call (System/exit) here, but
                                          ;; I'd really prefer to avoid killing the JVM.

                                          (println "FIXME: Start back here.")
                                          (assert (not ex) "This should probably only be fatal for the sake of debugging"))
                                        (let [log-update
                                              #(log2/warn %
                                                          ::build-and-send-vouch
                                                          "Switching agent into an error state")]
                                          (send wrapper
                                                #(throw (ex-info "cookie->vouch timed out" %)))
                                          log-update)))]
                (send wrapper (fn [{log-state ::log2/state
                                    logger ::log2/logger
                                    :as this}]
                                ;; This is pretty obnoxious.
                                ;; I want to apply the functions that
                                ;; I just accumulated all at once.
                                ;; This violates one of the major points
                                ;; behind including timestamps everywhere,
                                ;; but this is really a pretty nasty situation
                                ;; FIXME: Figure out a way to move it into
                                ;; the logging ns
                                (let [log-state (reduce (fn [log-state log-fn]
                                                          (log-fn log-state))
                                                        log-state
                                                        log-updates)]
                                  (assoc this
                                         ::log2/state
                                         (log2/flush-logs! logger log-state))))))))))
      (send wrapper #(throw (ex-info (str cookie-packet " waiting for Cookie")
                                     (assoc %
                                            :problem (if (= cookie-packet ::drained)
                                                       ::server-closed
                                                       ::response-timeout))))))))
