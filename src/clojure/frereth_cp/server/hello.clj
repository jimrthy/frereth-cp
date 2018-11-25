(ns frereth-cp.server.hello
  "For coping with incoming HELLO packets"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth-cp.server
             [cookie :as cookie]
             [helpers :as helpers]
             [shared-specs :as srvr-specs]
             [state :as state]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [serialization :as serial]
             [specs :as specs]]
            [frereth-cp.util :as util]
            [frereth.weald :as weald]
            [frereth.weald.logging :as log]
            [manifold
             [deferred :as deferred]
             [stream :as stream]])
  (:import com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(set! *warn-on-reflection* true)

(def send-timeout
  "Milliseconds to wait for putting packets onto network queue"
  50)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::opened (s/nilable ::crypto/unboxed))
(s/def ::shared-secret ::specs/crypto-key)

(s/def ::cookie-response-builder
  (s/fspec
   :args (s/cat :state ::state/state
                :recipe (s/keys :req [::srvr-specs/cookie-components ::K/hello-spec]))
   :ret (s/keys :req [::weald/state]
                :opt [::K/cookie-packet])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef open-hello-crypto-box
        :args (s/cat :state ::state/state
                     :message any?
                     :crypto-box ::K/crypto-box)
        :ret (s/keys :req [::weald/state ::opened ::shared-secret]))
(defn open-hello-crypto-box
  [{:keys [::client-short-pk
           ::state/cookie-cutter]
    ^bytes nonce-suffix ::nonce-suffix
    {^TweetNaclFast$Box$KeyPair long-keys ::shared/long-pair
     :as my-keys} ::shared/my-keys
    log-state ::weald/state
    :as state}
   message
   ^bytes crypto-box]
  {:pre [log-state]}
  (when-not long-keys
    ;; Log whichever was missing and throw
    (let [log-state
          (if my-keys
            (log/error log-state
                       ::open-hello-crypto-box
                       "Missing ::shared/long-pair"
                       {::available-keys (keys my-keys)})
            (log/error log-state
                       "Missing ::shared/my-keys"
                       {::available-keys (keys state)}))])
    (throw (ex-info "Missing long-term keypair" log-state)))
  (let [my-sk (.getSecretKey long-keys)
        ;; Q: Is this worth saving? It's used again for
        ;; the outer crypto-box in the Cookie from the server
        shared-secret (crypto/box-prepare client-short-pk my-sk)
        log-state (log/debug log-state
                             ::open-hello-crypto-box
                             "Incoming HELLO"
                             {::client-short-pk (with-out-str (b-s/print-bytes client-short-pk))
                              ::my-long-pk (with-out-str (b-s/print-bytes (.getPublicKey long-keys)))})
        log-state (log/debug log-state
                             ::open-hello-crypto-box
                             "Trying to open"
                             {::box-length K/hello-crypto-box-length
                              ::crypto-box (with-out-str (b-s/print-bytes crypto-box))
                              ::shared/nonce-suffix (with-out-str (b-s/print-bytes nonce-suffix))})
        {:keys [::weald/state ::crypto/unboxed]} (crypto/open-box
                                                  log-state
                                                  K/hello-nonce-prefix
                                                  nonce-suffix
                                                  crypto-box
                                                  shared-secret)]
    {::weald/state log-state
     ::opened unboxed
     ::shared-secret shared-secret}))

(s/fdef open-packet
        ;; The thing about this approach to spec is that
        ;; we also need all the pieces in ::state/state
        ;; that open-hello-crypto-box needs.
        :args (s/cat :state (s/keys :req [::weald/state
                                          ::state/current-client])
                     :message bytes?)
        :ret (s/keys :req [::K/hello-spec ::weald/state ::opened ::shared-secret]))
(defn open-packet
  [{:keys [::state/current-client]
    log-state ::weald/state
    :as state}
   message]
  (let [message (bytes message)
        length (count message)]
    (if (= length K/hello-packet-length)
      (let [log-state (log/info log-state
                                 ::open-packet
                                 "This is the correct size")
            ;; Q: Is the convenience here worth the [hypothetical] performance hit of using decompose?
            {:keys [::K/clnt-xtn
                    ::K/crypto-box
                    ::K/client-nonce-suffix
                    ::K/srvr-xtn]
             ^bytes clnt-short-pk ::K/clnt-short-pk
             :as decomposed} (serial/decompose-array K/hello-packet-dscr message)]
        (when (not clnt-short-pk)
          (throw (ex-info "HELLO packet missed client short-term pk" decomposed)))

        ;; Note: The reference implementation keeps a specific memory address for the
        ;; client-short-pk. It seems like there might be some advantage to this approach
        ;; in terms of the CPU cache.
        ;; And possibly also from the standpoint of malloc/free performance.
        ;; There may also be serious implications from a crypto standpoint.
        ;; I'm inclined to suspect that this is probably just something that
        ;; was convenient to do in C.
        ;; TODO: Ask a cryptographer
        (assoc
         (open-hello-crypto-box (assoc state
                                       ::client-short-pk clnt-short-pk
                                       ::nonce-suffix client-nonce-suffix)
                                message
                                crypto-box)
         ::K/hello-spec decomposed))
      (throw (ex-info "Wrong size for a HELLO packet"
                      {::actual (count message)
                       ::expected K/hello-packet-length})))))

(s/fdef internal-handler
        ;; Passing around ::state/state everywhere was lazy/dumb.
        ;; TODO: Be more explicit about which keys we really and truly need.
        :args (s/cat :state ::state/state
                     :packet ::shared/message)
        :ret (s/keys :opt [::K/hello-spec ::srvr-specs/cookie-components]
                     :req [::weald/state]))
(defn internal-handler
  ;; This was originally refactored out of do-handle, back when that had
  ;; to reside in the top-level server ns
  "FIXME: Needs a better name"
  [{log-state ::weald/state
    :as state}
   message]
  (let [log-state (log/debug log-state
                             ::do-handle
                             "Have what looks like a HELLO packet")
        {:keys [::shared-secret]
         clear-text ::opened
         {:keys [::K/clnt-short-pk
                 ::K/clnt-xtn
                 ::K/srvr-xtn
                 ::K/crypto-box]
          :as fields} ::K/hello-spec
         :as unboxed} (open-packet state message)
        log-state (log/info log-state
                            ::do-handle
                            "box opened successfully")]
    ;; We don't actually care about the contents of the bytes we just decrypted.
    ;; They should be all zeroes for now, but that's really an area for possible future
    ;; expansion.
    ;; For now, the point is that they unboxed correctly, so the client has our public
    ;; key and the short-term private key so it didn't just send us random garbage.
    (if clear-text
      (let [minute-key (get-in state [::state/cookie-cutter ::state/minute-key])
            text (byte-array 2048)]
        (assert minute-key (str "Missing minute-key among "
                                (keys state)))
        {::srvr-specs/cookie-components {::state/client-short<->server-long shared-secret
                                         ::state/client-short-pk clnt-short-pk
                                         ::state/minute-key minute-key
                                         ::srvr-specs/clear-text clear-text}
         ::K/hello-spec fields
         ::weald/state log-state})
      {::weald/state (log/warn log-state
                             ::do-handle
                             "Unable to open the HELLO crypto-box: dropping")})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-handle
  :args (s/cat :state ::state/state
               :cookie-response-builder any?
               :packet ::shared/network-packet)
  :ret ::state/state)
(defn do-handle
  [{:keys [::weald/logger]
    log-state ::weald/state
    :as state}
   cookie-response-builder
   {:keys [:message]
    :as packet}]
  (let [log-state (log/debug log-state
                             ::do-handle
                             "Top")
        {log-state ::weald/state
         :as cookie-recipe} (internal-handler (assoc state ::weald/state log-state)
                                              message)]
    (if cookie-recipe
      (let [{cookie ::K/cookie-packet
             log-state ::weald/state} (cookie/do-build-response state cookie-recipe)
            log-state (log/info log-state
                                ::handle-hello!
                                (str "Cookie packet built. Sending it."))]
        (try
          (if-let [dst (get-in state [::state/client-write-chan ::state/chan])]
            ;; And this is why I need to refactor this. There's so much going
            ;; on in here that it's tough to remember that this is sending back
            ;; a map. It has to, since that's the way aleph handles
            ;; UDP connections, but it really shouldn't need to: that's the sort
            ;; of tightly coupled implementation detail that I can push further
            ;; to the boundary.
            (let [put-future (stream/try-put! dst
                                              (assoc packet
                                                     :message cookie)
                                              ;; TODO: This really needs to be part of
                                              ;; state so it can be tuned while running
                                              send-timeout
                                              ::timed-out)
                  log-state (log/info log-state
                                      ::handle-hello!
                                      "Cookie packet scheduled to send")
                  forked-log-state (log/clean-fork log-state
                                                    ::hello-processed)]

              (deferred/on-realized put-future
                (fn [success]
                  (log/flush-logs! logger
                                   (if success
                                     (log/info forked-log-state
                                               ::handle-hello!
                                               "Sending Cookie succeeded")
                                     (log/error forked-log-state
                                                ::handle-hello!
                                                "Sending Cookie failed"))))
                (fn [err]
                  (log/flush-logs! logger
                                   (log/error forked-log-state
                                              ::handle-hello!
                                              "Sending Cookie failed:" err))))
              {::weald/state (log/flush-logs! logger log-state)})
            (throw (ex-info "Missing destination"
                            (or (::state/client-write-chan state)
                                {::problem "No client-write-chan"
                                 ::keys (keys state)
                                 ::actual state}))))
          (catch Exception ex
            {::weald/state (log/exception log-state
                                          ex
                                          ::handle-hello!
                                          "Failed to send Cookie response")})))
      {::weald/state log-state})))
