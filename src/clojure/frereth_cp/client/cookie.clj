(ns frereth-cp.client.cookie
  (:require [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [frereth-cp.client.initiate :as initiate]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::succss-callback (s/fspec :args ::state/cookie-response
                                  :ret any?))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef decrypt-actual-cookie
        :args (s/cat :this ::state/state
                     :received ::K/cookie-frame)
        :ret ::state/state)
(defn decrypt-actual-cookie
  [{:keys [::shared/packet
           ::state/server-security
           ::state/shared-secrets]
    log-state ::log/state
    :as this}
   {:keys [::K/header
           ::K/client-extension
           ::K/server-extension]
    ^bytes client-nonce-suffix ::K/client-nonce-suffix
    ^bytes cookie ::K/cookie
    :as rcvd}]
  (let [log-state (log/info log-state
                            ::decrypt-actual-cookie
                            "Getting ready to try to extract cookie"
                            {::raw-cookie cookie
                             ::human-readable (shared/bytes->string cookie)})]
    (let [log-state (log/debug log-state
                               ::decrypt-actual-cookie
                               "Setting up cookie decryption"
                               {::this this
                                ::my-keys (keys this)})
          shared (::state/client-short<->server-long shared-secrets)]
      (when-not shared
        (throw (ex-info "Missing client-short<->server-long secret"
                        {::state/shared-secrets shared-secrets})))
      (try
        (let [log-state (log/info log-state
                                  ::decrypt-actual-cookie
                                  "Trying to decrypt"
                                  {::shared/text  (b-t/->string cookie)
                                   ::prefix-bytes (b-t/->string K/cookie-nonce-prefix)
                                   ::suffix-bytes (b-t/->string client-nonce-suffix)
                                   ::client-short<->server-long (b-t/->string shared)})
              {log-state ::log/state
               decrypted ::crypto/unboxed} (crypto/open-box log-state
                                                            K/cookie-nonce-prefix
                                                            client-nonce-suffix
                                                            cookie
                                                            shared)
              {server-short-pk ::K/s'
               server-cookie ::K/black-box
               :as extracted} (serial/decompose K/cookie decrypted)
              server-security (assoc (::state/server-security this)
                                     ::specs/public-short server-short-pk,
                                     ::state/server-cookie server-cookie)]
          (assert server-cookie)
          (assoc this
                 ::state/server-security server-security
                 ::log/state log-state))
        (catch ExceptionInfo ex
          (assoc this
                 ::log/state (log/exception log-state
                                            ex
                                            ::decrypt-actual-cookie
                                            "Decryption failed"
                                            (.getData ex))))))))

;; TODO: Split out the parameters we actually need instead of
;; just bundling the entire state all the way up and down the
;; call chain.
;; Sure, this approach qualifies as purely functional, but it's
;; a weak qualification.
(s/fdef decrypt-cookie-packet
        :args (s/cat :this ::state/state)
        :ret ::state/state)
(defn decrypt-cookie-packet
  [{:keys [::shared/extension
           ::shared/packet
           ::state/server-extension]
    log-state ::log/state
    :as this}]
  (when-not (= (count packet) K/cookie-packet-length)
    (let [err {::expected-length K/cookie-packet-length
               ::actual-length (count packet)
               ::packet packet
               ;; Because the stack trace hides
               ::where 'shared.curve.client/decrypt-cookie-packet}]
      (throw (ex-info "Incoming cookie packet illegal" err))))
  (let [log-state (log/debug log-state
                             ::decrypt-cookie-packet
                             "Incoming packet that looks like it might be a cookie"
                             {::raw-packet packet
                              ::human-readable (shared/bytes->string packet)})
        {:keys [::K/header
                ::K/client-extension
                ::K/server-extension]
         :as rcvd} (serial/decompose-array K/cookie-frame packet)
        log-state (log/info log-state
                            ::decrypt-cookie-packet
                            "Verifying that decrypted packet looks like a Cookie"
                            {::raw-header header
                             ::human-readable (shared/bytes->string header)})]
    ;; Q: How accurate/useful is this approach?
    ;; (i.e. mostly comparing byte array hashes)
    ;; A: Not at all.
    ;; Well, it's slightly better than nothing.
    ;; But it's trivial to forge.
    ;; Q: How does the reference implementation handle this?
    ;; A: Well, the proof *is* in the pudding.
    ;; The most important point is whether the other side sent
    ;; us a cookie we can decrypt using our shared key.
    ;; This is really just a quick finger-in-the-wind test.
    (when (and (b-t/bytes= K/cookie-header header)
               (b-t/bytes= extension client-extension)
               (b-t/bytes= server-extension server-extension))
      (decrypt-actual-cookie (assoc this
                                    ::log/state log-state)
                             rcvd))))

(s/fdef received-response!
        :args (s/cat :this ::state/state
                     :cookie ::specs/network-packet)
        :ret ::state/state)
(defn received-response!
  "Hello triggers this (via wait-for-cookie) when it hears back from a Server"
  [{log-state ::log/state
    :keys [::log/logger]
    :as this}
   {:keys [:host :message :port]
        :or {message (byte-array 0)}
        :as cookie}]
  ;; FIXME: Have to compare :host (and, realistically, :port)
  ;; against the server associated with the most recently
  ;; sent HELLO.
  ;; If they don't match, we need to discard this cookie
  ;; and go back to waiting (don't forget to reduce the
  ;; timeout based on elapsed time)
  ;; Realistically, it probably would have been better to do
  ;; this as soon as we received the packet.
  ;; It seems like that might introduce the possibility of timing
  ;; attacks, though I don't see how.
  ;; TODO: Check with a cryptographer.
  (let [log-label ::received-response!
        log-state (log/info log-state
                            log-label
                            "Possibly got a response from server"
                            cookie)]
    (try
      (if-not (or (= cookie ::drained)
                  (= cookie ::state/response-timed-out))
        (if (= K/cookie-packet-length (count message))
          ;; Next step for reference implementation is to compare the
          ;; expected server IP and port vs. what we received.
          ;; That info's pretty unreliable/meaningless, but the server
          ;; address probably won't change very often.
          ;; Unless we're communicating with a server on someone's cell
          ;; phone.
          ;; Which, if this is successful, will totally happen.
          ;; TODO: Verify those before trying to proceed
          (try
            (if-let [decrypted (decrypt-cookie-packet (assoc (select-keys this
                                                                          [::shared/extension
                                                                           ::shared/work-area
                                                                           ::state/server-extension
                                                                           ::state/server-security
                                                                           ::state/shared-secrets])
                                                             ::log/state log-state
                                                             ::shared/packet message))]
              ;; Q: Would merge-with be more appropriate?
              (let [{:keys [::shared/my-keys]
                     :as this} (merge this decrypted)
                    server-short (get-in this
                                         [::state/server-security
                                          ::specs/public-short])
                    log-state (log/debug log-state
                                         log-label
                                         "Managed to decrypt the cookie")]
                (if server-short
                  (let [^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
                        ;; line 327
                        shared-secrets (assoc (::state/shared-secrets this)
                                              ::state/client-short<->server-short
                                              (crypto/box-prepare
                                               server-short
                                               (.getSecretKey my-short-pair)))]
                    ;; Throwing this should cause us to forget the incoming Cookie. And
                    ;; either move on to the next server or wait for another Cookie from
                    ;; this one (which, realistically, won't happen).
                    ;; TODO: Get back to this and verify that we don't wind up sending
                    ;; an empty Initiate packet (which is what happened the last time
                    ;; I enabled this exception)
                    ;; TODO: Write a test that checks this without the faked-up exception
                    ;; here
                    (comment (throw (ex-info "This should discard the cookie"
                                             {::problem "Not sure. How is this proceeding?"})))
                    ;; Yay! Reached the Happy Path
                    (assoc this
                           ::log/state (log/debug log-state
                                                  log-label
                                                  (str "Prepared shared short-term secret\n"
                                                       "Cookie:\n"
                                                       (b-t/->string (get-in decrypted [::state/server-security
                                                                                        ::state/server-cookie]))))
                           ::state/server-security (::state/server-security decrypted)
                           ::state/shared-secrets shared-secrets
                           ::shared/network-packet cookie))
                  (assoc this
                         ::log/state (log/error log-state
                                                log-label
                                                (str "Missing ::specs/public-short among\n"
                                                     (keys (::state/server-security this))
                                                     "\namong bigger-picture\n"
                                                     (keys this))))))
              ;; This is a failure, really.
              ;; Discards the packet, update recent (and thus the polling timeout)
              ;; and go back to polling.
              (assoc this
                     ::log/state (log/warn log-state
                                           log-label
                                           "Unable to decrypt server cookie"
                                           {::problem cookie})))
            ;; TODO: Look into recovering from these
            (catch Throwable ex
              (assoc this ::log/state (log/exception log-state
                                                     ex
                                                     log-label
                                                     "Unhandled failure"))))
          (assoc this
                 ::log/state (log/warn log-state
                                       log-label
                                         "Invalid response. Just discard and retry"
                                         {::problem cookie})))
        (let [log-state (log/warn log-state
                                  log-label
                                  "Server didn't respond to HELLO. Move on to next.")]
          (assoc this ::log/state) log-state))
      (catch Exception ex
        {::log/state (log/exception log-state
                                    ex
                                    log-label)}
        (throw ex)))))

;; The name makes this seem like it doesn't belong in here.
;; It totally does.
;; A better name would be nice.
(s/fdef hello-response-failed!
        :args (s/cat :wrapper ::state/state
                     :failure ::specs/throwable)
        :ret any?)
(defn hello-response-failed!
  "Waiting for the cookie failed"
  [{:keys [::log/logger
           ::log/state
           ::state/terminated]
    :as this}
   failure]
  ;; FIXME: Really need to signal the outer client that
  ;; things broke pretty badly.
  ;; Note that this isn't an ordinary timeout: this was a true
  ;; failure in taking from the stream. And, realistically,
  ;; should never happen.
  (log/flush-logs! logger (log/exception state
                                         failure
                                         ::hello-response-failed!))
  (dfrd/error! terminated failure))

(s/fdef wrap-received
        :args (s/cat :this ::state/state
                     :incoming ::specs/network-packet)
        :ret ::state/state)
(defn wrap-received
  [{log-state ::log/state
    :keys [::log/logger]
    :as this}
   incoming]
  ;; It seems a bit silly to have a lambda here.
  ;; The println debugging adds insult to injury.
  ;; TODO: Refactor this into its own top-level named
  ;; function
  (println "The wait for the cookie has ended")
  (pprint incoming)
  (let [this
        (assoc this
               ::log/state (log/flush-logs! logger (log/trace log-state
                                                              ::wait-for-cookie!
                                                              "Pulled from server"
                                                              {::specs/network-packet incoming})))]
    (received-response! this incoming)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef servers-polled
        :args (s/cat :this ::state/state)
        :ret ::state/state)
(defn servers-polled
  "Got back a cookie. Respond with an Initiate"
  [{log-state ::log/state
    logger ::log/logger
    ;; Q: Is there a good way to pry this out
    ;; so it's its own parameter?
    ;; A: Well, we could work our way back up to
    ;; hello/set-up-server-polling! and have it return something
    ;; like a tuple.
    ;; So...it's doable.
    ;; Whether that's a "good way" or not is debatable.
    cookie ::specs/network-packet
    :as this}]
  (println "cookie: Top of servers-polled")
  (when-not log-state
    ;; This is an ugly situation.
    ;; Something has gone badly wrong
    (throw (ex-info "Missing log state"
                    {::state/state this
                     ::state-keys (keys this)})))
  (try
    (let [this (dissoc this ::specs/network-packet)
          log-state (log/info log-state
                              ::servers-polled!
                              "Forking child")
          ;; Got a Cookie response packet from server.
          ;; Theory in the reference implementation is that this is
          ;; a good signal that it's time to spawn the child to do
          ;; the real work.
          ;; Note that the packet-builder associated with this
          ;; will start as a partial built from build-initiate-packet!
          ;; The forked callback will call that until we get a response
          ;; back from the server.
          ;; At that point, we need to swap out packet-builder
          ;; as the child will be able to start sending us full-
          ;; size blocks to fill Message Packets.
          {:keys [::state/child]
           :as this} (state/fork! this)]
      this)
    (catch Exception ex
      (let [log-state (log/exception log-state
                                     ex
                                     ::servers-polled)
            log-state (log/flush-logs! logger log-state)
            failure (dfrd/error-deferred ex)]
        (assoc this
               ::log/state log-state
               ::specs/deferrable failure)))))

(s/fdef wait-for-cookie!
        :args (s/cat :this ::state/state
                     :timeout (s/and number?
                                     (complement neg?))
                     :sent ::specs/network-packet)
        :ret ::specs/deferrable)
(defn wait-for-cookie!
  "Pulls Cookie Packet from the wire, then triggers the response"
  [{:keys [::log/logger
           ::state/chan<-server]
    log-state ::log/state
    :as this}
   timeout send-success]
  (if (not= send-success ::state/sending-hello-timed-out)
    (let [this (assoc this
                      ::log/state (log/flush-logs! logger
                                                   (log/info (::log/state this)
                                                             ::wait-for-cookie!
                                                             "Sent to server"
                                                             send-success)))]
      (-> (strm/try-take! chan<-server
                                  ::drained
                                  timeout
                                  ::state/response-timed-out)
          (dfrd/chain
           (partial wrap-received this))
          (dfrd/catch (fn [ex]
                        (println "cookie/received-response! failed:" ex)
                        (throw (ex-info "received-response! failed"
                                        {::last-known this}
                                        ex))))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
