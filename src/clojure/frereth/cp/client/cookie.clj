(ns frereth.cp.client.cookie
  (:require [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [frereth.cp.client
             [state :as state]]
            [frereth.cp
             [shared :as shared]
             [util :as utils]]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [specs :as specs]
             [serialization :as serial]
             [templates :as templates]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::succss-callback (s/fspec :args ::state/cookie-response
                                  :ret any?))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef decrypt-actual-cookie
        :args (s/cat :this (s/keys :req [::weald/state
                                         ::shared/packet
                                         ::state/server-security
                                         ::state/shared-secrets])
                     :received ::templates/cookie-frame)
        :ret (s/keys :req [::weald/state]
                     :opt [::state/server-security]))
(defn decrypt-actual-cookie
  [{:keys [::shared/packet
           ::state/server-security
           ::state/shared-secrets]
    log-state ::weald/state
    :as this}
   {:keys [::templates/client-extension
           ::templates/client-nonce-suffix
           ::templates/cookie
           ::templates/header
           ::templates/server-extension]
    :as rcvd}]
  (let [client-nonce-suffix (bytes client-nonce-suffix)
        cookie (bytes cookie)
        log-state (log/debug log-state
                             ::decrypt-actual-cookie
                             "Setting up cookie decryption"
                             {::this this
                              ::my-keys (keys this)})
        shared (::state/client-short<->server-long shared-secrets)]
    (when-not shared
      (throw (ex-info "Missing client-short<->server-long secret"
                      {::state/shared-secrets shared-secrets
                       ::weald/state log-state})))
    (try
      (let [log-state (log/debug log-state ::decrypt-actual-cookie
                                 "Getting ready to try to unbox cookie\nFIXME: Don't log shared secret"
                                 (assoc (select-keys rcvd [::templates/cookie
                                                           ::templates/client-nonce-suffix])
                                        ::state/client-short<->server-long shared))
            {log-state ::weald/state
             decrypted ::crypto/unboxed} (crypto/open-box log-state
                                                          K/cookie-nonce-prefix
                                                          client-nonce-suffix
                                                          cookie
                                                          shared)]
        (if decrypted
          (let [{server-short-pk ::templates/s'
                 server-cookie ::templates/inner-cookie
                 :as extracted} (serial/decompose templates/cookie decrypted)
                server-security (assoc (::state/server-security this)
                                       ::specs/public-short server-short-pk,
                                       ::state/server-cookie server-cookie)]
            (assert server-cookie)
            {::state/server-security server-security
             ::weald/state log-state})
          {::weald/state (log/warn log-state
                                   ::decrypt-actual-cookie
                                   "Decryption failed silently")}))
      (catch RuntimeException ex
        {::weald/state (log/exception log-state
                                      ex
                                      ::decrypt-actual-cookie
                                      "Decryption failed")}))))

(s/fdef decrypt-cookie-packet
        :args (s/cat :this (s/keys :req [::weald/state
                                         ::shared/extension
                                         ::shared/packet
                                         ::state/server-extension
                                         ::state/server-security
                                         ::state/shared-secrets]))
        :ret (s/keys :req [::weald/state]
                     :opt [::state/server-security]))
(defn decrypt-cookie-packet
  [{:keys [::shared/extension
           ::shared/packet
           ::state/server-extension]
    log-state ::weald/state
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
        {:keys [::templates/header
                ::templates/client-extension
                ::templates/server-extension]
         :as rcvd} (serial/decompose-array templates/cookie-frame packet)
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
                                    ::weald/state log-state)
                             rcvd))))

(s/fdef expected-sender?
        :args (s/cat :server-security ::state/server-security
                     :host ::shared/host
                     :port ::specs/port)
        :ret boolean?)
(defn expected-sender?
  "Did the Cookie we just received come from the expected server?"
  [{:keys [::specs/srvr-port
           ::specs/srvr-ip]}
    host port]
  ;; Next step for reference implementation is to compare the
  ;; expected server IP and port vs. what we received.

  ;; The main point to this is that it identifies the server we meant
  ;; to address in this iteration of the Hello loop.
  ;; There are a lot of "does this really make sense?" questions
  ;; to be asked here.

  ;; That info's pretty unreliable/meaningless, but the server
  ;; address probably won't change very often.
  ;; Unless we're communicating with a server on someone's cell
  ;; phone.
  ;; Which, if this is successful, will totally happen.
  ;; Actually, the odds of clojure on a phone seem pretty slim.
  ;; TODO: Verify host/port before trying to proceed
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
  (let [result (and (= srvr-port port)
                    ;; This seems dicey
                    (= srvr-ip host))]
    (when-not result
      (println (str "("
                    (if (= srvr-port port)
                      "=" "not")
                    "= " srvr-port " " port ")\n"
                    "("
                    (if (= srvr-ip host)
                      "=" "not")
                    "= " srvr-ip " " host ")")))
    result))

(s/fdef do-received-response
        :args (s/cat :this ::state/state
                     :cookie ::specs/network-packet)
        :ret ::state/state)
(defn do-received-response
  "Hello triggers this (via wait-for-cookie) when it hears back from a Server"
  [{log-state ::weald/state
    :keys [::weald/logger
           ::state/server-security]
    :as this}
   {:keys [:host :message :port]
        :or {message (byte-array 0)}
        :as cookie}]
  (let [log-label ::do-received-response
        log-state (log/info log-state
                            log-label
                            "Possibly got a response from server"
                            cookie)]
    (try
      (if-not (or (= cookie ::drained)
                  (= cookie ::state/response-timed-out))
        ;; Line 301 in reference
        (if (= K/cookie-packet-length (count message))
          (try
            (when-not (expected-sender? server-security
                                        host
                                        port)
              (throw (ex-info "Response from wrong server (probably one we've already discarded)"
                              {::expected server-security
                               ::actual cookie})))

            ;; Line 312
            (if-let [decrypted (decrypt-cookie-packet (assoc (select-keys this
                                                                          [::shared/extension
                                                                           ::state/server-extension
                                                                           ::state/server-security
                                                                           ::state/shared-secrets])
                                                             ::weald/state log-state
                                                             ::shared/packet message))]
              ;; Q: Would merge-with be more appropriate?
              (let [{:keys [::state/server-security]
                     log-state ::weald/state} decrypted
                    {:keys [::shared/my-keys]
                     :as this} (merge this decrypted)]
                (if server-security
                  (let [server-short (get-in this
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
                        ;; This is an exception I added temporarily for debugging error
                        ;; situations.
                        ;; Throwing this causes us to forget the incoming Cookie. And
                        ;; either move on to the next server or wait for another Cookie from
                        ;; this one (which, realistically, won't happen).
                        ;; TODO: Write a test that checks this without the faked-up exception
                        ;; here
                        (comment (throw (ex-info "This should discard the cookie"
                                                 {::problem "How is this proceeding?"})))
                        ;; Yay! Reached the Happy Path
                        (assoc this
                               ::weald/state (log/debug log-state
                                                        log-label
                                                        (str "Prepared shared short-term secret\n"
                                                             "Cookie:\n"
                                                             (b-t/->string (get-in decrypted [::state/server-security
                                                                                              ::state/server-cookie]))))
                               ::state/server-security (::state/server-security decrypted)
                               ::state/shared-secrets shared-secrets
                               ::shared/network-packet cookie))
                      (update this ::weald/state
                              #(log/error %
                                          log-label
                                          (str "Missing ::specs/public-short among\n"
                                               (keys (::state/server-security this))
                                               "\namong bigger-picture\n"
                                               (keys this))))))
                  ;; This is a failure, really.
                  ;; Discards the packet, update recent (and thus the polling timeout)
                  ;; and go back to polling.
                  (assoc this
                         ::weald/state (log/warn log-state
                                                 log-label
                                                 "Missing ::state/server-security"
                                                 {::problem cookie
                                                  ::decrypted (dissoc decrypted ::weald/state)}))))
              (assoc this
                     ::weald/state (log/warn log-state
                                             log-label
                                             "Decryption failed so badly we didn't even get back a log message"
                                             {::problem cookie})))
            ;; TODO: Look into recovering from the variations that are recoverable
            (catch Throwable ex
              (assoc this ::weald/state (log/exception log-state
                                                       ex
                                                       log-label
                                                       "Unhandled failure"))))
          (assoc this
                 ::weald/state (log/warn log-state
                                         log-label
                                         "Invalid response. Just discard and retry"
                                         {::problem cookie
                                          ::cookie-length (count cookie)})))
        (let [log-state (log/warn log-state
                                  log-label
                                  "Server didn't respond to HELLO. Move on to next.")]
          (assoc this ::weald/state log-state)))
      (catch Exception ex
        {::weald/state (log/exception log-state
                                      ex
                                      log-label)}
        (throw ex)))))

(s/fdef wrap-received
        :args (s/cat :this ::state/state
                     :incoming ::specs/network-packet)
        :ret ::state/state)
(defn wrap-received
  [{log-state ::weald/state
    :keys [::weald/logger]
    :as this}
   incoming]
  (println "The wait for the cookie has ended")
  (pprint incoming)
  (let [this
        (assoc this
               ::weald/state (log/flush-logs! logger (log/trace log-state
                                                                ::wait-for-cookie!
                                                                "Pulled from server"
                                                                {::specs/network-packet incoming})))]
    (do-received-response this incoming)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef servers-polled
        :args (s/cat :this ::state/state)
        :ret ::state/state)
(defn servers-polled
  "Got back a cookie. Respond with an Initiate"
  [{log-state ::weald/state
    logger ::weald/logger
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
           :as this} (state/fork! (assoc this
                                         ::weald/state log-state))]
      this)
    (catch Exception ex
      (let [log-state (log/exception log-state
                                     ex
                                     ::servers-polled)
            log-state (log/flush-logs! logger log-state)
            failure (dfrd/error-deferred ex)]
        (assoc this
               ::weald/state log-state
               ::specs/deferrable failure)))))

(s/def wait-for-cookie! ::state/cookie-waiter)
(defn wait-for-cookie!
  "Pulls Cookie Packet from the wire, then triggers the response"
  [{:keys [::weald/logger
           ::state/chan<-server]
    log-state ::weald/state
    :as this}
   timeout send-success]
  (if (not= send-success ::state/sending-hello-timed-out)
    (let [this (assoc this
                      ::weald/state (log/flush-logs! logger
                                                     (log/info (::weald/state this)
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
                        (println "cookie/do-received-response failed:" ex)
                        (throw (ex-info "cookie/do-received-response failed"
                                        {::last-known this}
                                        ex))))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
