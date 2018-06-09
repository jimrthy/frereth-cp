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
;;; Internal

(s/fdef decrypt-actual-cookie
        :args (s/cat :this ::state/state
                     :received ::K/cookie-frame)
        :ret ::state/state)
(defn decrypt-actual-cookie
  [{:keys [::shared/packet
           ;; Having a shared work-area is probably
           ;; important for avoiding GC.
           ;; At the same time, the mutable state
           ;; causes a lot of trouble.
           ;; Q: Is it worth it?
           ;; A: Need benchmarks!
           ;; (but almost definitely not)
           ::shared/work-area
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
                             ::human-readable (shared/bytes->string cookie)})
        {^bytes text ::shared/text
         ^bytes working-nonce ::shared/working-nonce} work-area]
    (assert working-nonce (str "Missing nonce buffer amongst\n"
                               (keys work-area)
                               "\nin\n"
                               (keys this)))
    (let [log-state (log/info log-state
                              ::decrypt-actual-cookie
                              "Copying nonce prefix"
                              {::src K/cookie-nonce-prefix
                               ::dst working-nonce})]
      (b-t/byte-copy! working-nonce K/cookie-nonce-prefix)
      (b-t/byte-copy! working-nonce
                      K/server-nonce-prefix-length
                      K/server-nonce-suffix-length
                      client-nonce-suffix)
      (let [log-state (log/info log-state
                                ::decrypt-actual-cookie
                                "Copying encrypted cookie"
                                {::target text
                                 ::this this
                                 ::my-keys (keys this)})]
        (b-t/byte-copy! text 0 K/cookie-frame-length cookie)
        (let [shared (::state/client-short<->server-long shared-secrets)]
          (when-not shared
            (throw (ex-info "Missing client-short<->server-long secret"
                            {::state/shared-secrets shared-secrets})))
          (let [log-state (log/info log-state
                                    ::decrypt-actual-cookie
                                    "Trying to decrypt"
                                    {::shared/text  (b-t/->string text)
                                     ::shared/working-nonce (b-t/->string working-nonce)
                                     ::client-short<->server-long (b-t/->string shared)})]
            ;; TODO: If/when an exception is thrown here, it would be nice
            ;; to notify callers immediately
            (try
              (let [{log-state ::log/state
                     decrypted ::crypto/unboxed} (crypto/open-after log-state
                                                                    text
                                                                    0
                                                                    K/cookie-frame-length
                                                                    working-nonce
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
                                                  (.getData ex)))))))))))

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
                     :notifier dfrd/deferrable?
                     :cookie ::specs/network-packet)
        ;; The main point is the side-effect of "delivering" the notifier.
        ;; That will become a map that includes a) the updated log-state
        ;; (although, honestly, it should be a seq of functions for running
        ;; those updates...and those functions need a way to specify
        ;; the current time)
        ;; and b) the cookie (if we managed to decrypt it)
        :ret any?)
(defn received-response!
  "Hello triggers this when we hear back from the Server"
  [{log-state ::log/state
    :keys [::log/logger]
    :as this}
   notifier
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
                  (= cookie ::hello-response-timed-out))
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
              ;; It seems highly likely that I'm either messing up a) where the cookie
              ;; wound up in decrypted or b) just discarding it
              ;; Q: Is merge-with really more appropriate than plain into ?
              (let [this (merge this decrypted)
                    {:keys [::shared/my-keys]} this
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
                    (dfrd/success! notifier {::log/state (log/debug log-state
                                                                    log-label
                                                                    (str "Prepared shared short-term secret\n"
                                                                         "Should resolve the cookie-response in client/poll-servers-with-hello!"))
                                             ::state/server-security (::state/server-security decrypted)
                                             ::state/shared-secrets shared-secrets
                                             ::shared/network-packet cookie}))
                  (dfrd/error! notifier {::log/state (log/error log-state
                                                                log-label
                                                                (str "Missing ::specs/public-short among\n"
                                                                     (keys (::state/server-security this))
                                                                     "\namong bigger-picture\n"
                                                                     (keys this)))})))
              ;; This is a failure, really.
              ;; Discards the packet, update recent (and thus the polling timeout)
              ;; and go back to polling.
              (dfrd/success! notifier {::log/state (log/warn log-state
                                                             log-label
                                                             "Unable to decrypt server cookie"
                                                             {::problem cookie})}))
            ;; TODO: Look into recovering from these
            (catch ExceptionInfo ex
              (dfrd/error! notifier (assoc this ::log/state (log/exception log-state
                                                                           ex
                                                                           log-label
                                                                           "High-level failure"))))
            (catch RuntimeException ex
              (dfrd/error! notifier {::log/state (log/exception log-state
                                                                ex
                                                                log-label
                                                                "Unexpected failure")}))
            (catch Exception ex
              (dfrd/error! notifier {::log/state (log/exception log-state
                                                                ex
                                                                log-label
                                                                "Low-level failure")}))
            (catch Throwable ex
              (dfrd/error! notifier {::log/state (log/exception log-state
                                                                ex
                                                                log-label
                                                                "Serious Problem")})))
          (dfrd/success! notifier {::log/state (log/warn log-state
                                                         log-label
                                                         "Invalid response. Just discard and retry"
                                                         {::problem cookie})}))
        (let [log-state (log/warn log-state
                                  log-label
                                  "Server didn't respond to HELLO. Move on to next.")]
          (dfrd/success! notifier {::log/state log-state})))
      (catch Exception ex
        (dfrd/error! {::log/state (log/exception log-state
                                                 ex
                                                 log-label)})))))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef servers-polled
        :args (s/cat :this ::state/state)
        :ret ::state/state)
(defn servers-polled
  "Got back a cookie. Respond with a vouch"
  [{log-state ::log/state
    logger ::log/logger
    ;; Q: Is there a good way to pry this out
    ;; so it's its own parameter?
    cookie ::specs/network-packet
    :as this}]
  (println "client: Top of servers-polled")
  (when-not log-state
    ;; This is an ugly situation.
    ;; Something has gone badly wrong
    (let [logger (if logger
                   logger
                   (log/std-out-log-factory))]
      (log/warn (log/init ::servers-polled)
                ::missing-log-state
                ""
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
                     :notifier dfrd/deferrable?
                     :timeout (s/and number?
                                     (complement neg?))
                     :sent ::specs/network-packet)
        :ret ::specs/deferrable)
(defn wait-for-cookie!
  [this notifier timeout sent]
  (if (not= sent ::sending-hello-timed-out)
    (let [this (update this
                       ::log/state
                       #(log/info %
                                  ::wait-for-cookie!
                                  "Sent to server"
                                  sent))]
      (let [chan<-server (::state/chan<-server this)
            d (strm/try-take! chan<-server
                                ::drained
                                timeout
                                ::hello-response-timed-out)]
        (dfrd/on-realized d
                          (partial received-response! this notifier)
                          (partial hello-response-failed! this))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
