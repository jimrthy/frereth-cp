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
    ;; Well, the proof *is* in the pudding.
    ;; The most important point is whether the other side sent
    ;; us a cookie we can decrypt using our shared key.
    (when (and (b-t/bytes= K/cookie-header header)
               (b-t/bytes= extension client-extension)
               (b-t/bytes= server-extension server-extension))
      (decrypt-actual-cookie (assoc this
                                    ::log/state log-state)
                             rcvd))))

(s/fdef received-response
        :args (s/cat :this ::state/state
                     :notifier dfrd/deferrable?
                     :cookie ::specs/network-packet)
        :ret any?)
(defn received-response
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
  (let [log-state (log/info log-state
                            ::received-response
                            "Possibly got a response from server"
                            cookie)]
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
        ;; FIXME: Verify those before trying to proceed
        (try
          (if-let [decrypted (decrypt-cookie-packet (assoc (select-keys this
                                                                        [::shared/extension
                                                                         ::shared/work-area
                                                                         ::state/server-extension
                                                                         ::state/server-security
                                                                         ::state/shared-secrets])
                                                           ::log/state log-state
                                                           ::shared/packet message))]
            (let [this (into this decrypted)
                  {:keys [::shared/my-keys]} this
                  server-short (get-in this
                                       [::state/server-security
                                        ::specs/public-short])
                  log-state (log/debug log-state
                                       ::cookie->vouch
                                       "Managed to decrypt the cookie")]
              (assert server-short (str "Missing ::specs/public-short among\n"
                                        (keys (::state/server-security this))
                                        "\namong bigger-picture\n"
                                        (keys this)))
              (let [^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
                    ;; line 327
                    this (assoc-in this
                                   [::state/shared-secrets ::state/client-short<->server-short]
                                   (crypto/box-prepare
                                    server-short
                                    (.getSecretKey my-short-pair)))
                    log-state (log/debug log-state
                                         ::cookie->vouch
                                         "Prepared shared short-term secret")]
                (dfrd/success! notifier (assoc this
                                               ::log/state log-state
                                               ::specs/network-packet cookie))))
            (let [log-state (log/warn log-state
                                      ::received-response
                                      "Unable to decrypt server cookie"
                                      {::problem cookie})]
              (dfrd/success! notifier (assoc this ::log/state log-state))))
          ;; TODO: Look into recovering from these
          (catch ExceptionInfo ex
            (let [log-state (log/exception log-state
                                           ex
                                           ::received-response
                                           "High-level failure")
                  log-state (log/flush-logs! logger log-state)]
              (dfrd/error! notifier (assoc this ::log/state log-state))))
          (catch RuntimeException ex
            (let [log-state (log/exception log-state
                                           ex
                                           ::received-response
                                           "Unexpected failure")
                  log-state (log/flush-logs! logger log-state)]
              (dfrd/error! notifier (assoc this ::log/state log-state))))
          (catch Exception ex
            (let [log-state (log/exception log-state
                                           ex
                                           ::received-response
                                           "Low-level failure")
                  log-state (log/flush-logs! logger log-state)]
              (dfrd/error! notifier (assoc this ::log/state log-state))))
          (catch Throwable ex
            (let [log-state (log/exception log-state
                                           ex
                                           ::received-response
                                           "Serious Problem")
                  log-state (log/flush-logs! logger log-state)]
              (dfrd/error! notifier (assoc this ::log/state log-state)))))
        (let [log-state (log/warn log-state
                                  ::received-response
                                  "Invalid response. Just discard and retry"
                                  {::problem cookie})]
          (dfrd/success! notifier (assoc this ::log/state log-state))))
      (let [log-state (log/warn log-state
                                ::received-response
                                "Server didn't respond to HELLO. Move on to next.")]
        (dfrd/success! notifier (assoc this ::log/state log-state))))))

(s/fdef hello-response-failed
        :args (s/cat :wrapper ::state/state-agent
                     :failure ::specs/throwable))
(defn hello-response-failed!
  [this failure]
  ;; FIXME: Find a better way to signal this so wait-for-cookie!
  ;; doesn't need access to the agent.
  (send this #(throw (ex-info "Timed out waiting for hello response"
                              {::problem %}
                              failure))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef wait-for-cookie!
        :args (s/cat :wrapper ::state/agent-wrapper
                     :this ::state/state
                     :notifier dfrd/deferrable?
                     ::timeout (s/and number?
                                      (complement neg?))
                     :sent ::specs/network-packet)
        :ret any?)
(defn wait-for-cookie!
  ;; FIXME: Eliminate wrapper from here.
  [wrapper this notifier timeout sent]
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
                          (partial received-response this notifier)
                          (partial hello-response-failed! wrapper))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
