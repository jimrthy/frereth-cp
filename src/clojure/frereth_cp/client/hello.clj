#_(ns-unalias *ns* 'log)
(ns frereth-cp.client.hello
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as util]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(defn send-succeeded!
  [logger this]
  (as-> (::log/state this) x
    (log/info x
              ::hello-succeeded!
              "Polling complete. Child should be able to trigger Initiate/Vouch"
              {::result (dissoc this ::log/state)})
    ;; Note that the log-flush gets discarded, except
    ;; for its side-effects.
    ;; But those side-effects *do* include updating the clock.
    ;; So that seems good enough for rough work.
    (log/flush-logs! logger x)))

(s/fdef send-failed!
        :args (s/cat :this ::state/state
                     :completion ::specs/deferrable
                     :problem ::specs/throwable)
        :ret any?)
(defn send-failed!
  [{:keys [::log/logger
           ::log/state]
    :as this}
   completion
   ex]
  (log/flush-logs! logger
                   (log/exception state
                                  ex
                                  ::send-failed!))
  (dfrd/error! completion ex))


(s/fdef build-raw
        :args (s/cat :this ::state/state
                      :short-term-nonce any?
                      :working-nonce ::shared/working-nonce)
        :ret (s/keys :req [::K/hello-spec ::log/state]))
(defn build-raw
  [{:keys [::state/server-extension
           ::shared/extension
           ::shared/my-keys
           ::state/shared-secrets]
    log-state ::log/state
    :as this}
   short-term-nonce
   working-nonce]
  (let [log-state
        (if-let [{:keys [::state/server-security]} this]
          (log/debug log-state
                     ::build-raw
                     "server-security for raw-hello:" server-security)
          (log/warn log-state
                    ::build-raw
                    "Missing server-security"
                    {::keys (keys this)
                     ::state/state this}))
        my-short<->their-long (::state/client-short<->server-long shared-secrets)
        _ (assert my-short<->their-long)
        ;; Note that this definitely inserts the 16-byte prefix for me
        boxed (crypto/box-after my-short<->their-long
                                K/all-zeros (- K/hello-crypto-box-length K/box-zero-bytes) working-nonce)
        ^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
        log-state (log/info log-state
                            ::build-raw
                            ""
                            {::crypto-box (b-t/->string boxed)
                             ::shared/working-nonce (b-t/->string working-nonce)
                             ::my-short-pk (-> my-short-pair
                                               .getPublicKey
                                               b-t/->string)
                             ::server-long-pk (b-t/->string (get-in this [::state/server-security
                                                                          ::specs/public-long]))
                             ::state/client-short<->server-long (b-t/->string my-short<->their-long)})]
    {::template {::K/hello-prefix nil  ; This is a constant, so there's no associated value
                 ::K/srvr-xtn server-extension
                 ::K/clnt-xtn extension
                 ::K/clnt-short-pk (.getPublicKey my-short-pair)
                 ::K/zeros nil
                 ::K/client-nonce-suffix (b-t/sub-byte-array working-nonce K/client-nonce-prefix-length)
                 ::K/crypto-box boxed}
     ::log/state log-state}))

(s/fdef build-actual-hello-packet
        :args (s/cat :this ::state/state
                     ;; TODO: Verify that this is a long
                     :short-nonce integer?
                     :working-nonce bytes?)
        :ret ::state/state)
(defn build-actual-packet
  [{log-state ::log/state
    :as this}
   short-term-nonce
   working-nonce]
  (let [{raw-hello ::template
         log-state ::log/state} (build-raw this short-term-nonce working-nonce)
        log-state (log/info log-state
                            ::build-actual-packet
                            "Building Hello"
                            {::raw raw-hello})
        ^ByteBuf result (serial/compose K/hello-packet-dscr raw-hello)
        n (.readableBytes result)]
    (when (not= K/hello-packet-length n)
      (throw (ex-info "Built a bad HELLO"
                      {::expected-length K/hello-packet-length
                       ::actual n})))
    {::shared/packet result
     ::log/state log-state}))

(s/fdef do-polling-loop
        :args (s/cat :completion ::specs/deferrable
                     :this ::state/state
                     :raw-packet ::specs/network-packet
                     :cookie-sent-callback (s/fspec :args (s/cat :this ::state/state
                                                                 :sent ::specs/network-packet))
                     :start-time nat-int?
                     :timeout (s/and number?
                                     (complement neg?))
                     :ips ::state/server-ips)
        :ret ::log/state)
(defn do-polling-loop
  [completion
   {:keys [::log/logger
           ::specs/executor]
    :as this}
   raw-packet cookie-sent-callback start-time timeout ips]
  (let [ip (first ips)
        log-state (log/info (::log/state this)
                            ::do-polling-loop
                            "Polling server"
                            {::specs/srvr-ip ip})
        cookie-response (dfrd/deferred executor)
        this (-> this
                 (assoc ::log/state log-state)
                 (assoc-in [::state/server-security ::specs/srvr-ip] ip))
        cookie-waiter (partial cookie-sent-callback
                               this
                               cookie-response
                               timeout)
        {log-state ::log/state
         dfrd-send-success ::specs/deferrable} (state/do-send-packet this
                                                                     cookie-waiter
                                                                     (fn [ex]
                                                                       (dfrd/error! completion ex))
                                                                     timeout
                                                                     ::sending-hello-timed-out
                                                                     raw-packet)
        send-packet-success (deref dfrd-send-success 1000 ::send-response-timed-out)
        _ (println "client/poll-servers-with-hello! Hello sent:" send-packet-success)
        actual-success (deref cookie-response timeout ::awaiting-cookie-timed-out)
        _ (println "client/poll-servers-with-hello! Cookie received:" actual-success)
        now (System/nanoTime)]
    ;; I don't think send-packet-success matters much
    ;; Although...actually, ::send-response-timed-out would be a big
    ;; deal.
    ;; FIXME: Add error handling for that.
    (println "client/poll-servers-with-hello! Sending HELLO returned:"
             send-packet-success
             "\nQ: Does that value matter?"
             "\nactual-success:\n"
             (dissoc actual-success ::log/state)
             "\nTop-level keys:\n"
             (keys actual-success)
             "\nReceived:\n"
             (::specs/network-packet actual-success))
    (if (and (not (instance? Throwable actual-success))
             (not (#{::sending-hello-timed-out
                     ::awaiting-cookie-timed-out
                     ::send-response-timed-out} actual-success)))
      (let [log-state (try
                        (log/info (::log/state actual-success)
                                  ::do-polling-loop
                                  "Might have found a responsive server"
                                  {::specs/srvr-ip ip})
                        (catch Exception ex
                          (println "client: Failed trying to log about potentially responsive server\n"
                                   (log/exception-details ex))
                          (throw (ex-info "Logging failure re: server response" {::actual-success actual-success} ex))))
            log-state (try
                        (log/flush-logs! logger log-state)
                        (catch Exception ex
                          (println "client: Failed trying to flush logs re: server response\n"
                                   (log/exception-details ex))
                          (throw (ex-info "Log flush failure re: server response" {::actual-success actual-success} ex))))]
        (println "client: Should have a log message about possibly responsive server")
        (if-let [{:keys [::specs/network-packet]} actual-success]
          (do
            ;; Need to move on to Vouch. But there's already far
            ;; too much happening here.
            ;; So the deferred in completion should trigger servers-polled
            (dfrd/success! completion (assoc actual-success
                                             ::log/state log-state))
            log-state)
          (let [elapsed (- now start-time)
                remaining (- timeout elapsed)]
            (if (< 0 remaining)
              (recur completion
                     (assoc this ::log/state log-state)
                     raw-packet
                     cookie-sent-callback
                     start-time
                     ;; Note that this jacks up the orderly timeout progression
                     ;; Not that the progression is quite as orderly as it looked
                     ;; at first glance:
                     ;; there's a modulo against a random 32-byte number involved
                     ;; (line 289)
                     remaining
                     ips)
              (if-let [remaining-ips (next ips)]
                (recur completion
                       this
                       raw-packet
                       cookie-sent-callback
                       now
                       (* 1.5 timeout)
                       remaining-ips)
                (do
                  (dfrd/error! completion (ex-info "Giving up" this))
                  log-state))))))
      (let [this (assoc this (log/warn log-state
                                       ::do-polling-loop
                                       "Failed to connect"
                                       {::specs/srvr-ip ip
                                        ;; Actually, if this is a Throwable,
                                        ;; we probably don't have a way
                                        ;; to recover
                                        ::outcome actual-success}))]
        (if-let [remaining-ips (next ips)]
          (recur completion this raw-packet cookie-sent-callback now (* 1.5 timeout) remaining-ips)
          (do
            (dfrd/error! completion (ex-info "Giving up" this))
            (::log/state this)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-build-packet
        ;; FIXME: Be more restrictive about this.
        ;; Only pass/return the pieces that this
        ;; actually uses.
        ;; Since that involves tracing down everything
        ;; it calls (et al), that isn't quite trivial.
        :args (s/cat :this ::state/state)
        :ret ::state/state)
(defn do-build-packet
  "Puts plain-text hello packet into packet-management

  Note that, for all intents and purposes, this is really called
  for side-effects, even though it has trappings to make it look
  functional."
  ;; A major part of the way this is written revolves around
  ;; updating packet-management and work-area in place.
  ;; That seems like premature optimization here.
  ;; Though it seems as though it might make sense for
  ;; sending messages.
  ;; Then again, if the implementation isn't shared...can
  ;; it possibly be worth the trouble?
  [{:keys [::shared/packet-management
           ::shared/work-area]
    :as this}]
  (let [;; There's a good chance this updates my extension.
        ;; That doesn't get set into stone until/unless I
        ;; manage to handshake with a server
        {log-state ::log/state
         :as this} (state/clientextension-init this)
        working-nonce (::shared/working-nonce work-area)
        {:keys [::shared/packet-nonce ::shared/packet]} packet-management
        short-term-nonce (state/update-client-short-term-nonce packet-nonce)]
    (b-t/byte-copy! working-nonce K/hello-nonce-prefix)
    (b-t/uint64-pack! working-nonce K/client-nonce-prefix-length short-term-nonce)

    (let [log-state (log/info log-state
                              ::do-build-hello
                              "Packed short-term- into working- -nonces"
                              {::short-term-nonce short-term-nonce
                               ::shared/working-nonce (b-t/->string working-nonce)})
          {:keys [::shared/packet]
           log-state ::log/state} (build-actual-packet (assoc this ::log/state log-state)
                                                        short-term-nonce
                                                        working-nonce)
          log-state (log/info log-state
                              ::do-build-hello
                              "hello packet built inside the agent. Returning/updating")]
      (-> this
          (update ::shared/packet-management
                  (fn [current]
                    (assoc current
                           ::shared/packet-nonce short-term-nonce
                           ::shared/packet (b-s/convert packet io.netty.buffer.ByteBuf))))
          (assoc ::log/state log-state)))))

(s/fdef poll-servers!
        :args (s/cat :this ::state/state
                     :timeout nat-int?
                     :cookie-waiter (s/fspec :args (s/cat :notifier ::specs/deferrable
                                                          :timeout (s/and number?
                                                                          (complement neg?))
                                                          :this ::state/state
                                                          :sent ::specs/network-packet)))
        :ret (s/keys :req [::specs/deferrable
                           ::log/state]))
(defn poll-servers!
  "Send hello packet to a seq of server IPs associated with a single server name."
  ;; Ping a bunch of potential servers (listening on an appropriate port with the
  ;; appropriate public key) in a sequence until you get a response or a timeout.
  ;; In a lot of ways, it was an early attempt at what haproxy does.
  ;; Then again, haproxy doesn't support UDP, and it's from the client side.
  ;; So maybe this was/is breathtakingly cutting-edge.
  ;; The main point is to avoid waiting 20-ish minutes for TCP connections
  ;; to time out.
  [{:keys [::log/logger
           ::state/server-ips]
    log-state ::log/state
    {raw-packet ::shared/packet
     :as packet-management} ::shared/packet-management
    :as this}
   timeout cookie-waiter]
  (let [log-state (log/debug log-state
                             ::poll-servers!
                             "Putting hello(s) onto ->server channel"
                             {::raw-packet raw-packet})]
    ;; There's an important break
    ;; with the reference implementation
    ;; here: this should be sending the
    ;; HELLO packet to multiple server
    ;; end-points to deal with them
    ;; going down.
    ;; It's supposed to happen
    ;; in an increasing interval, to give
    ;; each a short time to answer before
    ;; the next, but a major selling point
    ;; is not waiting for TCP buffers
    ;; to expire.
    (let [completion (dfrd/deferred)]
      (dfrd/on-realized completion
                        (partial send-succeeded! logger)
                        (partial send-failed! this completion))
      (println "Client: Entering the hello polling loop")
      (let [log-state
            (try
              (do-polling-loop completion
                                     (-> this
                                         (assoc ::log/state log-state))
                                     raw-packet
                                     cookie-waiter
                                     (System/nanoTime)
                                     ;; FIXME: The initial timeout needs to be customizable
                                     (util/seconds->nanos 1)
                                     ;; Q: Do we really want to max out at 8?
                                     ;; 8 means over 46 seconds waiting for a response,
                                     ;; but what if you want the ability to try 20?
                                     ;; Or don't particularly care how long it takes to get a response?
                                     ;; Stick with the reference implementation version for now.
                                     (take 8 (cycle server-ips)))
                (catch Exception ex
                  (log/exception log-state
                                 ex
                                 ::poll-servers-with-hello!)))]
        {::specs/deferrable completion
         ;; FIXME: Move this back into hello (actually
         ;; that's problematic because it uses a function in
         ;; the cookie ns. And another in here. That really just
         ;; means another indirection layer of callbacks, but
         ;; it's annoying).
         ::log/state (log/flush-logs! logger log-state)}))))
