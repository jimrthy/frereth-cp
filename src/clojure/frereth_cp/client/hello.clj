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
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;; TODO: Fix this spec. s/keys just doesn't cut it.
;; If we have any of the "optional" keys, we must have all 3.
;; And, realistically, I don't want anything more. There's
;; to much potential to smuggle in extra crap that shouldn't
;; be involved here.
(s/def ::cookie-response (s/keys :req [::log/state]
                                 :opt [::state/security
                                       ::state/shared-secrets
                                       ::shared/network-packet]))

(s/def ::servers-polled (s/or :possibly-succeeded dfrd/deferrable?
                              :failed ::state/state))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Globals

(set! *warn-on-reflection* true)

(def max-server-attempts 8)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef send-succeeded!
        ;; Yes, the logger parameter is redundant
        :args (s/cat :logger ::log/logger
                     :this ::state/state)
        :ret any?)
(defn send-succeeded!
  [logger this]
  (as-> (::log/state this) x
    (log/info x
              ::send-succeeded!
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
  ;; This is really set up in response to a
  ;; completion error.
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
                     "server-security" server-security)
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

;; This matches the global hellowait array from line 27
(let [hello-wait-time (reduce (fn [acc n]
                                (let [previous (last acc)]
                                  (conj acc (* 1.5 previous))))
                              [(util/seconds->nanos 1)]
                              (range max-server-attempts))]
  (defn pick-next-timeout
    ;; This is what's going on in
    ;; FIXME: Needs unit test
    [n-remaining]
    (let [n (- (count hello-wait-time))
          timeout (nth hello-wait-time n)]
      ;; This matches up with line 289
      (+ timeout (crypto/random-mod timeout)))))

(declare do-polling-loop)
(s/fdef cookie-result-callback
        :args (s/cat :this ::state/state
                     :cokie-response dfrd/deferrable?
                     ;; Q: What is this?
                     ;; A: It looks like it should be a ::cookie/success-callback
                     ;; Since I'm trying to called dfrd/success! on it below,
                     ;; that better not be the case
                     ;; TODO: Either way, move that spec somewhere shared

                     ;; Q: What is this?
                     :actual-success any?)
        :ret any?)
(defn cookie-result-callback
  [{:keys [::log/logger]
    log-state ::log/state
    :as this}
   ;; Q: Can this go away?
   cookie-response
   actual-success]
  {:pre [actual-success]}
  (let [now (System/nanoTime)]
    ;; TODO: convert this to a log message
    ;; (although, admittedly, it's really helpful for debugging)
    (println "hello/cookie-result-callback: Received network packet:\n"
             (::shared/network-packet actual-success))
    (if (and (not (instance? Throwable actual-success))
             (not (#{::sending-hello-timed-out
                     ::awaiting-cookie-timed-out
                     ::send-response-timed-out} actual-success)))
      (do
        (when-let [problem (s/explain-data ::cookie-response actual-success)]
          (println "hello/cookie-result-callback Bad cookie response:" problem)
          (dfrd/error! cookie-response
                       (ex-info "Bad cookie response"
                                {::error problem})))
        ;; FIXME: Debug only
        (println "hello/cookie-result-callback Cookie response was OK")
        (let [log-state (try
                          (log/info (::log/state actual-success)
                                    ::do-polling-loop
                                    "Might have found a responsive server")
                          (catch Exception ex
                            (println "client: Failed trying to log about potentially responsive server\n"
                                     (log/exception-details ex))
                            (dfrd/error! (ex-info "Logging failure re: server response" {::actual-success actual-success} ex))))]
          (dfrd/success! cookie-response actual-success)))
      (dfrd/success! cookie-response {::log/state (log/warn log-state
                                                            ::do-polling-loop
                                                            "Problem retrieving cookie"
                                                            {;; Actually, if this is a Throwable,
                                                             ;; we probably don't have a way
                                                             ;; to recover
                                                             ::outcome actual-success})}))))

(s/fdef possibly-recurse
        :args (s/cat :completion ::specs/deferrable
                     :this ::state/state)
        :fn (s/or :recursion (s/fspec :args nil?
                                      :ret ::log/state)
                  :giving-up ::log/state))
(defn possibly-recurse
  [{:keys [::log/logger
           ::state/server-ips]
    log-state ::log/state
    :as this}
   cookie-sent-callback
   raw-packet]
  ;; Sending the packet probably isn't going to fail. But it's good
  ;; to handle the possibility
  (let [remaining-ips (next server-ips)
        log-state (log/flush-logs! logger (log/warn log-state
                                                    ::possibly-recurse
                                                    "Sending HELLO failed. Will try the next (if any) in the list"
                                                    {::state/server-ips remaining-ips}))]
    (if remaining-ips
      ;; Return the function for the trampoline to call
      (partial do-polling-loop
               (assoc this
                      ::log-state log-state)
               raw-packet
               cookie-sent-callback
               (System/nanoTime)
               (pick-next-timeout (count remaining-ips))
               remaining-ips)
      (throw (ex-info "Giving up" this)))))

(s/fdef cookie-sent
        :args (s/cat :this ::state/state
                     :raw-packet ::specs/network-packet
                     :log-state-atom ::log/state-atom
                     :cookie-response dfrd/deferrable?
                     :cookie-sent-callback (s/fspec :args (s/cat :this ::state/state
                                                                 :result dfrd/deferrable?
                                                                 :timeout nat-int?
                                                                 :sent ::specs/network-packet)
                                                    :ret any?)
                     :send-packet-success boolean?)
        ;; Actually, it should return a deferrable
        ;; that resolves to a ::cookie-response
        :ret (s/or :response dfrd/deferrable?
                   :recursed ::cookie-response))
(defn cookie-sent
  ;; TODO: Come up with a better name. do-polling-loop
  ;; needs both this and a callback from the cookie
  ;; ns that it's named cookie-sent-callback.
  ;; Need to make them different enough that I won't
  ;; get them snarled up.

  ;; Q: Is there enough going on in here to justify
  ;; having a stand-alone top-level function?
  [{:keys [::state/timeout
           :state/server-ips]
    :as this}
   raw-packet
   log-state-atom
   cookie-response
   ;; Yeah. This is where the names go haywire
   cookie-sent-callback
   send-packet-success]
  (if send-packet-success
    ;; Note that this timeout actually can grow to be quite long.
    ;; In the original, they probably add up to a ballpark of a minute.
    ;; It's probably acceptable for a single polling thread to block for that
    ;; long.
    ;; Or, at least, it probably was back in 2011 when the spec was written,
    ;; or in 2013 when my copy of the reference implementation was published.
    ;; Q: Is that still reasonable today?
    ;; Better Q: Is there a better alternative?
    (dfrd/timeout! cookie-response timeout ::awaiting-cookie-timed-out)
    ;; I'd really like to trampoline this. Realistically, we can't, because
    ;; we're inside a deferred chain.
    ;; TODO: Prove that, one way or another
    (trampoline possibly-recurse
                (assoc this ::log/state @log-state-atom)
                server-ips cookie-sent-callback raw-packet)))

(s/fdef cookie-retrieved
        :args (s/cat :this ::state/state
                     :raw-packet ::specs/network-packet
                     :cookie-sent-callback (s/fspec :args (s/cat :notifier ::specs/deferrable
                                                                 :timeout (s/and number?
                                                                                 (complement neg?))
                                                                 :this ::state/state
                                                                 :sent ::specs/network-packet))
                     :start-time  (s/and number?
                                         (complement neg?))
                     ;; FIXME: If this isn't somewhere shared already,
                     ;; move it there
                     :timeout  (s/and number?
                                      (complement neg?))
                     :ips ::specs/srvr-ips)
        :ret ::state/state)
(defn cookie-retrieved
  [{log-state ::log/state
    :keys [::log/logger
           ::shared/network-packet
           ::state/server-security
           ::state/shared-secrets]
    :as this}
   raw-packet
   cookie-sent-callback
   start-time
   timeout
   ips]
  (let [now (System/nanoTime)
        {:keys [::specs/srvr-ip]} server-security]
    ;; This really should be a log message. Time after time, it's shown up in STDOUT
    ;; as a marker when my logs disappear.
    ;; That isn't an endorsement of using the print.
    ;; It's probably more of a sign that maybe logs simply are not meant to be
    ;; accrued this way.
    ;; Then again, logs are really for diagnosing production issues, not debugging
    ;; problems at dev time
    (println "hello/cookie-retrieved:\n"
             (dissoc this ::log/state)
             "\nTop-level keys:\n"
             (keys this)
             "\nServer:"
             srvr-ip)
    (if network-packet
      (do
        (if (and server-security shared-secrets)

          ;; Sometime between now and state/child-> the ::state/state should get
          ;; a ::state/server-cookie key added to its ::state/server-security
          ;; structure.
          ;; Spoiler: it's supposed to happen after the cookie gets decrypted,
          ;; just before state/fork!
          ;; That's stopped happening again.
          ;; It was probably a prime motivation behind the contortions I just
          ;; ironed out.
          ;; Need to move on to Vouch. But there's already far
          ;; too much happening here.
          (assoc this ::log/state (log/debug log-state
                                             ::cookie-retrieved
                                             "Got back a usable cookie"
                                             (dissoc this ::log/state)))
          (do
            (log/flush-logs! logger (log/error log-state
                                               ::cookie-retrieved
                                               "Got back a network-packet but missing something else"
                                               {::cookie-response this}))
            (throw (ex-info "Network-packet missing either security or shared-secrets"
                            {::problem this})))))
      (let [elapsed (- now start-time)
            remaining (- timeout elapsed)
            log-state (log/info log-state
                                ::cookie-retrieved
                                "Discarding garbage cookie")]
        (if (< 0 remaining)
          ;; Q: Use trampoline instead?
          ;; A: That would get into all sorts of weirdness, because this
          ;; is nested inside a deferred handler.
          ;; Famous Last Words:
          ;; The call stack on this should never get all that deep.
          (do-polling-loop
           (assoc this ::log/state (log/flush-logs! logger (log/info log-state
                                                                     ::cookie-retrieved
                                                                     "Still waiting on server"
                                                                     {::shared/host srvr-ip
                                                                      ::millis-remaining remaining})))
           raw-packet
           cookie-sent-callback
           start-time
           remaining
           ips)
          (possibly-recurse (assoc this ::log/state (log/flush-logs! logger (log/info log-state
                                                                                      ::cookie-retrieved
                                                                                      "Moving on to next ip")))
                            raw-packet
                            cookie-sent-callback
                            now
                            (pick-next-timeout timeout)
                            ips))))))

(s/fdef do-polling-loop
        :args (s/cat :this ::state/state
                     :raw-packet ::specs/network-packet
                     :cookie-sent-callback (s/fspec :args (s/cat :this ::state/state
                                                                 :result dfrd/deferrable?
                                                                 :timeout nat-int?
                                                                 :sent ::specs/network-packet)
                                                    :ret any?)
                     :start-time nat-int?
                     :timeout (s/and number?
                                     (complement neg?))
                     :ips ::state/server-ips)
        :ret ::state/state)
(defn do-polling-loop
  [{:keys [::log/logger
           ::specs/executor
           ::state/chan->server
           ::state/server-security]
    :as this}
   raw-packet cookie-sent-callback start-time timeout ips]
  (let [srvr-ip (first ips)
        log-state (log/info (::log/state this)
                            ::do-polling-loop
                            "Polling server"
                            {::specs/srvr-ip srvr-ip})
        {:keys [::specs/srvr-port]} server-security
        this (-> this
                 (assoc ::log/state log-state)
                 (assoc-in [::state/server-security ::specs/srvr-ip] srvr-ip))]
    (-> chan->server
        (strm/try-put! {:host srvr-ip
                        :message raw-packet
                        :port srvr-port}
                       timeout
                       ::state/sending-hello-timed-out)
        (dfrd/chain
         ;; Note that this is actually cookie/wait-for-cookie!
         #(cookie-sent-callback this
                                timeout
                                %)
         #(cookie-retrieved % raw-packet cookie-sent-callback start-time timeout ips))
        (dfrd/catch (fn [ex]
                      (assoc this
                             ;; FIXME: This is where the log-state-atom would come in handy
                             ::log/state (swap! #_log-state-atom log-state
                                                #(log/flush-logs! logger
                                                                  (log/exception %
                                                                                 ex
                                                                                 ::do-polling-loop)))))))))

(s/fdef poll-servers!
        :args (s/cat :this ::state/state
                     :timeout nat-int?
                     :cookie-waiter (s/fspec :args (s/cat :notifier ::specs/deferrable
                                                          :timeout (s/and number?
                                                                          (complement neg?))
                                                          :this ::state/state
                                                          :sent ::specs/network-packet)))
        :ret ::servers-polled)
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
    (println "Hello: Entering the server polling loop")
    (try
      (do-polling-loop (assoc this ::log/state log-state)
                       raw-packet
                       cookie-waiter
                       (System/nanoTime)
                       ;; FIXME: The initial timeout needs to be customizable
                       ;; Q: Why aren't I using timeout?
                       ;; A: Because it can grow to be arbitrarily long.
                       ;; This is really about the timeout for the packet
                       ;; send. Honestly, this is far too long.
                       (util/seconds->nanos 1)
                       ;; Q: Do we really want to max out at 8?
                       ;; 8 means over 46 seconds waiting for a response,
                       ;; but what if you want the ability to try 20?
                       ;; Or don't particularly care how long it takes to get a response?
                       ;; Stick with the reference implementation version for now.
                       (take max-server-attempts (cycle server-ips)))
      (catch Exception ex
        (assoc this ::log/state (log/exception log-state
                                               ex
                                               ::poll-servers!))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-build-packet
        ;; FIXME: Be more restrictive about this.
        ;; Only pass/return the pieces that this
        ;; actually uses.
        ;; Since that involves tracing down everything
        ;; it calls (et al), that isn't quite trivial.
        :args (s/cat :this ::state/state)
        ;; However:
        ;; It absolutely should not return much more than
        ;; the bytes of the packet.
        ;; And probably things like the nonce generator
        ;; state.
        ;; Probably the short-term key.
        ;; But definitely not the full state
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
  [{:keys [::log/logger
           ::shared/packet-management
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
                              ::do-build-packet
                              "Packed short-term- into working- -nonces"
                              {::short-term-nonce short-term-nonce
                               ::shared/working-nonce (b-t/->string working-nonce)})
          {:keys [::shared/packet]
           log-state ::log/state} (build-actual-packet (assoc this ::log/state log-state)
                                                        short-term-nonce
                                                        working-nonce)
          log-state (log/info log-state
                              ::do-build-packet
                              "hello packet built. Returning/updating")]
      (-> this
          (update ::shared/packet-management
                  (fn [current]
                    (assoc current
                           ::shared/packet-nonce short-term-nonce
                           ::shared/packet (b-s/convert packet io.netty.buffer.ByteBuf))))
          (assoc ::log/state (log/flush-logs! logger log-state))))))

(s/fdef set-up-server-polling!
        :args (s/cat :this ::state/state
                     :timeout (s/and #((complement neg?) %)
                                     int?)
                     ;; TODO: Spec this out
                     :wait-for-cookie! any?
                     ;; TODO: Spec this out
                     :build-inner-vouch any?
                     :servers-polled any?)
        :ret ::servers-polled)
(defn set-up-server-polling!
  "Start polling the server(s) with HELLO Packets"
  [{:keys [::log/logger]
    :as this}
   log-state-atom
   timeout
   wait-for-cookie!]
  (println "hello: polling triggered")
  (let [this (do-build-packet this)]
    (poll-servers! this timeout wait-for-cookie!)))
