(ns frereth-cp.client.hello
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth-cp.client.state :as state]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log]
             [serialization :as serial]
             [specs :as specs]]
            [frereth-cp.util :as util]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

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
                      :safe-nonce ::shared/safe-nonce)
        :ret (s/keys :req [::K/hello-spec ::log/state]))
(defn build-raw
  [{:keys [::state/server-extension
           ::shared/extension
           ::shared/my-keys
           ::state/shared-secrets]
    log-state ::log/state
    :as this}
   short-term-nonce
   safe-nonce]
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
       safe-nonce (byte-array safe-nonce)
        ;; Note that this definitely inserts the 16-byte prefix for me
        boxed (crypto/box-after my-short<->their-long
                                K/all-zeros (- K/hello-crypto-box-length K/box-zero-bytes)
                                safe-nonce)
        ^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
        log-state (log/info log-state
                            ::build-raw
                            ""
                            {::crypto-box (b-t/->string boxed)
                             ::shared/safe-nonce (b-t/->string safe-nonce)
                             ::my-short-pk (-> my-short-pair
                                               .getPublicKey
                                               b-t/->string)
                             ::server-long-pk (b-t/->string (get-in this [::state/server-security
                                                                          ::specs/public-long]))
                             ::state/client-short<->server-long (b-t/->string my-short<->their-long)})
        nonce-suffix (byte-array (vec (drop specs/client-nonce-prefix-length
                                            safe-nonce)))]
    {::template {::K/hello-prefix nil  ; This is a constant, so there's no associated value
                 ::K/srvr-xtn server-extension
                 ::K/clnt-xtn extension
                 ::K/clnt-short-pk (.getPublicKey my-short-pair)
                 ::K/zeros nil
                 ::K/client-nonce-suffix nonce-suffix
                 ::K/crypto-box boxed}
     ::log/state log-state}))

(s/fdef build-actual-hello-packet
        :args (s/cat :this ::state/state
                     ;; TODO: Verify that this is a valid long
                     ;; Annoying detail: Negatives are also legal, because this needs to map
                     ;; into the ulong space.
                     ;; More important TODO: Make sure I'm working within that range.
                     ;; And that bigint isn't killing performance.
                     :short-nonce integer?
                     :safe-nonce ::shared/safe-nonce)
        :ret ::state/state)
(defn build-actual-packet
  [{log-state ::log/state
    :as this}
   short-term-nonce
   safe-nonce]
  (let [{raw-hello ::template
         log-state ::log/state} (build-raw this short-term-nonce safe-nonce)
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
    ;; This is what's going on around line 289 in
    ;; curvecpclient.c
    ;; FIXME: Needs unit test
    [n-remaining]
    (let [n (- (count hello-wait-time) n-remaining)
          timeout (nth hello-wait-time n)]
      ;; This matches up with line 289
      (+ timeout (crypto/random-mod timeout)))))

(declare do-polling-loop)

(s/fdef possibly-recurse
        :args (s/cat :this ::state/state
                     :cookie-waiter ::state/cookie-waiter
                     :raw-packet ::specs/network-packet)
        :fn (s/or :recursion (s/fspec :args nil?
                                      :ret ::log/state)
                  :giving-up ::log/state))
(defn possibly-recurse
  "Try the next server (if any)"
  [{:keys [::log/logger
           ::state/server-ips]
    log-state ::log/state
    :as this}
   cookie-waiter
   raw-packet]
  (let [remaining-ips (next server-ips)
        log-state (log/flush-logs! logger (log/warn log-state
                                                    ::possibly-recurse
                                                    "Sending HELLO failed. Will try the next (if any) in the list"
                                                    {::state/server-ips remaining-ips}))]
    (if remaining-ips
      (let [timeout-ns (pick-next-timeout (count remaining-ips))
            timeout-ms (util/nanos->millis timeout-ns)]
        ;; FIXME: Return a partial version of this function for the trampoline to call
        ;; That's easier said than done, because deferreds do not play nicely
        ;; with the call stack.
        (do-polling-loop
         (assoc this
                ::log-state log-state
                ::state/server-ips remaining-ips)
         raw-packet
         cookie-waiter
         (System/nanoTime)
         timeout-ms))
      (throw (ex-info "No IPs left. Giving up" this)))))

(s/fdef cookie-retrieved
        :args (s/cat :this ::state/state
                     :raw-packet ::specs/network-packet
                     :cookie-waiter ::state/cookie-waiter
                     :start-time ::specs/time
                     :timeout ::specs/time
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
   cookie-waiter
   start-time
   timeout]
  ;; Q: Refactor the filtering/error checking pieces into their own function?
  (let [now (System/nanoTime)
        {:keys [::specs/srvr-ip
                ::state/server-cookie]} server-security]
    ;; This really should be a log message. Time after time, it's shown up in STDOUT
    ;; as a marker when my logs disappear.
    ;; That isn't an endorsement of using the print.
    ;; It's probably more of a sign that maybe logs simply are not meant to be
    ;; accrued the way I'm trying.
    ;; Then again, logs are really for diagnosing production issues, not debugging
    ;; problems at dev time.
    ;; (By that same token: unexpected errors that show up in prod are more
    ;; likely to cause logs like this to just disappear)
    (println "hello/cookie-retrieved:\n"
             (dissoc this ::log/state)
             "\nTop-level keys:\n"
             (keys this)
             "\nServer"
             srvr-ip
             "\nCookie:\n"
             (if server-cookie
               (b-t/->string server-cookie)
               "missing"))
    (if-not server-cookie
      ;; This sort of decision-based orchestration seems difficult
      ;; to model under manifold.
      ;; I'd like to filter the logic out to something like a dfrd/chain,
      ;; but I'm not sure how to represent branches and failures.
      ;; The obvious approaches seem messy.
      (do
        ;; Move on the next server in the list
        (binding [*out* *err*]
          (println "hello/cookie-retrieved: Missing the server-cookie!!\nAmong:\n" server-security))
        (possibly-recurse (assoc this ::log/state (log/flush-logs! logger (log/info log-state
                                                                                    ::cookie-retrieved
                                                                                    "Moving on to next ip"
                                                                                    {::timeout timeout})))
                          cookie-waiter
                          raw-packet))
      (if network-packet
        (do
          (if (and server-security shared-secrets)
            (assoc this ::log/state (log/debug log-state
                                               ::cookie-retrieved
                                               "Got back a usable cookie"
                                               (dissoc this ::log/state)))
            (do
              (log/flush-logs! logger (log/error log-state
                                                 ::cookie-retrieved
                                                 "Got back a network-packet but missing something else"
                                                 {::state/cookie-response this}))
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
             cookie-waiter
             start-time
             remaining)
            (possibly-recurse (assoc this ::log/state (log/flush-logs! logger (log/info log-state
                                                                                        ::cookie-retrieved
                                                                                        "Moving on to next ip")))
                              cookie-waiter
                              raw-packet)))))))

(s/fdef do-polling-loop
        :args (s/cat :this ::state/state
                     :hello-packet ::shared/message
                     :cookie-waiter ::state/cookie-waiter
                     :start-time nat-int?
                     :timeout ::specs/milli-time
                     :ips ::state/server-ips)
        :ret ::state/state)
(defn do-polling-loop
  [{:keys [::log/logger
           ::specs/executor
           ::state/chan->server
           ::state/server-security]
    ips ::state/server-ips
    :as this}
   hello-packet cookie-waiter start-time timeout]
  ;; TODO: At least consider ways to rewrite this as
  ;; a dfrd/loop.
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
                        :message hello-packet
                        :port srvr-port}
                       timeout
                       ::state/sending-hello-timed-out)
        (dfrd/chain
         ;; Note that this is actually cookie/wait-for-cookie!
         #(cookie-waiter this timeout %)
         ;; It's very tempting to inject a filter like this, instead
         ;; of doing it inside cookie-retrieved, which is what happens
         ;; now.
         ;; TODO: Figure out a way to do so while retaining the granularity
         ;; of things like tracing and error handling that I currently have
         ;; in cookie-retrieved.
         ;; Note that doing this makes the idea behind dfrd/loop and
         ;; dfrd/recur at least plausible.
         ;; TODO: Verify that I can recur in the middle of a dfrd/chain.
         #_(fn [{log-state ::log/state
               :keys [::state/server-security]
               :as this}]
           (if server-security
             (let [{:keys [::specs/public-short ::state/server-cookie]} server-security]
               (if (and public-short server-cookie)
                 this
                 (throw (ex-info "Missing something that should have been added to server-security"
                                 {::state/server-security server-security}))))
             (throw (ex-info "Missing server-security"
                             {::available this}))))
         ;; Need details like the hello-packet and cookie-waiter for recursing
         #(cookie-retrieved % hello-packet cookie-waiter start-time timeout))
        (dfrd/catch (fn [ex]
                      ;; This seems to wind up acting as a success.
                      ;; The brittleness around this part of the entire chain has
                      ;; lost its charm.
                      ;; FIXME: Make this part robust.
                      (println "hello/do-polling-loop: wait-for-cookie! failed:" ex)
                      (assoc this
                             ;; FIXME: This is where actually using the log-state-atom would
                             ;; have been handy
                             ;; (so I wouldn't lose anything that led up to this point)
                             ::log/state #_(swap! log-state-atom #(log/flush-logs! logger %))
                             (log/flush-logs! logger
                                              (log/exception log-state
                                                             ex
                                                             ::do-polling-loop))))))))

(s/fdef poll-servers!
  :args (s/cat :this ::state/state
               :hello-packet ::shared/packet
               :send-timeout ::specs/time
               :cookie-waiter ::state/cookie-waiter)
        :ret ::servers-polled)
(defn poll-servers!
  "Send hello packet to a seq of server IPs associated with a single server name.

  Params:
      - this: Client state
      - send-timeout (milliseconds): How long do we wait for the send?
      - cookie-waiter: sets up a deferrable that does the waiting"
  ;; Ping a bunch of potential servers (listening on an appropriate port with the
  ;; appropriate public key) in a sequence until you get a response or a timeout.
  ;; The main point is to avoid waiting 20-ish minutes for initial TCP connections
  ;; to time out.
  [{:keys [::log/logger
           ::state/server-ips]
    log-state ::log/state
    :as this}
   hello-packet
   send-timeout cookie-waiter]
  (let [log-state (log/debug log-state
                             ::poll-servers!
                             "Putting hello(s) onto ->server channel"
                             {::hello-packet hello-packet
                              ::state/server-ips server-ips})]
    (do-polling-loop (assoc this
                            ::log/state log-state
                            ;; Q: Do we really want to max out at 8?
                            ;; 8 means over 46 seconds waiting for a response,
                            ;; but what if you want the ability to try 20?
                            ;; Or don't particularly care how long it takes to get a response?
                            ;; Stick with the reference implementation version for now.
                            ::state/server-ips (take max-server-attempts (cycle server-ips)))
                     hello-packet
                     cookie-waiter
                     (System/nanoTime)
                     (util/millis->nanos send-timeout))))

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
        ;; But definitely not the full state.
        ;; FIXME: Do that, in a different branch
        :ret (s/keys :req [::shared/packet-management]))
(defn do-build-packet
  "Puts plain-text hello packet into packet-management

  Note that, for all intents and purposes, this is really called
  for side-effects, even though it has trappings to make it look
  functional."
  ;; A major part of the way this is written revolves around
  ;; updating packet-management in place.
  ;; That seems like premature optimization here.
  ;; Though it seems as though it might make sense for
  ;; sending messages.
  ;; Then again, if the implementation isn't shared...can
  ;; it possibly be worth the trouble?
  [{:keys [::log/logger
           ::shared/packet-management]
    :as this}]
  ;; FIXME: Eliminate packet-management.
  ;; Be explicit about the actual parameters.
  ;; Return the new packet.
  ;; Honestly, split up the calls that configure all the things
  ;; like setting up the nonce that make this problematic
  (let [;; There's a good chance this updates my extension.
        ;; That doesn't get set into stone until/unless I
        ;; manage to handshake with a server
        {log-state ::log/state
         :as extension-initialized} (state/clientextension-init (select-keys this
                                                                             [::state/client-extension-lead-time
                                                                              ::log/logger
                                                                              ::msg-specs/recent
                                                                              ::shared/extension]))
        this (into this extension-initialized)
        _ (throw (RuntimeException. "Start back here"))
        ;; Getting rid of the globally shared packet may make sense.
        ;; But eliminating packet-nonce seems difficult, at best.
        {:keys [::shared/packet-nonce ::shared/packet]} packet-management
        short-term-nonce (state/update-client-short-term-nonce packet-nonce)
        safe-nonce-prefix (vec K/hello-nonce-prefix)
        nonce-suffix (byte-array 8)]
    ;; Q: Is it worth coming up with a more efficient way to build this?
    (b-t/uint64-pack! nonce-suffix 0 short-term-nonce)
    (let [safe-nonce (concat safe-nonce-prefix (vec nonce-suffix))
          log-state (log/info log-state
                              ::do-build-packet
                              "Packed short-term- into safe- -nonces"
                              {::short-term-nonce short-term-nonce
                               ::shared/safe-nonce safe-nonce})
          {:keys [::shared/packet]
           log-state ::log/state} (build-actual-packet (assoc this ::log/state log-state)
                                                        short-term-nonce
                                                        safe-nonce)
          log-state (log/info log-state
                              ::do-build-packet
                              "hello packet built. Returning/updating")]
      (-> this
          (update ::shared/packet-management
                  (fn [current]
                    (assoc current
                           ::shared/packet-nonce short-term-nonce
                           ::shared/packet (b-s/convert packet specs/byte-array-type))))
          (assoc ::log/state (log/flush-logs! logger log-state))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef set-up-server-polling!
        :args (s/cat :this ::state/state
                     :wait-for-cookie! ::state/cookie-waiter
                     ;; TODO: Spec this out
                     :build-inner-vouch any?
                     :servers-polled any?)
        :ret ::servers-polled)
(defn set-up-server-polling!
  "Start polling the server(s) with HELLO Packets"
  [{:keys [::log/logger]
    :as this}
   ;; TODO: Either use this or eliminate it.
   log-state-atom
   wait-for-cookie!]
  (println "hello: polling triggered")
  (let [this (do-build-packet this)
        hello-packet nil]
    ;; Q: Is a quarter second a reasonable amount of time to
    ;; wait for the send?
    (poll-servers! this hello-packet 250 wait-for-cookie!)))
