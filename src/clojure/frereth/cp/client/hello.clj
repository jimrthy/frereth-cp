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
             [serialization :as serial]
             [specs :as specs]]
            [frereth-cp.util :as util]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;; Q: Is there a better/cleaner way to set up these specs?

;; For build-raw-template-values
(s/def ::raw-template (s/keys :req [::shared/extension
                                    ::shared/my-keys
                                    ::state/server-extension
                                    ::state/server-security
                                    ::state/shared-secrets
                                    ::weald/state]))

;; Pieces needed for build-actual-packet
(s/def ::packet-builders (s/merge ::raw-template
                                  (s/keys :req [::shared/packet-nonce])))

;; These are the top-level keys that are passed into do-build-packet.
(s/def ::top-level-packet-builders (s/merge ::state/extension-initializers
                                            ::packet-builders))

(s/def ::servers-polled (s/or :possibly-succeeded dfrd/deferrable?
                              :failed ::state/state))

;; Signal to continue waiting on the current server.
;; There was something wrong with the incoming cookie, but the server
;; still has time to make things right
(s/def ::continue boolean?)
;; Signal to try again with the next server
(s/def ::recurse boolean?)
;; How much time is left on the current poll
(s/def remaining number?)
(s/def ::skipping-state (s/merge ::state/state
                                 (s/keys :opt [::continue
                                               ::recurse
                                               ::remaining])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Globals

(set! *warn-on-reflection* true)

(def max-server-attempts 8)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef send-succeeded!
        ;; Yes, the logger parameter is redundant
        :args (s/cat :logger ::weald/logger
                     :this ::state/state)
        :ret any?)
(defn send-succeeded!
  [logger this]
  (as-> (::weald/state this) x
    (log/info x
              ::send-succeeded!
              "Polling complete. Child should be able to trigger Initiate/Vouch"
              {::result (dissoc this ::weald/state)})
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
  [{:keys [::weald/logger
           ::weald/state]
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


(s/fdef build-raw-template-values
        :args (s/cat :this ::raw-template
                      :short-term-nonce any?
                      :internal-nonce-suffix (s/and sequential?
                                                    #(= (count %) ::specs/client-nonce-suffix-length)))
        :ret (s/keys :req [::K/hello-spec ::weald/state]))
(defn build-raw-template-values
  "Set up the values for injecting into the template"
  [{:keys [::shared/extension
           ::shared/my-keys
           ::state/server-extension
           ::state/server-security
           ::state/shared-secrets]
    log-state ::weald/state
    :as this}
   short-term-nonce
   internal-nonce-suffix]
  {:pre [extension
         my-keys
         server-security]}
  (let [log-state
        (if server-security
          (log/debug log-state
                     ::build-raw
                     "server-security" server-security)
          (log/warn log-state
                    ::build-raw
                    "Missing server-security"
                    {::keys (keys this)
                     ::state/state this}))
        my-short<->their-long (::state/client-short<->server-long shared-secrets)
        _ (assert my-short<->their-long (str "Missing client-short<->server-long among "
                                             (keys shared-secrets)
                                             " in "
                                             shared-secrets))
        safe-nonce-prefix (vec K/hello-nonce-prefix)
        safe-nonce (-> safe-nonce-prefix
                       (into internal-nonce-suffix)
                       byte-array)
        ;; Note that this inserts the 16-byte prefix for me
        boxed (crypto/box-after my-short<->their-long
                                K/all-zeros (- K/hello-crypto-box-length K/box-zero-bytes)
                                safe-nonce)
        ^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
        log-state (log/info log-state
                            ::build-raw-template-values
                            ""
                            {::crypto-box (b-t/->string boxed)
                             ::shared/safe-nonce (b-t/->string safe-nonce)
                             ::my-short-pk (-> my-short-pair
                                               .getPublicKey
                                               b-t/->string)
                             ::server-long-pk (b-t/->string (::specs/public-long server-security))
                             ::state/client-short<->server-long (b-t/->string my-short<->their-long)})
        nonce-suffix (byte-array (drop specs/client-nonce-prefix-length
                                       safe-nonce))]
    {::template {::K/hello-prefix nil  ; This is a constant, so there's no associated value
                 ::K/srvr-xtn server-extension
                 ::K/clnt-xtn extension
                 ::K/clnt-short-pk (.getPublicKey my-short-pair)
                 ::K/zeros nil
                 ::K/client-nonce-suffix nonce-suffix
                 ::K/crypto-box boxed}
     ::weald/state log-state}))

(s/fdef build-actual-packet
        :args (s/cat :this ::packet-builders
                     ;; TODO: Verify that this is a valid long
                     ;; Annoying detail: Negatives are also legal, because this needs to map
                     ;; into the ulong space.
                     ;; More important TODO: Make sure I'm working within that range.
                     ;; And that bigint isn't killing performance.
                     :short-nonce integer?
                     :safe-nonce ::shared/safe-nonce)
        :ret ::state/state)
(defn build-actual-packet
  [{log-state ::weald/state
    :as this}
   short-term-nonce
   safe-nonce]
  (let [{raw-hello ::template
         log-state ::weald/state} (build-raw-template-values this
                                                             short-term-nonce
                                                             safe-nonce)
        log-state (log/info log-state
                            ::build-actual-packet
                            "Building Hello"
                            {::raw raw-hello})
        ;; This is for the sake of tricksy exception handling
        composition-succeeded? (promise)]
    (try
      (let [^ByteBuf result (serial/compose K/hello-packet-dscr raw-hello)]
        (deliver composition-succeeded? true)
        (let [n (.readableBytes result)]
          (when (not= K/hello-packet-length n)
            (throw (ex-info "Built a bad HELLO"
                            {::expected-length K/hello-packet-length
                             ::actual n}))))
        {::shared/packet result
         ::weald/state log-state})
      (catch Throwable ex
        (if (realized? composition-succeeded?)
          (throw ex)
          {::weald/state (log/exception log-state ex ::build-actual-packet
                                        "Failed to compose HELLO")})))))

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
                                      :ret ::weald/state)
                  :giving-up ::weald/state))
(defn possibly-recurse
  "Try the next server (if any)"
  [{:keys [::weald/logger
           ::state/server-ips]
    log-state ::weald/state
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
         cookie-waiter
         (System/nanoTime)
         timeout-ms))
      (throw (ex-info "No IPs left. Giving up" this)))))

(s/fdef cookie-validation
  :args (s/cat :this ::state/state
               :timeout number?)
  :ret ::skipping-state)
(defn cookie-validation
  "Check whether the cookie matches our expectations"
  [{log-state ::weald/state
    :keys [::shared/network-packet
           ::state/server-security
           ::state/shared-secrets]
    :as this}
   start-time
   timeout]
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
    (println (str ::cookie-validation
                  ":\n"
                  (dissoc this ::weald/state)
                  "\nTop-level keys:\n"
                  (keys this)
                  "\nServer: "
                  srvr-ip
                  "\nCookie:\n"
                  (if server-cookie
                    (b-t/->string server-cookie)
                    "missing")))
    (if server-cookie
      (if network-packet
        (do
          (if (and server-security shared-secrets)
            (assoc this ::weald/state (log/debug log-state
                                                 ::cookie-retrieved
                                                 "Got back a usable cookie"
                                                 (dissoc this ::weald/state)))
            (let [logger (::weald/logger this)]
              (log/flush-logs! logger (log/error log-state
                                                 ::cookie-retrieved
                                                 "Got back a network-packet but missing something else"
                                                 {::state/cookie-response (dissoc this ::weald/state)}))
              (throw (ex-info "Network-packet missing either security or shared-secrets"
                              {::problem this})))))
        (let [elapsed (- now start-time)
              remaining (- timeout elapsed)
              log-state (log/info log-state
                                  ::cookie-retrieved
                                  "Discarding garbage cookie")]
          (if (< 0 remaining)
            (assoc this
                   ::continue true
                   ::remaining remaining
                   ::weald/state (log/info log-state
                                           ::cookie-validation
                                           "Still waiting on server"
                                           {::shared/host srvr-ip
                                            ::millis-remaining remaining}))
            (assoc this
                   ::recurse true
                   ::weald/state (log/info log-state
                                           ::cookie-validation
                                           "Out of time. Next server")))))
      (do
        ;; Move on the next server in the list
        (binding [*out* *err*]
          (println "hello/cookie-retrieved: Missing the server-cookie!!\nAmong:\n" server-security))
        (assoc this
               ::weald/state (log/info log-state
                                       ::cookie-validation
                                       "Moving on to next ip"
                                       {::timeout timeout})
               ::recurse true)))))

(s/fdef cookie-retrieved
        :args (s/cat :this ::skipping-state
                     :raw-packet ::specs/network-packet
                     :cookie-waiter ::state/cookie-waiter
                     :start-time ::specs/time
                     :timeout ::specs/time
                     :ips ::specs/srvr-ips)
        :ret ::state/state)
(defn cookie-retrieved
  [{log-state ::weald/state
    :keys [::continue
           ::recurse
           ::weald/logger
           ::state/server-security]
    :as this}
   raw-packet
   cookie-waiter
   start-time
   timeout]
  (let [this (assoc this ::weald/state (log/flush-logs! logger log-state))]
    (if-not recurse
      (if-not continue
        ;; It doesn't look like there's actually anything to do here
        this
        (let [remaining (::remaining this)]
          ;; Q: Use trampoline instead?
          ;; A: That would get into all sorts of weirdness, because this
          ;; is nested inside a deferred handler.
          ;; Famous Last Words:
          ;; The call stack on this should never get all that deep.
          (do-polling-loop
           (dissoc this ::continue ::remaining)
           raw-packet
           cookie-waiter
           start-time
           remaining)))
      (possibly-recurse (dissoc this ::recurse)
                        cookie-waiter
                        raw-packet))))

(s/fdef do-build-packet
  :args (s/cat :this ::top-level-packet-builders)
  ;; However:
  ;; It absolutely should not return much more than
  ;; the bytes of the packet.
  ;; And probably things like the nonce generator
  ;; state.
  ;; Probably the short-term key.
  ;; But definitely not the full state.
  ;; FIXME: Do that, in a different branch
  :ret (s/keys :req [::weald/state]
               :opt [::shared/packet-nonce
                     ::shared/packet]))
(defn do-build-packet
  "Builds a plain-text hello packet"
  [{:keys [::shared/packet-nonce]
    :as this}]
  ;; Be explicit about the actual parameters.
  ;; Return the new packet.
  ;; Honestly, split up the calls that configure all the things
  ;; like setting up the nonce that make this problematic
  (let [;; There's a good chance this updates my extension.
        ;; This doesn't get set into stone until after I've
        ;; managed to contact a server.
        ;; However: the nonce needs to be different for
        ;; each server.
        ;; So building an initial packet up-front like this
        ;; to share among all of them simply does not work.
        {:keys [::shared/extension
                ::state/client-extension-load-time]
         log-state ::weald/state
         :as extension-initialized} (state/clientextension-init (select-keys this
                                                                             [::state/client-extension-load-time
                                                                              ::weald/logger
                                                                              ::weald/state
                                                                              ::msg-specs/recent
                                                                              ::shared/extension]))
        ;; It's tempting to protect against the error that the nonce space has been exhausted.
        ;; That's basically an almost-fatal error that should trigger a reconnect.
        ;; But that decision needs to be made at a higher level.
        ;; Though we probably don't have to worry about it here.
        ;; This should also happen at the top of reading a message from the child
        short-term-nonce (state/update-client-short-term-nonce packet-nonce)
        nonce-suffix (byte-array 8)]
    (b-t/uint64-pack! nonce-suffix 0 short-term-nonce)
    (let [log-state (log/info log-state
                              ::do-build-packet
                              "Packed short-term- into safe- -nonces"
                              {::short-term-nonce short-term-nonce
                               ::specs/client-nonce-suffix nonce-suffix})
          packet-builders (select-keys this [::weald/state
                                             ::state/server-extension
                                             ::state/server-security
                                             ::shared/my-keys
                                             ::state/server-security
                                             ::state/shared-secrets])
          packet-builders (assoc packet-builders ::shared/extension extension)
          {:keys [::shared/packet]
           log-state ::weald/state} (build-actual-packet packet-builders
                                                         short-term-nonce
                                                         nonce-suffix)
          log-state (log/info log-state
                              ::do-build-packet
                              "hello packet possibly built. Returning/updating")]
      (assoc extension-initialized
             ::weald/state log-state
             ::shared/packet-nonce short-term-nonce
             ::shared/packet (if packet
                               (b-s/convert packet specs/byte-array-type)
                               nil)))))

(s/fdef do-polling-loop
        :args (s/cat :this ::state/state
                     :cookie-waiter ::state/cookie-waiter
                     :start-time nat-int?
                     :timeout ::specs/milli-time
                     :ips ::state/server-ips)
        :ret ::state/state)

(defn do-polling-loop
  [{:keys [::weald/logger
           ::specs/executor
           ::state/chan->server
           ::state/server-security]
    ips ::state/server-ips
    :as this}
   cookie-waiter start-time timeout]
  ;; TODO: At least consider ways to rewrite this as
  ;; a dfrd/loop.
  (let [;; Have to adjust nonce for each server.
        {hello-packet ::shared/packet
         log-state ::weald/state
         :as delta} (do-build-packet (select-keys this [::state/client-extension-load-time
                                                        ::shared/extension
                                                        ::weald/logger
                                                        ::shared/my-keys
                                                        ::shared/packet-nonce
                                                        ::msg-specs/recent
                                                        ::state/server-extension
                                                        ::state/server-security
                                                        ::state/shared-secrets
                                                        ::weald/state]))
        this (into this (dissoc delta ::shared/packet))
        log-state (log/info log-state
                            ::do-polling-loop
                            "After extending this with delta keys"
                            {::changed-keys (keys delta)
                             ::shared/extension (::shared/extension this)})
        srvr-ip (first ips)
        log-state (log/info (::weald/state this)
                            ::do-polling-loop
                            "Polling server"
                            {::specs/srvr-ip srvr-ip})
        {:keys [::specs/srvr-port]} server-security
        this (-> this
                 (assoc ::weald/state log-state)
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
         #(cookie-validation % start-time timeout)
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
                             ::weald/state #_(swap! log-state-atom #(log/flush-logs! logger %))
                             (log/flush-logs! logger
                                              (log/exception log-state
                                                             ex
                                                             ::do-polling-loop))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef set-up-server-polling!
        :args (s/cat :this ::state/state
                     :wait-for-cookie! ::state/cookie-waiter)
        :ret ::servers-polled)
(defn set-up-server-polling!
  "Start polling the server(s) with HELLO Packets"
  [{log-state ::weald/state
    :keys [::state/server-ips]
    :as this}
   wait-for-cookie!]
  (let [log-state (log/info log-state
                            ::set-up-server-polling!
                            "hello: polling triggered")
        ;; Q: How was this number chosen?
        ;; A: Well, it came from line 274 of curvecpclient.c
        nonce (crypto/random-mod K/two-pow-48)
        this (assoc this ::shared/packet-nonce nonce)]
    ;; Q: Is a quarter second a reasonable amount of time to
    ;; wait for the [initial] send?
    (do-polling-loop (assoc this
                            ::weald/state log-state
                            ;; Q: Do we really want to max out at 8?
                            ;; 8 means over 46 seconds waiting for a response,
                            ;; but what if you want the ability to try 20?
                            ;; Or don't particularly care how long it takes to get a response?
                            ;; Stick with the reference implementation version for now.
                            ::state/server-ips (take max-server-attempts (cycle server-ips)))
                     wait-for-cookie!
                     (System/nanoTime)
                     (util/millis->nanos 250))))
