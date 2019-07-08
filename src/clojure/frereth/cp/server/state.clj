(ns frereth.cp.server.state
  "Managing CurveCP server state"
  (:require [clojure.spec.alpha :as s]
            [frereth.cp.message.specs :as msg-specs]
            [frereth.cp.server.helpers :as helpers]
            [frereth.cp.shared :as shared]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [child :as child]
             [constants :as K]
             [crypto :as crypto]
             [specs :as shared-specs]
             [serialization :as serial]
             [templates :as templates]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold.stream :as strm])
  (:import [io.netty.buffer ByteBuf]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;; For maintaining a secret symmetric pair of encryption
;; keys for the cookies.
(s/def ::last-minute-key ::shared/symmetric-key)
(s/def ::minute-key ::shared/symmetric-key)
(s/def ::next-minute integer?)
(s/def ::cookie-cutter (s/keys :req [::next-minute
                                     ::minute-key
                                     ::last-minute-key]))

(s/def ::server-short-sk ::shared-specs/crypto-key)

;; Q: Do I really want to store the client's long-term PK?
;; A: Reference implementation has was looks like TODO items
;; about things like caching, policy management, and validating.
;; So almost definitely.
;; Although: there's also the perfectly legitimate use-case of
;; 1 client opening multiple connections.
;; Honestly, that's something to decide at the individual child
;; level.
;; Which means sending the long-pk to said child.
(s/def ::client-security (s/keys :opt [::shared-specs/long-pk
                                       ::shared-specs/short-pk]
                                 :req [::server-short-sk]))

;; Yes, this seems silly. And will probably cause plenty of
;; trouble/confusion. I'm not sure about alternatives for specing
;; out client-read-chan/client-write chan.
;; Actually, this demonstrates a poor design decision.
;; Different channels used for different purposes should
;; have different keys. Which is the purpose behind having
;; ::client-read-chan distinct from ::client-write-chan.
;; However:
;; I remember thinking I had a good reason for the indirection
;; that leaves each pointing to another map.
;; (Most likely bet: I thought they would be more involved).
;; FIXME: Revisit that reason and decide whether it's still
;; valid.
(s/def ::chan #(= % ::chan))
;; Message bytes from the client arrive here
(s/def ::client-read-chan (s/map-of ::chan strm/sourceable?))
;; Send message bytes to the client
(s/def ::client-write-chan (s/map-of ::chan strm/sinkable?))

;; These are defined both here and client.state.
;; FIXME: Move them into shared
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-short<->server-long
                                      ;; Q: Do we want to store the other two?
                                      ::client-short<->server-short
                                      ::client-long<->server-long]))

(s/def ::received-nonce int?)

(s/def ::initial-client-state (s/keys :req [;; The names for the next 2 seem silly, at best
                                            ;; ::host and ::port seem like better options
                                            ;; But this matches the reference implementation
                                            ;; and will hopefully reduce confusion.
                                            ;; Plus the alternatives I'd prefer seem to just
                                            ;; be begging for issues with collisions.
                                            ::client-ip
                                            ::client-port
                                            ::client-security
                                            ::shared/extension
                                            ::received-nonce]))

(s/def ::sent-nonce int?)

(s/def ::client-state (s/merge ::initial-client-state
                               (s/keys :req [::sent-nonce
                                             ::shared-secrets]
                                       :opt [::child/state])))
(s/def ::current-client ::client-state)

;; We're using the client's short-term public key as the key into the
;; active-clients map.
;; A byte-array is a terrible thing to use for a hash key. So translate
;; it into a vector.
(s/def ::public-key-vec (s/and vector?
                               #(= (count %) shared-specs/client-key-length)
                               (fn [bs]
                                 (every? #(instance? Byte %) bs))))
(s/def ::active-clients (s/map-of ::public-key-vec ::client-state))
(s/def ::max-active-clients nat-int?)

(s/def ::event-loop-stopper! (s/fspec :args (s/cat)
                                     :ret any?))

;; This is almost copy/pasted straight from ::server/pre-state.
;; But that's really about putting the pieces together in
;; order to build this, which is what gets shared
;; everywhere.
;; The dichotomy illustrates a big part of my current (2018-MAR-30)
;; conundrum:
;; I think I want to be explicit about what fields each function
;; really and truly needs.
;; But the calls are really a very tightly coupled chain that I
;; refactored from a single gigantic C function that takes advantage
;; of a bunch of globals.
;; The functions at the bottom of the call stack uses most of this
;; state. Which means that everything that leads up to them
;; also requires it. The differences are minor enough that it
;; it doesn't seem worth the book-keeping effort to try to
;; keep them sorted out.
(let [fields-safe-to-validate [::active-clients
                               ::client-read-chan
                               ::client-write-chan
                               ::max-active-clients
                               ::weald/logger
                               ::weald/state
                               ::msg-specs/message-loop-name-base
                               ::shared/extension
                               ;; Q: Does this make any sense here?
                               ;; A: Definitely not.
                               ;; Especially since, given the current
                               ;; implementation, it's also a part of
                               ;; ::shared/my-keys
                               ;; FIXME: Revisit this decision if/when
                               ;; that stops being the case.
                               #_::shared/keydir

                               ;; Worth calling out for the compare/
                               ;; contrast
                               ;; These fields are optional in
                               ;; server/handle
                               ::cookie-cutter
                               ::shared/my-keys]]
  ;; This is really just for documentation.
  ;; If you try to validate this, it will make you very sad.
  (s/def ::state (s/keys :req (conj fields-safe-to-validate
                                    ::msg-specs/child-spawner!
                                    ;; Checking the spec on this means calling
                                    ;; it. Which really hoses the entire system
                                    ;; if it happens more than once.
                                    ;; OTOH, commenting it out doesn't fix my problem
                                    ;; with the spec check just hanging
                                    ::event-loop-stopper!)
                         ;; This doesn't particularly belong here
                         :opt [::current-client]))
  ;; Honestly, this is really just for documentation.
  ;; If you want to validate a ::state, be sure to dissoc
  ;; the unsafe function keys (because every namespaced key in
  ;; the map that has a spec will be checked, whether it's listed
  ;; as a key in here or not).
  ;; Also note: this isn't legit. Macrology bites us here, because
  ;; fields-safe-to-validate doesn't get spliced into the list, but
  ;; I can't just use it directly, since a Symbol isn't an ISeq.
  ;; TODO: ask about this approach on the mailing list.
  (s/def ::checkable-state (s/keys :req [fields-safe-to-validate])))

;; This is misleading. Basically, it can update pretty much
;; any state component. They're going to get merged using into.
;; TODO: Need to come up with a reasonable way to spec this
(s/def ::delta ::state)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal Implementation
;;;; Q: Really? Nothing?
;;;; A: Yep. It's tough to believe.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef configure-shared-secrets
        :args (s/cat :client ::client-state
                     :client-short-pk ::shared/public-key
                     :server-short-sk ::shared/secret-key)
        :ret ::client-state)
(defn configure-shared-secrets
  "Return altered client state that reflects new shared key
  This almost corresponds to lines 369-371 in reference implementation,
  but does *not* have side-effects!  <----"
  [client
   client-short-pk
   server-short-sk]
  (when-not (and client-short-pk server-short-sk)
    (throw (ex-info "Missing key"
                    {::server-short-sk server-short-sk
                     ::client-short-pk client-short-pk})))
  (-> client
      (assoc-in [::shared-secrets ::client-short<->server-short] (crypto/box-prepare client-short-pk server-short-sk))
      ;; Q: Is there a client-security entry already present? Could we just overwrite
      ;; the map directly rather than calling assoc-in twice?
      ;; Q: Would the risk be worth the extra clarity?
      (assoc-in [::client-security ::shared/short-pk] client-short-pk)
      (assoc-in [::client-security ::server-short-sk] server-short-sk)))

(s/fdef new-client
  :args (s/cat :packet ::shared/network-packet
               :cookie ::templates/srvr-cookie
               :initiate ::K/initiate-packet-spec)
  :ret ::initial-client-state)
(defn new-client
  [{:keys [:host :port]
    :as packet}
   {:keys [::templates/clnt-short-pk
           ::templates/srvr-short-sk]
    :as cookie}
   {:keys [::K/clnt-xtn]
    :as initiate}]
  (let [raw-rcvd-nonce (::K/outer-i-nonce initiate)
        received-nonce-array (bytes raw-rcvd-nonce)
        received-nonce (b-t/uint64-unpack received-nonce-array)]
    {::client-ip host
     ::client-port port
     ::client-security {::shared/short-pk (bytes clnt-short-pk)
                        ::server-short-sk (bytes srvr-short-sk)}
     ::shared/extension clnt-xtn
     ::received-nonce received-nonce}))

(s/fdef alter-client-state
  :args (s/cat :state ::state
               :altered-client ::client-state)
  :ret ::delta)
(defn alter-client-state
  [state altered-client]
  ;; Skip incrementing the numactiveclients count.
  ;; We get that for free from the data structure
  (let [client-key (get-in altered-client [::client-security ::shared/short-pk])]
    (assoc (::active-clients state)
           (vec client-key)
           altered-client)))

(s/fdef find-client
        :args (s/cat :state ::state
                     :client-short-key ::shared/public-key)
        :ret (s/nilable ::client-state))
(defn find-client
  [state client-short-key]
  (get-in state [::active-clients (vec client-short-key)]))

(s/fdef hide-secrets!
  :args (s/cat :this ::state)
  :ret ::state)
(defn hide-secrets!
  "Scrambles sensitive byte-arrays in place"
  [{log-state-atom ::weald/state-atom
    :as this}]
  (log/atomically! log-state-atom
                   log/info
                   ::hide-secrets!
                   "Top")
  ;; This is almost the top of the server's for(;;)
  ;; Missing step: reset timeout
  ;; Missing step: copy :minute-key into :last-minute-key
  ;; (that's handled by key rotation. Don't need to bother
  ;; if we're "just" cleaning up on exit)
  (let [minute-key-array (get-in this [::cookie-cutter ::minute-key])]
    ;; Q: Is assert really appropriate here?
    ;; A: Honestly, yes. If we get here without one, the system's hosed.
    ;; It should probably be a check that also happens in production
    ;; mode. Maybe the way it gets produced changes in a way that could
    ;; fail there but still pass at dev time.
    ;; TODO: Worry about that later.
    (assert minute-key-array)
    ;; Overwriting the bytes in place feels wrong, but it's also the
    ;; entire point. We do not want references to be able to leak.
    (crypto/random-bytes! minute-key-array))

    ;; Missing step: update cookie-cutter's next-minute
    ;; (that happens in handle-key-rotation)

  (when-let [client (::current-client this)]
    (crypto/random-bytes! (get-in client [::client-security ::shared/short-pk])))
  ;; The shared secrets are all private, so I really can't touch them
  ;; Q: What *is* the best approach to clearing them then?
  ;; For now, just explicitly set my versions to nil once we get past these side-effects
  ;; (i.e. at the bottom)
  #_(crypto/random-bytes (-> this ::current-client ::shared-secrets :what?))

  (when-let [^com.iwebpp.crypto.TweetNaclFast$Box$KeyPair short-term-keys (get-in this [::shared/my-keys ::shared/short-pair])]
    (crypto/random-bytes! (.getPublicKey short-term-keys))
    (crypto/random-bytes! (.getSecretKey short-term-keys)))
  ;; Clear the shared secrets in the current client
  ;; Maintaning these anywhere I don't need them seems like an odd choice.
  ;; Actually, keeping them in 2 different places seems odd.
  ;; Q: What's the point to current-client at all?
  ;; A: This is really a "convenience" that I cobbled into place.
  ;; DJB did not have such an idea. When a client sends a message,
  ;; he finds the current client by index and uses that index.
  ;; TODO: Something similar.
  ;; I *do* want to lock most functionality down to a single client to
  ;; reduce the possibility of data about the others leaking over.
  ;; But storing both together is a mistake.
  ;; Especially since this approach makes the return value matter when
  ;; this function should be all about the side-effects.
  (assoc-in this [::current-client ::shared-secrets] {::client-short<->server-long nil
                                                      ::client-short<->server-short nil
                                                      ::client-long<->server-long nil}))

(s/fdef handle-key-rotation
  :args (s/cat :state ::state)
  :ret ::delta)
(defn handle-key-rotation
  "Doing it this way means that state changes are only seen locally

  They really need to propagate back up to the System that owns the Component.

  It seems obvious that this state should go into an atom, or possibly an agent
  so other pieces can see it.

  But this is very similar to the kinds of state management issues that Om and
  Om next are trying to solve. So that approach might not be as obvious as it
  seems at first."
  [{:keys [::cookie-cutter]
    log-state ::weald/state
    :as state}]
  (try
    (let [log-state (log/info log-state
                              ::handle-key-rotation
                              "Checking whether it's time to rotate keys or not")
          now (System/nanoTime)
          next-minute (::next-minute cookie-cutter)
          timeout (- next-minute now)
          log-state (log/debug log-state
                               ::handle-key-rotation
                               ""
                               {::next-minute next-minute
                                ::state-keys (keys state)
                                ::cookie-cutter cookie-cutter
                                ::timeout timeout})]
      (if (<= timeout 0)
        (let [timeout (helpers/one-minute now)
              log-state (log/info log-state
                                  ::handle-key-rotation
                                  "Saving key for previous minute")
              log-state
              (try
                (b-t/byte-copy! (::last-minute-key cookie-cutter)
                                (::minute-key cookie-cutter))
                ;; Q: Why aren't we setting up the next minute-key here and now?
                (catch Exception ex
                  (log/exception log-state
                                 ex
                                 "Key rotation failed")))
              log-state (log/warn log-state
                                  ::handle-key-rotation
                                  "Saved key for previous minute. Hiding")]
          (assoc (hide-secrets! (assoc state ::weald/state log-state))
                 ::timeout timeout))
        (assoc state
               ::timeout timeout
               ::weald/state log-state)))
    (catch Exception ex
      ;; Unfortunately, this will lose logs that happened before the
      ;; exception.
      ;; Q: Are those worth adding a log-state-atom?
      ;; A: Not until this is a problem.
      (assoc state
             ::weald/state (log/exception log-state
                                          ex
                                          ::handle-key-rotation)))))

(defn randomized-cookie-cutter
  []
  {::minute-key (crypto/random-key)
   ::last-minute-key (crypto/random-key)
   ;; Q: Should this be ::timeout?
   ;; A: No. There's definitely a distinction.
   ;; Q: Alright, then. What is the difference?
   ::next-minute(+ (System/nanoTime)
                   (helpers/one-minute))})
