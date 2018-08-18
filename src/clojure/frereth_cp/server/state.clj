(ns frereth-cp.server.state
  "Managing CurveCP server state"
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.server.helpers :as helpers]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log2]
             [specs :as shared-specs]]
            [manifold.stream :as strm]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

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
(s/def ::client-security (s/keys :opt [::shared-specs/public-long
                                       ::shared-specs/public-short
                                       ::server-short-sk]))

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
;; FIXME: Revisit that reason and decide whether it's still
;; valid.
(s/def ::chan #(= % ::chan))
;; These definitions seem dubious.
;; Originally, I expected them to be core.async channels.
;; They should probably be manifold streams, in which
;; case read-chan seems like it should be a source?
;; and write-chan seems like it should be a sink?
(s/def ::client-read-chan (s/map-of ::chan strm/sourceable?))
(s/def ::client-write-chan (s/map-of ::chan strm/sinkable?))

;;; Note that this has really changed drastically.
;;; These are now really side-effecting functions
;;; that accept byte-arrays to pass back and forth.
;;; But I haven't had a chance to even start refactoring
;;; the server side of this.
;;; Right now, I'm still hip-deep in the client side.
;;; I'm very hopeful that I'll be able to refactor that
;;; implementation to avoid duplication.
;; OK, now life starts getting interesting.
;; What, exactly, do we need to do here?
(s/def ::child-id int?)
(s/def ::read<-child strm/sourceable?)
(s/def ::write->child strm/sinkable?)
(s/def ::child-interaction (s/keys :req [::child-id
                                         ::read<-child
                                         ::write->child]))

;; These are defined both here and client.state.
;; FIXME: Move them into shared
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-short<->server-long
                                      ;; Q: Do we want to store the other two?
                                      ::client-short<->server-short
                                      ::client-long<->server-long]))

(s/def ::message-len int?)
(s/def ::received-nonce int?)
(s/def ::client-state (s/keys :req [::child-interaction
                                    ;; The names for the next 2 seem silly, at best
                                    ;; ::host and ::port seem like better options
                                    ;; But this matches the reference implementation
                                    ;; and should reduce confusion
                                    ;; Plus the alternatives I'd prefer seem to just
                                    ;; be begging for issues with collisions
                                    ::client-ip
                                    ::client-port
                                    ::client-security
                                    ::shared/extension
                                    ;; TODO: Needs spec
                                    ::message
                                    ::message-len
                                    ::received-nonce
                                    ;; TODO: Needs spec
                                    ::sent-nonce
                                    ::shared-secrets]))
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

;; TODO: Make this go away. Switch to the version in message.specs
(s/def ::child-spawner! (s/fspec :args (s/cat)
                                 :ret ::child-interaction))

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
                               ::log2/logger
                               ::log2/state
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
                                    ::child-spawner!
                                    ;; Checking the spec on this means calling
                                    ;; it. Which really hoses the entire system
                                    ;; if it happens more than once.
                                    ;; OTOH, commenting it out doesn't fix my problem
                                    ;; with the spec check just hanging
                                    ::event-loop-stopper!)
                         ;; This doesn't particularly belong here
                         ;; (Or, for that matter, make much sense
                         ;; as anything except a reference. And
                         ;; even that seems questionable)
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
;;; Public

(s/fdef alloc-client
        :args (s/cat)
        :ret ::client-state)
(defn alloc-client
  []
  (let [interact {::child-id -1}
        sec {::shared/long-pk (crypto/random-key)
             ::shared/short-pk (crypto/random-key)}]
    {::child-interaction interact
     ::client-security sec
     ::shared/extension (crypto/random-bytes! (byte-array 16))
     ::message (crypto/random-bytes! (byte-array K/message-len))
     ::message-len 0
     ::received-nonce 0
     ::sent-nonce (crypto/random-nonce)}))

(s/fdef alter-client-state
        :args (s/cat :state ::state
                     :altered-client ::client-state)
        :ret ::state)
(defn alter-client-state
  [state altered-client]
  ;; Skip incrementing the numactiveclients count.
  ;; We get that for free from the data structure
  (let [client-key (get-in altered-client [::client-security ::shared/short-pk])]
    (assoc-in state
              [::active-clients (vec client-key)]
              ;; Q: Worth surgically applying a delta?
              altered-client)))

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
      (assoc-in [::client-security ::short-pk] client-short-pk)
      (assoc-in [::client-security ::server-short-sk] server-short-sk)))

(s/fdef find-client
        :args (s/cat :state ::state
                     :client-short-key ::shared/public-key)
        :ret (s/nilable ::client-state))
(defn find-client
  [state client-short-key]
  (get-in state [::active-clients (vec client-short-key)]))

(defn hide-secrets!
  [this]
  (log/info "Hiding secrets")
  ;; This is almost the top of the server's for(;;)
  ;; Missing step: reset timeout
  ;; Missing step: copy :minute-key into :last-minute-key
  ;; (that's handled by key rotation. Don't need to bother
  ;; if we're "just" cleaning up on exit)
  (let [minute-key-array (get-in this [::cookie-cutter ::minute-key])]
    (assert minute-key-array)
    (crypto/random-bytes! minute-key-array))

  ;; Missing step: update cookie-cutter's next-minute
  ;; (that happens in handle-key-rotation)
  (when-let [client (this ::current-client)]
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
  (assoc-in this [::current-client ::shared-secrets] {::client-short<->server-long nil
                                                      ::client-short<->server-short nil
                                                      ::client-long<->server-long nil}))

(defn handle-key-rotation
  "Doing it this way means that state changes are only seen locally

  They really need to propagate back up to the System that owns the Component.

  It seems obvious that this state should go into an atom, or possibly an agent
  so other pieces can see it.

  But this is very similar to the kinds of state management issues that Om and
  Om next are trying to solve. So that approach might not be as obvious as it
  seems at first."
  [{:keys [::cookie-cutter]
    :as state}]
  (try
    (log/info "Checking whether it's time to rotate keys or not")
    (let [now (System/nanoTime)
          next-minute (::next-minute cookie-cutter)
          _ (log/debug "next-minute:" next-minute "out of" (keys state)
                     "with cookie-cutter" cookie-cutter)
          timeout (- next-minute now)]
      (log/info "Top of handle-key-rotation. Remaining timeout:" timeout)
      (if (<= timeout 0)
        (let [timeout (helpers/one-minute now)]
          (log/info "Saving key for previous minute")
          (try
            (b-t/byte-copy! (::last-minute-key cookie-cutter)
                               (::minute-key cookie-cutter))
            ;; Q: Why aren't we setting up the next minute-key here and now?
            (catch Exception ex
              (log/error "Key rotation failed:" ex "a" (class ex))))
          (log/warn "Saved key for previous minute. Hiding:")
          (assoc (hide-secrets! state)
                 ::timeout timeout))
        (assoc state ::timeout timeout)))
    (catch Exception ex
      (log/error "Rotation failed:" ex "\nStack trace:")
      (.printStackTrace ex)
      state)))

(defn randomized-cookie-cutter
  []
  {::minute-key (crypto/random-key)
   ::last-minute-key (crypto/random-key)
   ;; Q: Should this be ::timeout?
   ;; A: No. There's definitely a distinction.
   ;; Q: Alright, then. What is the difference?
   ::next-minute(+ (System/nanoTime)
                   (helpers/one-minute))})
