(ns frereth-cp.server.state
  "Managing CurveCP server state"
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.server.helpers :as helpers]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]))

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

(s/def ::server-short-sk ::crypto/crypto-key)

;; Q: Do I really want to store the client's long-term PK?
;; A: Reference implementation has was looks like TODO items
;; about things like caching, policy management, and validating.
;; So almost definitely.
(s/def ::client-security (s/keys :opt [::shared/long-pk
                                       ::shared/short-pk
                                       ::server-short-sk]))

;; This seems like something that should basically be defined in
;; shared.
;; Or, at least, ::chan ought to.
;; Except that it's a...what?
;; (it seems like it ought to be an async/chan, but it might really
;; be a manifold/stream
(s/def ::client-read-chan (s/keys :req [::chan]))
(s/def ::client-write-chan (s/keys :req [::chan]))

;; OK, now life starts getting interesting.
;; What, exactly, do we need to do here?
(s/def ::child-id int?)
(s/def ::child-interaction (s/keys :req [::child-id]))

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

;; Q: Does this really need to be an atom?
(s/def ::active-clients (s/and #(instance? clojure.lang.Atom %)
                               ;; TODO: Should probably verify that this is a map of
                               ;; short keys to ::client-state
                               #(map? (deref %))))

(s/def ::child-spawner (s/fspec :args (s/cat)
                                :ret ::child-interaction))

(s/def ::state (s/keys :req [::active-clients
                             ::child-spawner
                             ::client-read-chan
                             ::client-write-chan
                             ::cookie-cutter
                             ;; This doesn't particularly belong here
                             ::current-client
                             ::event-loop-stopper
                             ::max-active-clients
                             ::shared/extension
                             ::shared/keydir
                             ::shared/my-keys
                             ::shared/packet-management
                             ::shared/working-area]))

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

(s/fdef alter-client-state!
        :args (s/cat :state ::state
                     :altered-client ::client-state)
        :ret nil?)
(defn alter-client-state!
  [state altered-client]
  (swap! (::active-clients state)
         update
         (get-in altered-client [::client-security ::shared/short-pk])
         ;; Q: Worth surgically applying a delta?
         (constantly altered-client)))

(s/fdef configure-shared-secrets
        :args (s/cat :client ::client-state
                     :server-short-sk ::shared/secret-key
                     :client-short-pk ::shared/public-key)
        :ret ::client-state)
(defn configure-shared-secrets
  "Return altered client state that reflects new shared key
  This almost corresponds to lines 369-371 in reference implementation,
  but does *not* have side-effects!  <----"
  [client
   server-short-sk
   client-short-pk]
  (-> client
      (assoc-in [::shared-secrets ::client-short<->server-short] (crypto/box-prepare client-short-pk server-short-sk))
      (assoc-in [::client-security ::short-pk] client-short-pk)
      (assoc-in [::client-security ::server-short-sk] server-short-sk)))

(s/fdef find-client
        :args (s/cat :state ::state
                     :client-short-key ::shared/public-key))
(defn find-client
  [state client-short-key]
  (-> state ::active-clients deref (get client-short-key)))

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
  (let [p-m (::shared/packet-management this)]
    (crypto/randomize-buffer! (::shared/packet p-m)))
  (crypto/random-bytes! (-> this ::current-client ::client-security ::shared/short-pk))
  ;; The shared secrets are all private, so I really can't touch them
  ;; Q: What *is* the best approach to clearing them then?
  ;; For now, just explicitly set my versions to nil once we get past these side-effects
  ;; (i.e. at the bottom)
  #_(crypto/random-bytes (-> this ::current-client ::shared-secrets :what?))
  (let [work-area (::shared/working-area this)]
    ;; These next two may make more sense once I have a better idea about
    ;; the actual messaging implementation.
    ;; Until then, plan on just sending objects across core.async.
    ;; Of course, the entire point may be messages that are too big
    ;; and need to be sharded.
    #_(crypto/random-bytes! (-> this :child-buffer ::buf))
    #_(crypto/random-bytes! (-> this :child-buffer ::msg))
    (crypto/random-bytes! (::shared/working-nonce work-area))
    (crypto/random-bytes! (::shared/text work-area)))
  (when-let [short-term-keys (get-in this [::shared/my-keys ::shared/short-pair])]
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
      (.printtStackTrace ex)
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
