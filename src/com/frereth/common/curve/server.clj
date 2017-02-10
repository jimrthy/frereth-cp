(ns com.frereth.common.curve.server
  "Implement the server half of the CurveCP protocol"
  (:require [clojure.spec :as s]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))

(def default-max-clients 100)
(def message-len 1104)

;; For maintaining a secret symmetric pair of encryption
;; keys for the cookies.
(s/def ::last-minute-key ::shared/symmetric-key)
(s/def ::minute-key ::shared/symmetric-key)
(s/def ::next-minute integer?)
(s/def ::cookie-cutter (s/keys :req [::next-minute
                                     ::minute-key
                                     ::last-minute-key]))

;; Q: Move these public key specs into shared?
(s/def ::long-pk (s/and bytes?
                        #(= (count %) shared/key-length)))
(s/def ::short-pk (s/and bytes?
                         #(= (count %) shared/key-length)))
(s/def ::client-security (s/keys :req [::long-pk
                                       ::short-pk]))

(s/def client-short<->server-long ::shared/shared-secret)
(s/def client-short<->server-short ::shared/shared-secret)
(s/def client-long<->server-long ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-short<->server-long
                                      ::client-short<->server-short
                                      ::client-long<->server-long]))

;;; This is probably too restrictive. And it seems a little
;;; pointless. But we have to have *some* way to identify
;;; them. Especially if I'm coping with address/port at a
;;; higher level.
(s/def ::child-id integer?)
;;; Note that this is probably too broad, assuming I choose to
;;; go with this model.
;;; From this perspective, from-child is really just sourceable?
;;; while to-child is just sinkable?
(s/def ::from-child (s/and stream/sinkable?
                           stream/sourceable?))
(s/def ::to-child (s/and stream/sinkable?
                         stream/sourceable?))

(s/def ::child-interaction (s/keys :req [::child-id
                                         ::to-child
                                         ::from-child]))

;; This seems like something that should basically be defined in
;; shared.
;; Or, at least, ::chan ought to.
;; Except that it's a...what?
;; (it seems like it ought to be an async/chan, but it might really
;; be a manifold/stream
(s/def ::client-chan (s/keys :req [::chan]))

(s/def ::client-state (s/keys :req [::child-interaction
                                    ::client-security
                                    ::shared/extension
                                    ::message
                                    ::message-len
                                    ::received-nonce
                                    ::sent-nonce
                                    ::shared-secrets]))

(s/def ::state (s/keys :req [::active-clients
                             ::client-chan
                             ::cookie-cutter
                             ::current-client
                             ::event-loop-stopper
                             ::max-active-clients
                             ::shared/extension
                             ::shared/keydir
                             ::shared/my-keys
                             ::shared/packet-management
                             ::shared/server-name
                             ::shared/working-area]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef alloc-client
        :args (s/cat)
        :ret ::client-state)
(defn alloc-client
  []
  (let [interact {::child-id -1}
        sec {::long-pk (shared/random-key)
             ::short-pk (shared/random-key)}]
    {::child-interaction interact
     ::client-security sec
     ::shared/extension (shared/random-bytes! (byte-array 16))
     ::message (shared/random-bytes! (byte-array message-len))
     ::message-len 0
     ::received-nonce 0
     ::sent-nonce (shared/random-nonce)}))

(defn one-minute
  ([]
   (* 60 shared/nanos-in-second))
  ([now]
   (+ (one-minute) now)))

(defn handle-incoming!
  [state msg]
  (throw (ex-info "Not yet written" {:message msg})))

(defn hide-secrets!
  [this]
  (println "Hiding secrets")
  ;; This is almost the top of the server's for(;;)
  ;; Missing step: reset timeout
  ;; Missing step: copy :minute-key into :last-minute-key
  ;; (that's handled by key rotation. Don't need to bother
  ;; if we're "just" cleaning up on exit)
  (let [minute-key-array (get-in this [:cookie-cutter ::minute-key])]
    (assert minute-key-array)
    (shared/random-bytes! minute-key-array))

  ;; Missing step: update cookie-cutter's next-minute
  ;; (that happens in handle-key-rotation)
  (let [p-m (::shared/packet-management this)]
    (shared/random-bytes! (::shared/packet p-m)))
  (shared/random-bytes! (-> this ::current-client ::client-security ::short-pk))
  ;; These are all private, so I really can't touch them
  ;; Q: What *is* the best approach to clearing them then?
  ;; For now, just explicitly set to nil once we get past these side-effects
  ;; (i.e. at the bottom)
  #_(shared/random-bytes (-> this :current-client ::shared-secrets :what?))
  (let [work-area (::shared/working-area this)]
    ;; These next two may make more sense once I have a better idea about
    ;; the actual messaging implementation.
    ;; Until then, plan on just sending objects across core.async.
    ;; Of course, the entire point may be messages that are too big
    ;; and need to be sharded.
    #_(shared/random-bytes! (-> this :child-buffer ::buf))
    #_(shared/random-bytes! (-> this :child-buffer ::msg))
    (shared/random-bytes! (::shared/working-nonce work-area))
    (shared/random-bytes! (::shared/text work-area)))
  (when-let [short-term-keys (get-in this [::shared/my-keys ::short-pair])]
    (shared/random-bytes! (.getPublicKey short-term-keys))
    (shared/random-bytes! (.getSecretKey short-term-keys)))
  ;; Clear the shared secrets in the current client
  ;; Maintaning these anywhere I don't need them seems like an odd choice.
  ;; Actually, keeping them in 2 different places seems odd.
  ;; Q: What's the point to current-client at all?
  (assoc-in this [:current-client ::shared-secrets] {::client-short<->server-long nil
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
    (println "Checking whether it's time to rotate keys or not")
    (let [now (System/nanoTime)
          next-minute (::next-minute cookie-cutter)
          _ (println "next-minute:" next-minute "out of" (keys state)
                     "with cookie-cutter" cookie-cutter)
          timeout (- next-minute now)]
      (println "Top of handle-key-rotation. Remaining timeout:" timeout)
      (if (<= timeout 0)
        (let [timeout (one-minute now)]
          (println "Saving key for previous minute")
          (try
            (shared/byte-copy! (::last-minute-key cookie-cutter)
                               (::minute-key cookie-cutter))
            ;; Q: Why aren't we setting up the next minute-key here and now?
            (catch Exception ex
              (println "Key rotation failed:" ex "a" (class ex))))
          (println "Saved key for previous minute. Hiding:")
          (assoc (hide-secrets! state)
                 ::timeout timeout))
        (assoc state ::timeout timeout)))
    (catch Exception ex
      (println "Rotation failed:" ex "\nStack trace:")
      (.printtStackTrace ex)
      state)))

;;; This is generally useful enough that I'm doing the actual
;;; definition down below in the public section.
;;; But (begin!) uses it pretty heavily.
;;; For now.
(declare hide-long-arrays)

(defn begin!
  "Start the event loop"
  [{:keys [::client-chan]
    :as this}]
  (let [stopper (deferred/deferred)
        stopped (promise)]
    (deferred/loop [this (assoc this
                                ::timeout (one-minute))]
      (println "Top of Server event loop. Timeout: " (::timeout this) "in"
               (comment (util/pretty (hide-long-arrays this)))
               "...[this]...")
      (deferred/chain
        ;; The timeout is in milliseconds, but state's timeout uses
        ;; the nanosecond clock
        (stream/try-take! (:chan client-chan)
                          ::drained
                          ;; Need to convert nanoseconds into milliseconds
                          (inc (/ (::timeout this) shared/nanos-in-milli))
                          ::timedout)
        (fn [msg]
          (println (str "Top of Server Event loop received " msg))
          (if-not (or (identical? ::drained msg)
                      (identical? ::timedout msg))
            (try
              ;; Q: Do I want unhandled exceptions to be fatal errors?
              (let [modified-state (handle-incoming! this msg)]
                (println "Updated state based on incoming msg:" (hide-long-arrays modified-state))
                modified-state)
              (catch clojure.lang.ExceptionInfo ex
                (println "handle-incoming! failed" ex (.getStackTrace ex))
                this)
              (catch RuntimeException ex
                (println "Unhandled low-level exception escaped handler" ex (.getStackTrace ex))
                (comment this))
              (catch Exception ex
                (println "Major problem escaped handler" ex (.getStackTrace ex))))
            (do
              (println "Server recv from" (:chan client-chan) ":" msg)
              (if (identical? msg ::drained)
                msg
                this))))
        ;; Return a function that will (eventually) cause that event
        ;; loop to exit
        (fn [this]
          (if this
            (if-not (identical? this ::drained)
              (if-not (realized? stopper)
                (do
                  (println "Rotating" (util/pretty (hide-long-arrays this)))
                  (deferred/recur (handle-key-rotation this)))
                (do
                  (println "Received stop signal")
                  (deliver stopped ::exited)))
              (do
                (println "Closing because client connection is drained")
                (deliver stopped ::drained)))
            (do
              (println "Exiting event loop because state turned falsey. Unhandled exception?")
              (deliver stopped ::failed))))))
    (fn [timeout]
      (when (not (realized? stopped))
        (deliver stopper ::exiting))
      (deref stopped timeout ::stopping-timed-out))))

(defn randomized-cookie-cutter
  []
  {::minute-key (shared/random-key)
   ::last-minute-key (shared/random-key)
   ;; Q: Should this be ::timeout?
   ;; A: No. There's definitely a distinction.
   ;; Q: Alright, then. What is the difference?
   ::next-minute(+ (System/nanoTime)
                   (one-minute))})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn hide-long-arrays
  "Try to make pretty printing less obnoxious"
  [state]
  (-> state
      (assoc-in [::current-client ::message] "...")
      (assoc-in [::shared/packet-management ::shared/packet] "...")
      (assoc #_[::message "..."]
             ::shared/working-area "...")))

(defn start!
  [{:keys [::client-chan
           ::shared/extension
           ::shared/my-keys]
    :as this}]
  {:pre [client-chan
         (:chan client-chan)
         #_(::shared/server-name my-keys)
         #_(::shared/keydir my-keys)
         extension
         ;; Actually, the rule is that it must be
         ;; 32 hex characters. Which really means
         ;; a 16-byte array
           (= (count extension) shared/extension-length)]}
  (println "CurveCP Server: Starting the server state")

  ;; Reference implementation starts by allocating the active client structs.
  ;; This is one area where updating in place simply cannot be worth it.
  ;; Q: Can it?
  ;; A: Skip it, for now


  ;; So we're starting by loading up the long-term keys
  (let [keydir (::shared/keydir my-keys)
        long-pair (shared/do-load-keypair keydir)
        this (assoc-in this [::shared/my-keys ::shared/long-pair] long-pair)
        almost (assoc this ::cookie-cutter (randomized-cookie-cutter))]
    (println "Kicking off event loop. packet-management:" (::shared/packet-management almost))
    (assoc almost ::event-loop-stopper (begin! almost))))

(defn stop!
  [{:keys [::event-loop-stopper]
    :as this}]
  (println "Stopping server state")
  (when event-loop-stopper
    (println "Sending stop signal to event loop")
    ;; This is fairly pointless. The client channel Component on which this
    ;; depends will close shortly after this returns. That will cause the
    ;; event loop to exit directly.
    ;; But, just in case that doesn't work, this will tell the event loop to
    ;; exit the next time it times out.
    (event-loop-stopper 1))
  (println "Clearing secrets")

  (let [outcome
        (assoc (try
                 (hide-secrets! this)
                 (catch Exception ex
                   (println "WARNING:" ex)
                   ;; TODO: This really should be fatal.
                   ;; Make the error-handling go away once hiding secrets actually works
                   this))
               ::event-loop-stopper nil)]
    (println "Secrets hidden")
    outcome))

(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::max-active-clients]
    :or {max-active-clients default-max-clients}
    :as cfg}]
  (-> cfg
      (assoc ::active-clients (atom #{})  ; Q: set or map?
             ::current-client (alloc-client)  ; Q: What's the point?
             ::max-active-clients max-active-clients
             ::shared/packet-management (shared/default-packet-manager)
             ::shared/working-area (shared/default-work-area))))
