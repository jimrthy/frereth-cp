(ns com.frereth.common.curve.server
  "Implement the server half of the CurveCP protocol"
  (:require [clojure.spec :as s]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.util :as util]
            [com.stuartsierra.component :as cpt]
            [gloss.core :as gloss-core]
            [gloss.io :as gloss]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))

(def default-max-clients 100)
(def message-len 1104)

;; For maintaining a secret symmetric pair of encryption
;; keys for the cookies.
(s/def ::last-minute-key ::shared/symmetric-key)
(s/def ::minute-key ::shared/symmetric-key)
(s/def ::next-minute integer?)
(s/def cookie-cutter (s/keys :req [::next-minute
                                   ::minute-key
                                   ::last-minute-key]))

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
(s/def ::from-child (s/and stream/sinkable?
                           stream/sourceable?))
(s/def ::to-child (s/and stream/sinkable?
                         stream/sourceable?))

(s/def ::child-interaction (s/keys :req [::child-id
                                         ::to-child
                                         ::from-child]))

(s/def ::client-state (s/keys :req [::child-interaction
                                    ::client-security
                                    ::extension
                                    ::message
                                    ::message-len
                                    ::received-nonce
                                    ::sent-nonce
                                    ::shared-secrets]))

(s/def ::state (s/keys :req-un [::shared/packet-management]))

(declare alloc-client begin! hide-secrets! randomized-cookie-cutter)
(defrecord State [active-clients
                  client-chan
                  cookie-cutter
                  current-client
                  event-loop-stopper
                  extension
                  max-active-clients
                  my-keys
                  packet-management
                  server-routing
                  working-area]
  cpt/Lifecycle
  (start
    [{:keys [client-chan
             extension
             my-keys]
      :as this}]
    {:pre [(and client-chan
                (:chan client-chan)
                (::shared/server-name my-keys)
                (::shared/keydir my-keys)
                extension
                ;; Actually, the rule is that it must be
                ;; 32 hex characters. Which really means
                ;; a 16-byte array
                (= (count extension) shared/extension-length))]}
    (println "CurveCP Server: Starting the server state")
    ;; Reference implementation starts by allocating the active client structs.
    ;; This is one area where updating in place simply cannot be worth it.
    ;; Q: Can it?
    ;; A: Skip it, for now

    ;; So we're starting by loading up the long-term keys
    (let [max-active-clients (or (:max-active-clients this) default-max-clients)
          keydir (::shared/keydir my-keys)
          long-pair (shared/do-load-keypair keydir)
          almost (-> this
                     (assoc :active-clients (atom #{})
                            :cookie-cutter (randomized-cookie-cutter)
                            :current-client (alloc-client)
                            :max-active-clients max-active-clients
                            :packet-management (shared/default-packet-manager)
                            :working-area (shared/default-work-area))
                     (assoc-in [:my-keys :shared/long-pair] long-pair)
                     (assoc :active-clients {}))]
      (println "Kicking off event loop. packet-management:" (:packet-management almost))
      (assoc almost :event-loop-stopper (begin! almost))))

  (stop
    [this]
    (println "Stopping server state")
    (when-let [event-loop-stopper (:event-loop-stopper this)]
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
                 :event-loop-stopper nil)]
      (println "Secrets hidden")
      outcome)))
;;; TODO: Def the State spec

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
     ::extension (shared/random-bytes! (byte-array 16))
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
  (throw (RuntimeException. (str "Just received: " msg))))

(defn handle-key-rotation
  "Doing it this way means that state changes are only seen locally

  They really need to propagate back up to the System that owns the Component.

  It seems obvious that this state should go into an atom, or possibly an agent
  so other pieces can see it.

  But this is very similar to the kinds of state management issues that Om and
  Om next are trying to solve. So that approach might not be as obvious as it
  seems at first."
  [state]
  (try
    (println "Checking whether it's time to rotate keys or not")
    (let [now (System/nanoTime)
          next-minute (-> state :cookie-cutter :next-minute)
          _ (println "next-minute:" next-minute "out of" (-> state keys)
                     "with cookie-cutter" (:cookie-cutter state))
          timeout (- next-minute now)]
      (println "Top of handle-key-rotation. Remaining timeout:" timeout)
      (if (<= timeout 0)
        (let [timeout (one-minute now)]
          (println "Saving key for previous minute")
          (try
            (shared/byte-copy! (-> state :cookie-cutter ::last-minute-key)
                               (-> state :cookie-cutter ::minute-key))
            (catch Exception ex
              (println "Key rotation failed:" ex "a" (class ex))))
          (println "Saved key for previous minute. Hiding:")
          (assoc (hide-secrets! state)
                 :timeout timeout))
        (assoc state :timeout timeout)))
    (catch Exception ex
      (println "Rotation failed:" ex "\nStack trace:")
      (.printtStackTrace ex)
      state)))

(defn hide-long-arrays
  "Try to make pretty printing less obnoxious"
  [state]
  (-> state
      (assoc-in [:packet-management ::shared/packet] "Lots o' bytes")
      (assoc :working-area "Lots more bytes")))

(defn begin!
  "Start the event loop"
  [{:keys [client-chan]
    :as this}]
  (let [stopper (deferred/deferred)
        stopped (promise)]
    (deferred/loop [this (assoc this
                                 :timeout (one-minute))]
      (println "Top of event loop. Timeout: " (:timeout this) "in"
               (util/pretty (hide-long-arrays this)))
      (deferred/chain
        ;; timeout is in nanoseconds.
        ;; The timeout is in milliseconds, but state's timeout uses
        ;; the nanosecond clock
        (stream/try-take! (:chan client-chan) ::drained
                          ;; This is in milliseconds
                          (inc (/ (:timeout this) shared/nanos-in-milli)) ::timeout)
        (fn [msg]
          (println (str "Top of Server Event loop received " msg))
          (if-not (or (identical? ::drained msg)
                      (identical? ::timeout msg))
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
              (println "Took from the client:" msg)
              (if (identical? msg ::drained)
                msg
                this))))
        ;; Return a function that will (eventually) cause that event
        ;; loop to exit
        (fn [this]
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
              (deliver stopped ::drained))))))
    (fn [timeout]
      (when (not (realized? stopped))
        (deliver stopper ::exiting))
      (deref stopped timeout ::stopping-timed-out))))

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
  (let [p-m (:packet-management this)]
    (shared/random-bytes! (::shared/packet p-m)))
  (shared/random-bytes! (-> this :current-client ::client-security ::short-pk))
  ;; These are all private, so I really can't touch them
  ;; Q: What *is* the best approach to clearing them then?
  ;; For now, just explicitly set to nil once we get past these side-effects
  ;; (i.e. at the bottom)
  #_(shared/random-bytes (-> this :current-client ::shared-secrets :what?))
  (let [work-area (:working-area this)]
    (shared/random-bytes! (::shared/working-nonce work-area))
    (shared/random-bytes! (::shared/text work-area)))
  ;; These next two may make more sense once I have a better idea about
  ;; the actual messaging implementation.
  ;; Until then, plan on just sending objects across core.async.
  ;; Of course, the entire point may be messages that are too big
  ;; and need to be sharded.
  #_(shared/random-bytes! (-> this :child-buffer ::buf))
  #_(shared/random-bytes! (-> this :child-buffer ::msg))
  (when-let [short-term-keys (get-in this [:my-keys ::short-pair])]
    (shared/random-bytes! (.getPublicKey short-term-keys)))
  (shared/random-bytes! (-> this :my-keys ::long-pair .getSecretKey))
  ;; Clear the shared secrets in the current client
  ;; Maintaning these anywhere I don't need them seems like an odd choice.
  ;; Actually, keeping them in 2 different places seems odd.
  ;; Q: What's the point to current-client at all?
  (assoc-in this [:current-client ::shared-secrets] {::client-short<->server-long nil
                                                     ::client-short<->server-short nil
                                                     ::client-long<->server-long nil}))

(defn randomized-cookie-cutter
  []
  {::minute-key (shared/random-key)
   ::last-minute-key (shared/random-key)
   ::next-minute(+ (System/nanoTime)
                   (one-minute))})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn ctor
  [cfg]
  (map->State cfg))
