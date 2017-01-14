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

(def message-len 1104)

;; For maintaining a secret symmetric pair of encryption
;; keys for the cookies.
(defrecord CookieCutter [next-minute
                         minute-key
                         last-minute-key])

(defrecord Security [keydir
                     name
                     long-pair
                     short-pair])

(s/def ::long-term-public (s/and bytes?
                                 #(= (count %) 32)))
(s/def ::short-term-public (s/and bytes?
                                  #(= (count %) 32)))
(defrecord ClientSecurity [long-pk
                           short-pk])
(s/def ::client-security (s/keys :req-un [::long-pk
                                          ::short-pk]))

(defrecord SharedSecrets [client-short<->server-long
                          client-short<->server-short
                          client-long<->server-long])

;;; This is probably too restrictive. And it seems a little
;;; pointless. But we have to have *some* way to identify
;;; them. Especially if I'm coping with address/port at a
;;; higher level.
(s/def ::child-id integer?)
(s/def ::from-child (s/and stream/sinkable?
                           stream/sourceable?))
(s/def ::to-child (s/and stream/sinkable?
                         stream/sourceable?))

(defrecord ChildInteraction [child-id
                             from-child
                             to-child])
(s/def ::child-interaction (s/keys :req-un [::child-id
                                            ::to-child
                                            ::from-child]))

(defrecord ClientState [child-interaction
                        client-security
                        extension
                        message
                        message-len
                        received-nonce
                        sent-nonce
                        shared-secrets])
(s/def ::client-state (s/keys :req-un [::child-interaction
                                       ::client-security
                                       ::extension
                                       ::message
                                       ::message-len
                                       ::received-nonce
                                       ::sent-nonce
                                       ::shared-secrets]))

;; This seems like it probably belongs in shared
(defrecord WorkingArea [nonce
                        text])
;; Q: Worth specifying a length?
(s/def ::nonce bytes?)
(s/def ::text bytes?)
(s/def ::working-area (s/keys :req-un [::nonce ::text]))

;; Q: Do I have any real use for this?
(defrecord ChildBuffer [buf
                        buf-len
                        msg
                        msg-len])

(declare alloc-client begin! hide-secrets! one-minute)
(defrecord State [active-clients
                  client-chan
                  cookie-cutter
                  current-client
                  event-loop-stopper
                  extension
                  max-active-clients
                  packet-management
                  server-routing
                  security
                  working-area]
  cpt/Lifecycle
  (start
    [{:keys [client-chan
             extension
             security]
      :as this}]
    (println "CurveCP Server: Starting the server state")
    (assert (and client-chan
                 (:chan client-chan)
                 (:name security)
                 (:keydir security)
                 extension
                 ;; Actually, the rule is that it must be
                 ;; 32 hex characters. Which really means
                 ;; a 16-byte array
                 (= (count extension) 16)))
    ;; Reference implementation starts by allocating the active client structs.
    ;; This is one area where updating in place simply cannot be worth it.
    ;; Q: Can it?
    ;; A: Skip it, for now

    ;; So we're starting by loading up the long-term keys

    (let [max-active-clients (or (:max-active-clients this) 100)
          keydir (:keydir security)
          long-pair (shared/do-load-keypair keydir)
          almost (-> this
                     (assoc :active-clients (atom #{})
                            ;; Randomize the cookie-cutter keys
                            :cookie-cutter {:minute-key (shared/random-key)
                                            :last-minute-key (shared/random-key)
                                            :next-minute(+ (System/nanoTime)
                                                           (one-minute))}
                            :current-client (alloc-client)
                            :max-active-clients max-active-clients
                            :packet-management (shared/map->PacketManagement {:packet (byte-array 4096)
                                                                              :ip (byte-array 4)
                                                                              :nonce 0N
                                                                              :port (byte-array 2)})
                            :working-area (map->WorkingArea {:nonce (byte-array 24)
                                                             :text (byte-array 2048)}))
                     (assoc-in [:security :long-pair] long-pair)
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

(defn alloc-client
  []
  (let [interact (map->ChildInteraction {:child-id -1})
        sec (map->ClientSecurity {:long-pk (shared/random-key)
                                  :short-pk (shared/random-key)})]
    (map->ClientState {:child-interaction interact
                       :client-security sec
                       :extension (shared/random-bytes! (byte-array 16))
                       :message (shared/random-bytes! (byte-array message-len))
                       :message-len 0
                       :received-nonce 0
                       :sent-nonce (shared/random-mod 281474976710656N)})))

(defn one-minute
  ([]
   (* 60 shared/nanos-in-seconds))
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
            (shared/byte-copy! (-> state :cookie-cutter :last-minute-key)
                               (-> state :cookie-cutter :minute-key))
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
      (assoc-in [:packet-management :packet] "Lots o' bytes")
      (assoc :working-area "Lots more bytes")))

(defn begin!
  "Start the event loop"
  [{:keys [client-chan]
    :as state}]
  (let [stopper (deferred/deferred)
        stopped (promise)]
    (deferred/loop [state (assoc state
                                 :timeout (one-minute))]
      (println "Top of event loop. Timeout: " (:timeout state) "in"
               (util/pretty (hide-long-arrays state)))
      (deferred/chain
        ;; timeout is in nanoseconds.
        ;; The timeout is in milliseconds, but state's timeout uses
        ;; the nanosecond clock
        (stream/try-take! (:chan client-chan) ::drained
                          (inc (/ (:timeout state) 1000000)) ::timeout)
        (fn [msg]
          (println (str "Top of Server Event loop received " msg))
          (if-not (or (identical? ::drained msg)
                      (identical? ::timeout msg))
            (try
              ;; Q: Do I want unhandled exceptions to be fatal errors?
              (let [modified-state (handle-incoming! state msg)]
                (println "Updated state based on incoming msg:" state)
                modified-state)
              (catch clojure.lang.ExceptionInfo ex
                (println "handle-incoming! failed" ex (.getStackTrace ex))
                state)
              (catch RuntimeException ex
                (println "Unhandled low-level exception escaped handler" ex (.getStackTrace ex))
                (comment state))
              (catch Exception ex
                (println "Major problem escaped handler" ex (.getStackTrace ex))))
            (do
              (println "Took from the client:" msg)
              (if (identical? msg ::drained)
                msg
                state))))
        (fn [state]
          (if-not (identical? state ::drained)
            (if-not (realized? stopper)
              (do
                (println "Rotating" (util/pretty (hide-long-arrays state)))
                (deferred/recur (handle-key-rotation state)))
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
  [state]
  (println "Hiding secrets")
  ;; This is almost the top of the server's for(;;)
  ;; Missing step: reset timeout
  ;; Missing step: copy :minute-key into :last-minute-key
  (let [min-key-array (-> state :cookie-cutter :minute-key)]
    (assert min-key-array)
    (shared/random-bytes! min-key-array))
  ;; Missing step: update cookie-cutter's next-minute
  ;; (that happens in handle-key-rotation)
  (let [p-m (:packet-management state)]
    (shared/random-bytes! (:packet p-m))
    (shared/random-bytes! (:ip p-m))
    (shared/random-bytes! (:port p-m)))
  (shared/random-bytes! (-> state :current-client :client-security :short-pk))
  ;; These are all private, so I really can't touch them
  ;; Q: What *is* the best approach to clearing them then?
  ;; For now, just explicitly set to nil once we get past these side-effects
  #_(shared/random-bytes (-> state :current-client :shared-secrets :what?))
  (shared/random-bytes! (-> state :working-area :nonce))
  (shared/random-bytes! (-> state :working-area :text))
  ;; These next two may make more sense once I have a better idea about
  ;; the actual messaging implementation.
  ;; Until then, plan on just sending objects across core.async.
  ;; Of course, the entire point may be messages that are too big
  ;; and need to be sharded.
  #_(shared/random-bytes! (-> state :child-buffer :buf))
  #_(shared/random-bytes! (-> state :child-buffer :msg))
  (when-let [short-term-keys (-> state :security :short-pair)]
    (shared/random-bytes! (.getPublicKey short-term-keys)))
  (shared/random-bytes! (-> state :security :long-pair .getSecretKey))
  ;; Clear the shared secrets in the current client
  ;; Maintaning these anywhere I don't need them seems like an odd choice.
  ;; Actually, keeping them in 2 different places seems odd.
  ;; Q: What's the point to current-client at all?
  (assoc-in state [:current-client :shared-secrets] nil))

(defn ctor
  [cfg]
  (map->State cfg))
