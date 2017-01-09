(ns com.frereth.common.curve.server
  "Implement the server half of the CurveCP protocol"
  (:require [clojure.spec :as s]
            [com.frereth.common.curve.shared :as shared]
            [mount.core :as mount :refer [defstate]]
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

(defrecord WorkingArea [nonce
                        text])

(defrecord PacketManagement [packet ; TODO: Rename this to body
                             ip
                             nonce
                             port])

;; Q: Do I have any real use for this?
(defrecord ChildBuffer [buf
                        buf-len
                        msg
                        msg-len])

(declare begin! hide-secrets! one-minute)
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
                  working-area])

(defn start!
  []
  (println "CurveCP Server: Starting the server state")
  (let [{:keys [client-chan]
         :as this} (:server-state (mount/args))
        security (:security this)
        extension (:extension this)]
    (assert (and client-chan
                 (:name security)
                 (:keydir security)
                 extension
                 ;; Actually, the rule is that it must be
                 ;; 32 hex characters. Which really means
                 ;; a 16-byte array
                 (= (count extension) 16)))
    (println "Passed assertion checks")
    ;; Reference implementation starts by allocating the active client structs.
    ;; This is one area where updating in place simply cannot be worth it.
    ;; Q: Can it?
    ;; A: Skip it, for now

    ;; So we're starting by loading up the long-term keys
    (let [max-active-clients (or (:max-active-clients this) 100)
          keydir (:keydir security)
          long-pair (shared/do-load-keypair keydir)
          almost (-> this
                     ;; Randomize the cookie-cutter keys
                     (assoc :cookie-cutter {:minute-key (shared/random-array 32)
                                            :last-minute-key (shared/random-array 32)
                                            :next-minute(+ (System/nanoTime)
                                                           (one-minute))})
                     (assoc-in [:security :long-pair] long-pair)
                     (assoc :active-clients {})
                     (assoc :client-chan client-chan))]
      (println "Kicking off event loop")
      (assoc almost :event-loop-stopper (begin! this)))))

(defn stop!
  [this]
  (println "Stopping server state")
  (when-let [event-loop-stopper (:event-loop-stopper this)]
    (println "Stopping event loop")
    (event-loop-stopper))
  (println "Clearing secrets")
  (assoc (hide-secrets! this)
         :event-loop-stopper nil))

(defstate cp-state
  :start (start!)
  :stop (stop! cp-state))
;;; TODO: Def the State spec

(defn alloc-client
  []
  (let [interact (map->ChildInteraction {:child-id -1})
        sec (map->ClientSecurity {:long-pair (shared/random-bytes! (byte-array 32))
                                  :short-pair (shared/random-bytes! (byte-array 32))})]
    (map->ClientState {:child-interaction interact
                       :client-security sec
                       :extension (shared/random-bytes! (byte-array 16))
                       :message (shared/random-bytes! (byte-array message-len))
                       :message-len (shared/random-long)
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
  [state]
  (let [now (System/nanoTime)
        timeout (- (-> state :cookie-cutter :next-minute) now)]
    (if (<= timeout 0)
      (let [timeout (one-minute now)]
        (shared/byte-copy! (-> state :cookie-cutter :last-minute-key))
        (assoc (hide-secrets! state)
               :timeout timeout))
      (assoc state :timeout timeout))))

(defn begin!
  "Start the event loop"
  [{:keys [client-chan]
    :as state}]
  (let [stopper (deferred/deferred)
        stopped (promise)]
    (deferred/loop [state (assoc state
                                 :timeout (one-minute))]
      (println "Top of event loop. Timeout: " (:timeout state))
      (deferred/chain
        ;; timeout is in nanoseconds.
        ;; The timeout is in milliseconds, but state's timeout uses
        ;; the nanosecond clock
        (stream/try-take! client-chan ::drained
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
            msg))
        (fn [state]
          (if-not (identical? state ::drained)
            (if-not (realized? stopper)
              (deferred/recur (handle-key-rotation state))
              (do
                (println "Received stop signal")
                (deliver stopped ::exited)))
            (println "Closing because client connection is drained")))))
    (fn []
      (deliver stopper ::exiting)
      @stopped)))

(defn hide-secrets!
  [state]
  ;; This is almost the top of the server's for(;;)
  ;; Missing step: reset timeout
  ;; Missing step: copy :minute-key into :last-minute-key
  (let [min-key-array (-> state :cookie-cutter :minute-key)]
    (assert min-key-array)
    (shared/random-bytes! min-key-array))
  ;; Missing step: update cookie-cutter's next-minute
  (shared/random-bytes! (-> state :packet-management :packet))
  (shared/random-bytes! (-> state :packet-management :ip))
  (shared/random-bytes! (-> state :packet-management :port))
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
  (shared/random-bytes! (-> state :security :short-pair .getPublicKey))
  (shared/random-bytes! (-> state :security :short-pair .getSecretKey))
  ;; Clear the shared secrets in the current client
  ;; Maintaning these anywhere I don't need them seems like an odd choice.
  ;; Actually, keeping them in 2 different places seems odd.
  ;; Q: What's the point to current-client at all?
  (assoc-in state [:current-client :shared-secrets] nil))
