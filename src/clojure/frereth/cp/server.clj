(ns frereth.cp.server
  "Implement the server half of the CurveCP protocol"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth.cp.message.specs :as msg-specs]
            [frereth.cp.server
             [cookie :as cookie]
             [hello :as hello]
             [helpers :as helpers]
             [initiate :as initiate]
             [state :as state]]
            [frereth.cp
             [shared :as shared]]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [specs :as specs]
             [util :as util]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import clojure.lang.ExceptionInfo
           io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(def default-max-clients 100)

;; Q: Do any of these really belong in here instead of shared.constants?
;; (minimum-initiate-packet-length seems defensible)
(def minimum-message-packet-length 112)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;; These next 2 really should be private. They're building blocks
;;; trying to reduce duplication (which may just fly in the face of
;;; the way spec is supposed to work)
(s/def ::shared-state-keys (s/keys :req [::weald/logger
                                         ::weald/state-atom
                                         ::shared/extension]))
(s/def ::common-state-option-keys (s/merge ::shared-state-keys
                                           (s/keys :req [;; Honestly, this should be an xor.
                                                         ;; It makes sense for the caller to
                                                         ;; supply one or the other, but not both.
                                                         (or ::shared/keydir ::shared/my-keys)
                                                         ;; Remember the distinction between these and
                                                         ;; the callbacks for sharing bytes with the child
                                                         ::state/client-read-chan
                                                         ::state/client-write-chan])))

;; These are the pieces that are used to put together the pre-state
(s/def ::pre-state-options (s/merge ::common-state-option-keys
                                    (s/keys :opt [::state/max-active-clients]
                                            :req [
                                                  ;; Can't include the child-spawner! spec,
                                                  ;; or checking it will spawn several children that we don't
                                                  ;; really want.
                                                  #_::msg-specs/child-spawner!
                                                  ;; ditto
                                                  #_::msg-specs/->child])))

;; Note that this really only exists as an intermediate step for the
;; sake of producing a ::state/state.
(s/def ::pre-state (s/merge ::shared-state-keys
                            (s/keys :req [::msg-specs/child-spawner!
                                          ::state/active-clients
                                          ::state/client-read-chan
                                          ::state/client-write-chan
                                          ::state/max-active-clients
                                          ;; Note that this really only makes sense
                                          ;; in terms of loading up my-keys.
                                          ;; And, really, it seems like there are
                                          ;; cleaner/better ways to handle that.
                                          ;; Like storing them in a database that
                                          ;; can handle expirations/rotations
                                          ;; and passing them directly to the constructor
                                          ::shared/keydir
                                          ::shared/working-area]
                                    :opt [::state/cookie-cutter
                                          ::state/current-client
                                          ::state/event-loop-stopper!
                                          ::shared/my-keys])))

  ;; After we've stopped it, these are the options we can use to start
  ;; another one with the same details

(s/def ::post-state-options (s/merge ::common-state-option-keys
                                     (s/keys :req [::state/max-active-clients])))

(comment
  (s/describe ::pre-state-options)
  )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef check-packet-length
  :args (s/cat :log-state-atom ::weald/state-atom
               :packet bytes?)
  :ret ::specs/okay?)
(defn check-packet-length
  "Could this packet possibly be a valid CurveCP packet, based on its size?"
  [log-state-atom packet]
  (log/atomically! log-state-atom
                   log/debug
                   ::check-packet-length
                   "Incoming"
                   {::packet packet
                    ::packet-class (class packet)})
  (let [packet (bytes packet)
        ;; `r` is what the reference implementation uses.
        ;; For now, retain the name for
        ;; reference/compatibility/historical reasons
        r (count packet)]
    (log/atomically! log-state-atom
                     log/info
                     ::check-packet-length
                     (str "Incoming packet contains " r " somethings"))
    (and (<= 80 r 1184)
         ;; TODO: Keep an eye out for potential benchmarks
         ;; The compiler really should be smart enough so these next
         ;; two are equivalent.
         #_(= (bit-and r 0xf) 0)
         (= (rem r 16) 0))))
(comment
  (let [r #_80 #_800 #_640 6400]
    [(zero? (bit-and r 0xf))
     (zero? (rem r 16))]))

(s/fdef verify-my-packet
        :args (s/cat :this ::state
                     ;; TODO: Be more specific about these
                     :header bytes?
                     ;; This has a spec def in both client.state
                     ;; and shared.constants.
                     ;; Neither one can possibly be right, can it?
                     ;; (I kind-of suspect that shared.constants
                     ;; has to do with a serialization template)
                     :server-extension bytes?)
        :ret (s/keys :req [::specs/okay?
                           ::weald/state]))
(defn verify-my-packet
  "Was this packet really intended for this server?"
  [{:keys [::shared/extension]
    log-state ::weald/state}
   header
   rcvd-xtn]
  (let [rcvd-prefix (-> header
                        vec
                        (subvec 0 (dec K/header-length))
                        byte-array)
        original (not= 0
                       ;; Q: Why did DJB use a bitwise and here?
                       ;; (most likely current guess: it doesn't shortcut)
                       ;; Q: Does that reason go away when you factor in the hoops I
                       ;; have to jump through to jump between bitwise and logical
                       ;; operations?
                       (bit-and (if (b-t/bytes= K/client-header-prefix
                                                rcvd-prefix)
                                  -1 0)
                                (if (b-t/bytes= extension
                                                rcvd-xtn)
                                  -1 0)))
        ;; TODO: Revisit the original and decide whether it's worth the trouble.
        ;; ALT: Compare the prefix as a vector. See how much of a performance hit we take
        ;; It doesn't seem likely that timing attacks matter here. These get sent in
        ;; clear-text.
        ;; As always: check with a cryptographer.
        verified (and (b-t/bytes= K/client-header-prefix
                                  rcvd-prefix)
                      (b-t/bytes= extension
                                  rcvd-xtn))]

    {::specs/okay? verified
     ::weald/state (if-not verified
                     (log/warn log-state
                               ::verify-my-packet
                               "Dropping packet intended for someone else."
                               {::K/client-header-prefix (String. K/client-header-prefix)
                                ::K/client-header-prefix-class (class K/client-header-prefix)
                                ::K/client-header-prefix-vec (vec K/client-header-prefix)
                                ::shared/extension (vec extension)
                                ::received-prefix (String. rcvd-prefix)
                                ::received-prefix-class (class rcvd-prefix)
                                ::received-prefix-vec (vec rcvd-prefix)
                                ::received-extension (vec rcvd-xtn)})
                     log-state)}))

(s/fdef do-handle-message
  :args (s/cat :state ::state/state
               :packet ::shared/network-packet)
  :ret ::state/delta)
(defn do-handle-message
  [state packet]
  (when (>= (count packet) minimum-message-packet-length)
    (throw (ex-info "Don't stop here!"
                    {:what "Interesting part: incoming message"}))))

(s/fdef do-handle-incoming
        :args (s/cat :this ::state/state
                     :msg ::shared/network-packet)
        :ret ::state/state)
(defn do-handle-incoming
  "Packet arrived from client. Do something with it."
  [{log-state-atom ::weald/state-atom
    :as this}
   {:keys [:host
           :port]
    message :message
    :as packet}]
  (swap! log-state-atom
         (fn [log-state]
           (let [synced (log/do-sync-clock log-state)]
             (log/debug synced
                        ::do-handle-incoming
                        "Server incoming <---------------"))))
  (let [;; Q: How much performance do we really lose if we
        ;; set up the socket to send a B] rather than a ByteBuf?
        message (bytes message)]
    (when-not message
      (throw (ex-info "Missing message in incoming packet"
                      {::problem packet})))
    (if (check-packet-length log-state-atom message)
      (let [header (byte-array K/header-length)
            server-extension (byte-array K/extension-length)]
        (b-t/byte-copy! header 0 K/header-length message)
        (b-t/byte-copy! server-extension 0 K/extension-length message K/header-length)
        (if (verify-my-packet this header server-extension)
          (let [_ (log/atomically! log-state-atom
                                   log/debug
                                   ::do-handle-incoming
                                   "This packet really is for me")
                packet-type-id (char (aget header (dec K/header-length)))
                _ (log/atomically! log-state-atom
                                   log/info
                                   ::do-handle-incoming
                                   "Packet for me"
                                   (-> this
                                       (dissoc ::weald/state)
                                       (assoc ::packet-type-id packet-type-id)))
                delta (try
                        (case packet-type-id
                          \H (hello/do-handle this
                                              cookie/do-build-response packet)
                          \I (initiate/do-handle this packet)
                          \M (do-handle-message this packet))
                        (catch Exception ex
                          (log/atomically! log-state-atom
                                           log/exception
                                           ex
                                           ::do-handle-incoming
                                           "Failed handling packet"
                                           {::packet-type-id packet-type-id})
                          this))]
            (log/atomically! log-state-atom
                             log/debug
                             ::do-handle-incoming
                             "Handled")
            (into this delta))
          (do
            (log/atomically! log-state-atom
                             log/info
                             ::do-handle-incoming
                             "Ignoring packet intended for someone else")
            this)))
      (do
        (log/atomically! log-state-atom
                         log/debug
                         ::do-handle-incoming
                         "Ignoring packet of illegal length"
                         {::state/message-length (count message)
                          ::shared/network-packet packet
                          ::pretty (b-t/->string message)})
        this))))

(s/fdef input-reducer
        :args (s/cat :this ::state/state
                     :message (s/or :stop-signal #{::drained
                                                   ::rotate
                                                   ::stop}
                                    :message ::shared/network-packet))
        :ret (s/nilable ::state/state))
(defn input-reducer
  "Convert input into the next state"
  [{:keys [::state/client-read-chan
           ::weald/logger]
    log-state-atom ::weald/state-atom
    :as this}
   msg]
  (log/atomically! log-state-atom
                  log/info
                  ::input-reducer
                  "Top of Server Event loop"
                  {::shared/network-packet msg
                   ::state/chan (::state/chan client-read-chan)
                   ::state/client-read-chan client-read-chan})
  (let [result (case msg
                 ::stop (do
                          (log/atomically! log-state-atom
                                           log/warn
                                           ::input-reducer
                                           "Received stop signal")
                          (reduced ::exited))
                 ::rotate (do
                            (state/handle-key-rotation this))
                 ::drained (do
                             (log/atomically! log-state-atom
                                              log/debug
                                              ::input-reducer
                                              "Source drained")
                             (reduced ::drained))
                 ;; Default is "Keep going"
                 (try
                   ;; Q: Do I want unhandled exceptions to be fatal errors?
                   (let [modified-state (do-handle-incoming this msg)]
                     (log/atomically! log-state-atom
                                      log/info
                                      ::input-reducer
                                      "Updated state based on incoming msg"
                                      (helpers/hide-long-arrays (dissoc modified-state ::weald/state-atom)))
                     this)
                   (catch clojure.lang.ExceptionInfo ex
                     (log/atomically! log-state-atom
                                      log/exception
                                      ex
                                      ::input-reducer
                                      "handle-incoming! failed")
                     this)
                   (catch RuntimeException ex
                     (log/atomically! log-state-atom
                                      log/exception
                                      ex
                                      "Unhandled low-level exception escaped handler")
                     (reduced nil))
                   (catch Exception ex
                     (log/atomically! log-state-atom
                                      log/exception
                                      ex
                                      "Major problem escaped handler")
                     (reduced nil))))]
    (log/flush-atomically! logger
                           log-state-atom)
    result))

(s/fdef build-event-loop-stopper
        ;; This isn't *quite* the ::state/state.
        ;; It doesn't include the ::stopper,
        ;; because that's what we're building here.
        ;; It should be possible to straighten that
        ;; out, but it doesn't seem worth the effort.
        :args (s/cat :this ::state/state)
        :ret ::state/event-loop-stopper!)
(defn build-event-loop-stopper
  [{:keys [::state/client-read-chan]
    log-atom ::weald/state-atom
    :as this}]
  (let [in-chan (::state/chan client-read-chan)]
    (fn []
      (log/atomically! log-atom
                       log/info
                       ::event-loop-stopper
                       "called")
      ;; It seems wrong to do the deref here.
      ;; This happens during shut-down, so isn't time-critical.
      ;; Making it synchronous makes like easier for everyone else.
      ;; So go with this approach until there's a strong reason for
      ;; changing.
      @(strm/put! in-chan ::stop))))

(s/fdef begin!
        :args (s/cat :this ::state/state)
        :ret any?)
(defn begin!
  "Start the event loop"
  [{:keys [::state/client-read-chan]
    log-state-atom ::weald/state-atom
    :as this}]
  (let [log-state (log/atomically! log-state-atom
                                   log/info
                                   ::do-begin
                                   "Starting server consumer"
                                   (select-keys this [::msg-specs/message-loop-name-base]))
        in-chan (::state/chan client-read-chan)
        ;; The part that handles input from the client
        finalized (strm/reduce input-reducer this in-chan)
        ;; Once a minute, signal rotation of the hidden symmetric key that handles cookie
        ;; encryption.
        key-rotator (strm/periodically (helpers/one-minute)
                                       (constantly ::rotate))]
    (strm/connect key-rotator in-chan {:upstream? true
                                       :description "Periodically trigger cookie key rotation"})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef start!
         :args (s/cat :this ::pre-state)
         :ret ::state/state)
(defn start!
  "Start a server"
  [{:keys [::weald/logger
           ::state/client-read-chan
           ::state/client-write-chan
           ::shared/extension
           ::shared/my-keys]
    log-state-atom ::weald/state-atom
    :as this}]
  {:pre [client-read-chan
         (::state/chan client-read-chan)
         client-write-chan
         (::state/chan client-write-chan)
         (::specs/srvr-name my-keys)
         (::shared/keydir my-keys)
         extension
         ;; Actually, the rule is that it must be
         ;; 32 hex characters. Which really means
         ;; a 16-byte array
         (= (count extension) K/extension-length)
         log-state-atom]}

  ;; Reference implementation starts by allocating the active client structs.
  ;; This is one area where updating in place simply cannot be worth it.
  ;; Q: Can it?
  ;; A: Skip it, for now
  (log/atomically! log-state-atom
                   log/warn
                   ::start!
                   "CurveCP Server: Starting the server state"
                   my-keys)
  (let [;; So we're starting by loading up the long-term keys
        keydir (::shared/keydir my-keys)
        long-pair (crypto/do-load-keypair log-state-atom keydir)
        this (assoc-in this [::shared/my-keys ::shared/long-pair] long-pair)
        almost (assoc this
                      ::state/cookie-cutter (state/randomized-cookie-cutter))
        _ (log/atomically! log-state-atom
                           log/info
                           ::start!
                           "Kicking off event loop.")
        base-result (assoc almost
                           ::state/event-loop-stopper! (build-event-loop-stopper almost))
        _ (log/flush-atomically! logger log-state-atom)]
    (begin! base-result)
    base-result))

(s/fdef stop!
        :args (s/cat :this ::state/state)
        :ret ::post-state-options)
(defn stop!
  "Stop the ioloop (but not the read/write channels: we don't own them)"
  [{:keys [::weald/logger
           ::state/event-loop-stopper!]
    log-state-atom ::weald/state-atom
    :as this}]
  ;; Q: Does the clock sync make sense here?
  (swap! log-state-atom #(update %
                                 ::weald/lamport
                                 log/do-sync-clock))
  (log/atomically! log-state-atom
                   log/warn
                   ::stop!
                   "Stopping server state")
  (try
    (if event-loop-stopper!
      (try
        (log/atomically! log-state-atom
                         log/info
                         ::stop!
                         "Sending stop signal to event loop")
        (let [;; The caller needs to close the client-read-chan,
              ;; which will effectively stop the ioloop by draining
              ;; the reduce's source.
              ;; This will signal it to stop directly.
              ;; It's probably redudant, but feels safer.
              stopped (event-loop-stopper!)]
          (log/atomically! log-state-atom
                           log/debug
                           ::stop!
                           "stopped"
                           {::side-effect-returned stopped}))
        (catch Exception ex
          (log/atomically! log-state-atom
                           log/exception
                           ex
                           ::stop!))
        (catch Throwable ex
          (log/atomically! log-state-atom
                           log/exception
                           ex
                           ::stop!
                           "This was bad")
          (throw ex)))
      (log/atomically! log-state-atom
                       log/debug
                       ::stop!
                       "No stop method"))
    (log/atomically! log-state-atom
                     log/warn
                     ::stop!
                     "Clearing secrets")
    (log/flush-atomically! logger log-state-atom)
    (let [secrets-hidden (try
                           (state/hide-secrets! this)
                           (catch Exception ex
                             ;; Very tempting to split RuntimeException
                             ;; away from Exception. And then make Exception
                             ;; fatal
                             (log/atomically! log-state-atom
                                              log/exception
                                              ex
                                              ::stop!)
                             this))
          outcome (dissoc secrets-hidden
                          ::state/event-loop-stopper!
                          ;; This doesn't make any sense here anyway.
                          ;; But it's actually breaking my spec
                          ;; check.
                          ;; Somehow.
                          ::state/current-client)]
      (log/atomically! log-state-atom
                       log/warn
                       ::stop!
                       "Secrets hidden")
      outcome)
    (catch Exception ex
      (log/atomically! log-state-atom
                       log/exception
                       ex
                       ::stop!))))

(s/fdef ctor
        :args (s/cat :cfg ::pre-state-options)
        :ret ::pre-state)
(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::state/max-active-clients]
    log-state-atom ::weald/state-atom
    :or {max-active-clients default-max-clients}
    :as cfg}]
  (let [safe-to-verify (dissoc cfg
                               ::msg-specs/child-spawner!
                               ::msg-specs/->child)]
    (println "Validating pre-state options\n"
             (util/pretty safe-to-verify))
    (s/describe ::pre-state-options)
    (when-let [problem (s/explain-data ::pre-state-options safe-to-verify)]
      (throw (ex-info "Invalid state construction attempt" problem))))
  (println "Swapping out the logs")
  (swap! log-state-atom #(log/clean-fork % ::server))
  (println "Ready to receive client connections")
  (assoc cfg
         ::state/active-clients {}
         ::state/max-active-clients max-active-clients))
