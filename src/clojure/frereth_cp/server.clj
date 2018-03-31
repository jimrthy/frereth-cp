(ns frereth-cp.server
  "Implement the server half of the CurveCP protocol"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            ;; TODO: Really need millisecond precision (at least)
            ;; associated with this log formatter
            [clojure.tools.logging :as log]
            [frereth-cp.server.cookie :as cookie]
            [frereth-cp.server.hello :as hello]
            [frereth-cp.server.helpers :as helpers]
            [frereth-cp.server.initiate :as initiate]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.util :as util]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def default-max-clients 100)

;; Q: Do any of these really belong in here instead of shared.constants?
;; (minimum-initiate-packet-length seems defensible)
(def minimum-message-packet-length 112)

(def send-timeout
  "Milliseconds to wait for putting packets onto network queue"
  50)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;; This is probably too restrictive. And it seems a little
;;; pointless. But we have to have *some* way to identify
;;; them. Especially if I'm coping with address/port at a
;;; higher level.
(s/def ::child-id integer?)
;;; Note that this is probably too broad, assuming I choose to
;;; go with this model.
;;; From this perspective, from-child is really just sourceable?
;;; while to-child is just sinkable?
(s/def ::from-child (s/and strm/sinkable?
                           strm/sourceable?))
(s/def ::to-child (s/and strm/sinkable?
                         strm/sourceable?))

(s/def ::child-interaction (s/keys :req [::child-id
                                         ::to-child
                                         ::from-child]))

(s/def ::stopper dfrd/deferrable?)

;; Note that this really only exists as an intermediate step for the
;; sake of producing a ::state/state.
(s/def ::pre-state (s/keys :req [::state/active-clients
                                 ::state/child-spawner
                                 ::state/client-read-chan
                                 ::state/client-write-chan
                                 ::state/max-active-clients
                                 ::log2/logger
                                 ::log2/state
                                 ::shared/extension
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
                                 ::state/event-loop-stopper
                                 ::shared/my-keys
                                 ::shared/packet-management]))

;; These are the pieces that are used to put together the pre-state
(s/def ::pre-state-options (s/keys :opt [::state/max-active-clients]
                                   :req [::log2/logger
                                         ::log2/state
                                         ::shared/extension
                                         ::shared/keydir
                                         ::state/child-spawner
                                         ::state/client-read-chan
                                         ::state/client-write-chan]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef check-packet-length
        :args (s/cat :packet bytes?)
        :ret boolean?)
(defn check-packet-length
  "Could this packet possibly be a valid CurveCP packet, based on its size?"
  [^bytes packet]
  ;; So far, for unit tests, I'm getting the [B I expect
  (log/debug (str "Incoming: " packet ", a " (class packet)))
  ;; For now, retain the name r for compatibility/historical reasons
  (let [r (count packet)]
    (log/info (str "Incoming packet contains " r " bytes"))
    (and (<= 80 r 1184)
         ;; i.e. (= (rem r 16) 0)
         ;; TODO: Keep an eye out for potential benchmarks
         (= (bit-and r 0xf) 0))))

(s/fdef handle-hello!
        :args (s/cat :state ::state/state
                     :packet ::shared/network-packet)
        :ret ::state/state)
(defn handle-hello!
  [{:keys [::log2/logger]
    :as state}
   {:keys [:message]
    :as packet}]
  (when-let [{log-state ::log2/state
              :as cookie-recipe} (hello/do-handle state message)]
    (let [^ByteBuf cookie (cookie/do-build-cookie-response state cookie-recipe)
          log-state (log2/info log-state
                               ::handle-hello!
                               (str "Cookie packet built. Sending it."))]
      (try
        (if-let [dst (get-in state [::state/client-write-chan ::state/chan])]
          ;; And this is why I need to refactor this. There's so much going
          ;; on in here that it's tough to remember that this is sending back
          ;; a map. It has to, since that's the way aleph handles
          ;; UDP connections, but it really shouldn't need to: that's the sort
          ;; of tightly coupled implementation detail that I can push further
          ;; to the boundary.
          (let [put-future (strm/try-put! dst
                                          (assoc packet
                                                 :message cookie)
                                          ;; TODO: This really needs to be part of
                                          ;; state so it can be tuned while running
                                          send-timeout
                                          ::timed-out)
                log-state (log2/info log-state
                                     ::handle-hello!
                                     "Cookie packet scheduled to send")
                forked-log-state (log2/clean-fork log-state
                                                  ::hello-processed)]

            (dfrd/on-realized put-future
                              (fn [success]
                                (log2/flush-logs! logger
                                                   (if success
                                                     (log2/info forked-log-state
                                                                ::handle-hello!
                                                                "Sending Cookie succeeded")
                                                     (log2/error forked-log-state
                                                                 ::handle-hello!
                                                                 "Sending Cookie failed"))))
                              (fn [err]
                                (log2/flush-logs! logger
                                                  (log2/error forked-log-state
                                                              ::handle-hello!
                                                              "Sending Cookie failed:" err))))
            (assoc state
                   ::log2/state log-state))
          (throw (ex-info "Missing destination"
                          (or (::state/client-write-chan state)
                              {::problem "No client-write-chan"
                               ::keys (keys state)
                               ::actual state}))))
        (catch Exception ex

          (assoc state
                 ::log2/state
                 (log2/exception log-state
                                 ex
                                 ::handle-hello!
                                 "Failed to send Cookie response")))))))

(s/fdef verify-my-packet
        :args (s/cat :packet bytes?)
        :ret boolean?)
(defn verify-my-packet
  "Was this packet really intended for this server?"
  [{:keys [::shared/extension]}
   header
   rcvd-xtn]
  (let [rcvd-prfx (-> header
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
                                                rcvd-prfx)
                                  -1 0)
                                (if (b-t/bytes= extension
                                                rcvd-xtn)
                                  -1 0)))
        ;; TODO: Revisit the original and decide whether it's worth the trouble.
        ;; ALT: Compare the prefix as a vector. See how much of a performance hit we take
        verified (and (b-t/bytes= K/client-header-prefix
                                  rcvd-prfx)
                      (b-t/bytes= extension
                                  rcvd-xtn))]
    (when-not verified
      (log/warn "Dropping packet intended for someone else. Expected" (String. K/client-header-prefix)
                "and" (vec extension)
                "\nGot" (String. rcvd-prfx) "and" (vec rcvd-xtn)))
    verified))

(defn handle-message!
  [state packet]
  (when (>= (count packet) minimum-message-packet-length)
    (throw (ex-info "Don't stop here!"
                    {:what "Interesting part: incoming message"}))))

(s/fdef handle-incoming!
        :args (s/cat :this ::handle
                     :msg ::shared/network-packet)
        :ret ::state/state)
(defn handle-incoming!
  "Packet arrived from client. Do something with it."
  [this
   {:keys [:host
           :port]
    ;; Q: How much performance do we really use if we
    ;; set up the socket to send a B] rather than a ByteBuf?
    ^bytes message :message
    :as packet}]
  (log/debug "Top of Incoming handler")
  (when-not message
    (throw (ex-info "Missing message in incoming packet"
                    {::problem packet})))
  (if (check-packet-length message)
    (let [header (byte-array K/header-length)
          server-extension (byte-array K/extension-length)]
      (b-t/byte-copy! header 0 K/header-length message)
      (b-t/byte-copy! server-extension 0 K/extension-length message K/header-length)
      (if (verify-my-packet this header server-extension)
        (do
          (log/debug "This packet really is for me")
          (let [packet-type-id (char (aget header (dec K/header-length)))]
            (log/info "Incoming packet-type-id: " packet-type-id)
            (try
              ;; FIXME: Here's a glaring mismatch.
              ;; These and everything downstream from them
              ;; expect ::state/state.
              ;; But we're supplying ::handle.
              ;; Which is just different enough to break things
              ;; when I try to start logging.
              ;; But has limped along fine until this point.
              ;; Hypothesis: the two are basically copy/pasted.
              ;; I think I want to branch before I head any further down
              ;; this rabbit hole.
              (when-let [problem (s/explain-data ::state/state this)]
                (throw (ex-info "Type mismatch"
                                problem)))
              (case packet-type-id
                \H (handle-hello! this packet)
                \I (initiate/handle! this packet)
                \M (handle-message! this packet))
              (catch Exception ex
                (let [trace (.getStackTrace ex)]
                  (log/error ex (str "Failed handling packet type: "
                                     packet-type-id
                                     "\n"
                                     (util/show-stack-trace ex))))
                this))))
        (do (log/info "Ignoring packet intended for someone else")
            this)))
    (do
      (log/debug "Ignoring packet of illegal length")
      this)))

(s/fdef input-reducer
        :args (s/cat :this ::handle)
        :message (s/or :stop-signal #{::drained
                                      ::rotate
                                      ::stop}
                       :message ::shared/network-packet))
(defn input-reducer
  "Convert input into the next state"
  [{:keys [::state/client-read-chan]
    :as this}
   msg]
  (log/info (str "Top of Server Event loop received " msg
                 "\nfrom " (::state/chan client-read-chan)
                 "\nin " client-read-chan))
  (case msg
    ::stop (reduced (do
                      (log/warn "Received stop signal")
                      ::exited))
    ::rotate (do
               (log/info "Possibly Rotating"
                         #_(util/pretty (helpers/hide-long-arrays this))
                         "...this...")
               (state/handle-key-rotation this))
    ::drained (do
                (log/debug "Server recv from" (::state/chan client-read-chan) ":" msg)
                (reduced ::drained))
    ;; Default is "Keep going"
    (try
      ;; Q: Do I want unhandled exceptions to be fatal errors?
      (let [modified-state (handle-incoming! this msg)]
        (log/info "Updated state based on incoming msg:"
                  (helpers/hide-long-arrays modified-state))
        modified-state)
      (catch clojure.lang.ExceptionInfo ex
        (log/error "handle-incoming! failed" ex (.getStackTrace ex))
        this)
      (catch RuntimeException ex
        (log/error "Unhandled low-level exception escaped handler" ex (.getStackTrace ex))
        (reduced nil))
      (catch Exception ex
        (log/error "Major problem escaped handler" ex (.getStackTrace ex))
        (reduced nil)))))

(s/fdef begin!
        :args (s/cat :this ::handle)
        :ret ::stopper)
(defn begin!
  "Start the event loop"
  [{:keys [::state/client-read-chan]
    :as this}]
  (let [in-chan (::state/chan client-read-chan)
        ;; The part that handles input from the client
        finalized (strm/reduce input-reducer this in-chan)
        ;; Once a minute, signal rotation of the hidden symmetric key that handles cookie
        ;; encryption.
        key-rotator (strm/periodically (helpers/one-minute)
                                       (constantly ::rotate))]
    (strm/connect key-rotator in-chan {:upstream? true
                                       :description "Periodically trigger cookie key rotation"})
    (fn []
      @(strm/put! in-chan ::stop))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef start!
         :args (s/cat :this ::pre-state)
         :ret ::state/state)
(defn start!
  "Start the server"
  [{:keys [::state/client-read-chan
           ::state/client-write-chan
           ::shared/extension
           ::shared/my-keys]
    :as this}]
  {:pre [client-read-chan
         (::state/chan client-read-chan)
         client-write-chan
         (::state/chan client-write-chan)
         (::K/srvr-name my-keys)
         (::shared/keydir my-keys)
         extension
         ;; Actually, the rule is that it must be
         ;; 32 hex characters. Which really means
         ;; a 16-byte array
           (= (count extension) K/extension-length)]}
  (log/warn "CurveCP Server: Starting the server state")

  ;; Reference implementation starts by allocating the active client structs.
  ;; This is one area where updating in place simply cannot be worth it.
  ;; Q: Can it?
  ;; A: Skip it, for now

  ;; So we're starting by loading up the long-term keys
  (let [keydir (::shared/keydir my-keys)
        long-pair (crypto/do-load-keypair keydir)
        this (assoc-in this [::shared/my-keys ::shared/long-pair] long-pair)
        almost (assoc this ::state/cookie-cutter (state/randomized-cookie-cutter))]
    (log/info "Kicking off event loop. packet-management:" (::shared/packet-management almost))
    (assoc almost
           ::state/event-loop-stopper (begin! almost)
           ::shared/packet-management (shared/default-packet-manager))))

(s/fdef stop!
        :args (s/cat :this ::handle)
        :ret ::handle)
(defn stop!
  "Stop the ioloop (but not the read/write channels: we don't own them)"
  [{:keys [::state/event-loop-stopper
           ::shared/packet-management]
    :as this}]
  (log/warn "Stopping server state")
  (try
    (when event-loop-stopper
      (log/info "Sending stop signal to event loop")
      ;; The caller needs to close the client-read-chan,
      ;; which will effectively stop the ioloop by draining
      ;; the reduce's source.
      ;; This will signal it to stop directly.
      ;; It's probably redudant, but feels safer.
      (event-loop-stopper))
    (log/warn "Clearing secrets")
    (let [outcome
          (assoc (try
                   (state/hide-secrets! this)
                   (catch RuntimeException ex
                     (log/error "ERROR: " ex)
                     this)
                   (catch Exception ex
                     (log/fatal "FATAL:" ex)
                     ;; TODO: This really should be fatal.
                     ;; Make the error-handling go away once hiding secrets actually works
                     this))
                 ::state/event-loop-stopper nil)]
      (log/warn "Secrets hidden")
      outcome)
    (finally
      (shared/release-packet-manager! packet-management))))

(s/fdef ctor
        :args (s/cat :cfg ::pre-state-options)
        :ret ::pre-state)
(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::state/max-active-clients]
    log-state ::log2/state
    :or {max-active-clients default-max-clients}
    :as cfg}]
  (when-let [problem (s/explain-data ::pre-state-options cfg)]
    (throw (ex-info "Invalid state construction attempt" problem)))

  (let [log-state (log2/clean-fork log-state ::server)]
    (-> cfg
        (assoc ::state/active-clients (atom {})
               ;; Q: What's the point?
               ;; A: It makes some sense in C, when we're dealing with
               ;; a single block of memory.
               ;; It avoids a pointer dereference.
               ;; Here...not so much.
               ;; We aren't going to overwrite the memory block
               ;; holding the struct with a copy of the struct
               ;; currently being considered
               ;; FIXME: This is an optimization that's screaming
               ;; to be pruned.
               ::state/current-client (state/alloc-client)
               ::state/max-active-clients max-active-clients
               ::shared/working-area (shared/default-work-area)))))
