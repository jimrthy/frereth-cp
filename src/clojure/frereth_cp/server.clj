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

(s/def ::handle (s/keys :req [::max-active-clients
                              ::shared/extension
                              ::shared/my-keys
                              ::shared/working-area
                              ::state/active-clients
                              ::state/current-client
                              ::state/client-read-chan
                              ::state/client-write-chan]
                        :opt [::event-loop-stopper
                              ::shared/packet-management
                              ::state/cookie-cutter]))

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

(defn handle-hello!
  [state
   {:keys [:message]
    :as packet}]
  (when-let [cookie-recipe (hello/do-handle state message)]
    (let [^ByteBuf cookie (cookie/do-build-cookie-response state cookie-recipe)]
      (log/info (str "Cookie packet built. Sending it."))
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
                                          ::timed-out)]
            (log/info "Cookie packet scheduled to send")
            (dfrd/on-realized put-future
                              (fn [success]
                                (if success
                                  (log/info "Sending Cookie succeeded")
                                  (log/error "Sending Cookie failed"))
                                ;; TODO: Make sure this does get released!
                                ;; The caller has to handle that, though.
                                ;; It can't be released until after it's been put
                                ;; on the socket.
                                ;; Actually, aleph should release it after it
                                ;; puts it in the socket
                                (comment (.release cookie)))
                              (fn [err]
                                (log/error "Sending Cookie failed:" err)
                                (.release cookie)))
            state)
          (throw (ex-info "Missing destination"
                          (or (::state/client-write-chan state)
                              {::problem "No client-write-chan"
                               ::keys (keys state)
                               ::actual state}))))
        (catch Exception ex
          (log/error ex "Failed to send Cookie response")
          state)))))

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
        :args (s/cat :state ::state/state
                     :msg bytes?)
        :ret ::state/state)
(defn handle-incoming!
  "Packet arrived from client. Do something with it."
  [state
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
      (if (verify-my-packet state header server-extension)
        (do
          (log/debug "This packet really is for me")
          (let [packet-type-id (char (aget header (dec K/header-length)))]
            (log/info "Incoming packet-type-id: " packet-type-id)
            (try
              (case packet-type-id
                \H (handle-hello! state packet)
                \I (initiate/handle! state packet)
                \M (handle-message! state packet))
              (catch Exception ex
                (let [trace (.getStackTrace ex)]
                  (log/error ex (str "Failed handling packet type: "
                                     packet-type-id
                                     "\n"
                                     (util/show-stack-trace ex))))
                state))))
        (do (log/info "Ignoring packet intended for someone else")
            state)))
    (do
      (log/debug "Ignoring packet of illegal length")
      state)))

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
         :args (s/cat :this ::handle)
         :ret ::handle)
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
           ::event-loop-stopper (begin! almost)
           ::shared/packet-management (shared/default-packet-manager))))

(s/fdef stop!
        :args (s/cat :this ::handle)
        :ret ::handle)
(defn stop!
  "Stop the ioloop (but not the read/write channels: we don't own them)"
  [{:keys [::event-loop-stopper
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
                 ::event-loop-stopper nil)]
      (log/warn "Secrets hidden")
      outcome)
    (finally
      (shared/release-packet-manager! packet-management))))

(s/fdef ctor
        :args (s/cat :cfg (s/keys :opt [::max-active-clients]))
        :ret ::handle)
(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::max-active-clients]
    :or {max-active-clients default-max-clients}
    :as cfg}]
  (-> cfg
      (assoc ::state/active-clients (atom {})
             ::state/current-client (state/alloc-client)  ; Q: What's the point?
             ::max-active-clients max-active-clients
             ::shared/working-area (shared/default-work-area))))
