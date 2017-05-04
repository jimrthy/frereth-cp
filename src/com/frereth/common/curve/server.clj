(ns com.frereth.common.curve.server
  "Implement the server half of the CurveCP protocol"
  (:require [byte-streams :as b-s]
            [clojure.spec :as s]
            ;; TODO: Really need millisecond precision (at least)
            ;; associated with this log formatter
            [clojure.tools.logging :as log]
            [com.frereth.common.curve.server.hello :as hello]
            [com.frereth.common.curve.server.helpers :as helpers]
            [com.frereth.common.curve.server.initiate :as initiate]
            [com.frereth.common.curve.server.state :as state]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]
            [com.frereth.common.curve.shared.constants :as K]
            [com.frereth.common.curve.shared.crypto :as crypto]
            [com.frereth.common.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream])
  (:import clojure.lang.ExceptionInfo))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def default-max-clients 100)

;; Q: Do any of these really belong in here instead of shared.constants?
;; (minimum-initiate-packet-length seems defensible)
(def minimum-message-packet-length 112)

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
(s/def ::from-child (s/and stream/sinkable?
                           stream/sourceable?))
(s/def ::to-child (s/and stream/sinkable?
                         stream/sourceable?))

(s/def ::child-interaction (s/keys :req [::child-id
                                         ::to-child
                                         ::from-child]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef check-packet-length
        :args (s/cat :packet bytes?)
        :ret boolean?)
(defn check-packet-length
  "Could this packet possibly be a valid CurveCP packet, based on its size?"
  [packet]
  ;; So far, for unit tests, I'm getting the [B I expect
  (log/debug (str "Incoming: " packet ", a " (class packet)))
  ;; For now, retain the name r for compatibility/historical reasons
  (let [r (.readableBytes packet)]
    (log/info (str "Incoming packet contains " r " bytes"))
    (and (>= r 80)
         (<= r 1184)
         (= (bit-and r 0xf)))))

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
                       (bit-and (if (b-t/bytes= (.getBytes K/client-header-prefix)
                                                rcvd-prfx)
                                  -1 0)
                                (if (b-t/bytes= extension
                                                rcvd-xtn)
                                  -1 0)))
        ;; TODO: Revisit the original and decide whether it's worth the trouble.
        ;; ALT: Compare the prefix as a vector. See how much of a performance hit we take
        verified (and (b-t/bytes= (.getBytes K/client-header-prefix)
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
   {:keys [host
           message
           port]
    :as packet}]
  (log/debug "Incoming")
  (if (check-packet-length message)
    (let [header (byte-array K/header-length)
          extension (byte-array K/extension-length)
          current-reader-index (.readerIndex message)]
      (.readBytes message header)
      (.readBytes message extension)
      ;; This means that I'll wind up reading the header/extension
      ;; again in the individual handlers.
      ;; Which seems wasteful.
      ;; TODO: Set up alternative reader templates which
      ;; exclude those fields so I don't need to do this.
      (.readerIndex message current-reader-index)
      (if (verify-my-packet state header extension)
        (do
          (log/debug "This packet really is for me")
          (let [packet-type-id (char (aget header (dec K/header-length)))]
            (log/info "Incoming packet-type-id: " packet-type-id)
            (try
              (case packet-type-id
                \H (hello/handle! state packet)
                \I (initiate/handle! state packet)
                \M (handle-message! state packet))
              (catch Exception ex
                (log/error ex (str "Failed handling packet type: "
                                   packet-type-id
                                   "\n"
                                   (with-out-str (.printStackTrace ex))))
                state))))
        (do (log/info "Ignoring packet intended for someone else")
            state)))
    (do
      (log/debug "Ignoring packet of illegal length")
      state)))

(defn begin!
  "Start the event loop"
  [{:keys [::state/client-read-chan]
    :as this}]
  (let [stopper (deferred/deferred)
        stopped (promise)]
    (deferred/loop [this (assoc this
                                ::timeout (helpers/one-minute))]
      (log/info "Top of Server event loop. Timeout: " (::timeout this) "in"
               #_(util/pretty (helpers/hide-long-arrays this))
               "...[this]...")
      (deferred/chain
        ;; The timeout is in milliseconds, but state's timeout uses
        ;; the nanosecond clock
        (stream/try-take! (:chan client-read-chan)
                          ::drained
                          ;; Need to convert nanoseconds into milliseconds
                          (inc (/ (::timeout this) shared/nanos-in-milli))
                          ::timedout)
        (fn [msg]
          (log/info (str "Top of Server Event loop received " msg
                        "\nfrom " (:chan client-read-chan)
                        "\nin " client-read-chan))
          (if-not (or (identical? ::drained msg)
                      (identical? ::timedout msg))
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
                (comment this))
              (catch Exception ex
                (log/error "Major problem escaped handler" ex (.getStackTrace ex))))
            (do
              (log/debug "Server recv from" (:chan client-read-chan) ":" msg)
              (if (identical? msg ::drained)
                msg
                this))))
        ;; Chain the handler to a function that loops
        ;; Or not, if we're done
        (fn [this]
          (if this
            (if-not (identical? this ::drained)
              ;; Weren't called to explicitly close
              (if-not (realized? stopper)
                (do
                  ;; The promise that tells us to stop hasn't
                  ;; been fulfilled
                  (log/info "Possibly Rotating"
                           #_(util/pretty (helpers/hide-long-arrays this))
                           "...this...")
                  (deferred/recur (state/handle-key-rotation this)))
                (do
                  (log/warn "Received stop signal")
                  (deliver stopped ::exited)))
              (do
                (log/warn "Closing because client connection is drained")
                (deliver stopped ::drained)))
            (do
              (log/error "Exiting event loop because state turned falsey. Unhandled exception?")
              (deliver stopped ::failed))))))
    (fn [timeout]
      (when (not (realized? stopped))
        (deliver stopper ::exiting))
      (deref stopped timeout ::stopping-timed-out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn start!
  [{:keys [::state/client-read-chan
           ::state/client-write-chan
           ::shared/extension
           ::shared/my-keys]
    :as this}]
  {:pre [client-read-chan
         (:chan client-read-chan)
         client-write-chan
         (:chan client-write-chan)
         (::K/server-name my-keys)
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
        long-pair (shared/do-load-keypair keydir)
        this (assoc-in this [::shared/my-keys ::shared/long-pair] long-pair)
        almost (assoc this ::state/cookie-cutter (state/randomized-cookie-cutter))]
    (log/info "Kicking off event loop. packet-management:" (::shared/packet-management almost))
    (assoc almost
           ::event-loop-stopper (begin! almost)
           ::shared/packet-management (shared/default-packet-manager))))

(defn stop!
  [{:keys [::event-loop-stopper
           ::shared/packet-management]
    :as this}]
  (log/warn "Stopping server state")
  (try
    (when event-loop-stopper
      (log/info "Sending stop signal to event loop")
      ;; This is fairly pointless. The client channel Component on which this
      ;; depends will close shortly after this returns. That will cause the
      ;; event loop to exit directly.
      ;; But, just in case that doesn't work, this will tell the event loop to
      ;; exit the next time it times out.
      (event-loop-stopper 1))
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

(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::max-active-clients]
    :or {max-active-clients default-max-clients}
    :as cfg}]
  (-> cfg
      (assoc ::state/active-clients (atom #{})  ; Q: set or map?
             ::state/current-client (state/alloc-client)  ; Q: What's the point?
             ::max-active-clients max-active-clients
             ::shared/working-area (shared/default-work-area))))
