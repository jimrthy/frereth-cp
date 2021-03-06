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

;; Note that this really only exists as an intermediate step for the
;; sake of producing a ::state/state.
(s/def ::pre-state (s/keys :req [::msg-specs/child-spawner!
                                 ::state/active-clients
                                 ::state/client-read-chan
                                 ::state/client-write-chan
                                 ::state/max-active-clients
                                 ::weald/logger
                                 ::weald/state
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
                                 ::state/event-loop-stopper!
                                 ::shared/my-keys]))

(let [common-state-option-keys [::weald/logger
                                ::weald/state
                                ::shared/extension
                                ;; Honestly, this should be an xor.
                                ;; It makes sense for the caller to
                                ;; supply one or the other, but not both.
                                (or ::shared/keydir ::shared/my-keys)
                                ;; Remember the distinction between these and
                                ;; the callbacks for sharing bytes with the child
                                ::state/client-read-chan
                                ::state/client-write-chan]]
  ;; These are the pieces that are used to put together the pre-state
  (s/def ::pre-state-options (s/keys :opt [::state/max-active-clients]
                                     :req (conj common-state-option-keys
                                                ;; Can't include the child-spawner! spec,
                                                ;; or checking it will spawn several children that we don't
                                                ;; really want.
                                                #_::msg-specs/child-spawner!
                                                ;; ditto
                                                #_::msg-specs/->child)))

  (s/def ::post-state-options (s/keys :req (conj common-state-option-keys ::state/max-active-clients))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef check-packet-length
  :args (s/cat :log-state ::weald/state
               :packet bytes?)
  :ret (s/keys :req [::weald/state
                     ::specs/okay?]))
(defn check-packet-length
  "Could this packet possibly be a valid CurveCP packet, based on its size?"
  [log-state packet]
  ;; So far, for unit tests, I'm getting the [B I expect
  ;; Note that this is actually wrong: I really should be
  ;; getting ByteBuf instances off the wire.
  ;; FIXME: Revisit this.
  (let [log-state (log/debug log-state
                             ::check-packet-length
                             "Incoming"
                             {::packet packet
                              ::packet-class (class packet)})
        packet (bytes packet)
        ;; For now, retain the name r for compatibility/historical reasons
        r (count packet)
        log-state (log/info log-state
                            ::check-packet-length
                            (str "Incoming packet contains " r " somethings"))]
    {::specs/okay? (and (<= 80 r 1184)
                        ;; TODO: Keep an eye out for potential benchmarks
                        ;; The compiler really should be smart enough so these next
                        ;; two are equivalent.
                        #_(= (bit-and r 0xf) 0)
                        (= (rem r 16) 0))
     ::weald/state log-state}))
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
  [{log-state ::weald/state
    :as this}
   {:keys [:host
           :port]
    message :message
    :as packet}]
  (let [log-state (-> log-state
                      log/do-sync-clock
                      (log/debug log-state
                                 ::do-handle-incoming
                                 "Server incoming <---------------"))
        ;; Q: How much performance do we really lose if we
        ;; set up the socket to send a B] rather than a ByteBuf?
        message (bytes message)]
    (when-not message
      (throw (ex-info "Missing message in incoming packet"
                      {::problem packet})))
    (let [{log-state ::weald/state
           :keys [::specs/okay?]} (check-packet-length log-state message)]
      (if okay?
        (let [header (byte-array K/header-length)
              server-extension (byte-array K/extension-length)]
          (b-t/byte-copy! header 0 K/header-length message)
          (b-t/byte-copy! server-extension 0 K/extension-length message K/header-length)
          (if (verify-my-packet this header server-extension)
            (let [log-state (log/debug log-state
                                       ::do-handle-incoming
                                       "This packet really is for me")
                  packet-type-id (char (aget header (dec K/header-length)))
                  log-state (log/info log-state
                                      ::do-handle-incoming
                                      ""
                                      {::packet-type-id packet-type-id})
                  this (assoc this ::weald/state (log/debug log-state
                                                            ::do-handle-incoming
                                                            "Packet for me"
                                                            (dissoc this ::weald/state)))
                  delta (try
                          (case packet-type-id
                            \H (hello/do-handle this
                                                cookie/do-build-response packet)
                            \I (initiate/do-handle this packet)
                            \M (do-handle-message this packet))
                          (catch Exception ex
                            {::weald/state (log/exception log-state
                                                          ex
                                                          ::do-handle-incoming
                                                          "Failed handling packet"
                                                          {::packet-type-id packet-type-id})}))]
              (as-> this x
                (into x delta)
                (update x
                       ::weald/state
                       log/debug
                       ::do-handle-incoming
                       "Handled")))
            (assoc this
                   ::weald/state (log/info log-state
                                           ::do-handle-incoming
                                           "Ignoring packet intended for someone else"))))
        (assoc this
               ::weald/state (log/debug log-state
                                        ::do-handle-incoming
                                        "Ignoring packet of illegal length"
                                        {::state/message-length (count message)
                                         ::shared/network-packet packet
                                         ::pretty (b-t/->string message)}))))))

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
    log-state ::weald/state
    :as this}
   msg]
  (let [log-state (log/info log-state
                            ::input-reducer
                            "Top of Server Event loop"
                            {::shared/network-packet msg
                             ::state/chan (::state/chan client-read-chan)
                             ::state/client-read-chan client-read-chan})
        result (case msg
                 ::stop (do (log/flush-logs! logger (log/warn log-state
                                                              ::input-reducer
                                                              "Received stop signal"))
                            (reduced ::exited))
                 ::rotate (let [log-state (log/info log-state
                                                    ::input-reducer
                                                    "Possibly Rotating")]
                            (state/handle-key-rotation this))
                 ::drained (do
                             (log/flush-logs! logger
                                              (log/debug log-state
                                                         ::input-reducer
                                                         "Source drained"))
                             (reduced ::drained))
                 ;; Default is "Keep going"
                 (try
                   ;; Q: Do I want unhandled exceptions to be fatal errors?
                   (let [{log-state ::weald/state
                          :as modified-state} (do-handle-incoming (assoc this
                                                                         ::weald/state log-state)
                                                                  msg)
                         log-state (log/info log-state
                                             ::input-reducer
                                             "Updated state based on incoming msg"
                                             (helpers/hide-long-arrays (dissoc modified-state ::weald/state)))]
                     (assoc modified-state
                            ::weald/state (log/flush-logs! logger log-state)))
                   (catch clojure.lang.ExceptionInfo ex
                     (assoc this
                            ::weald/state (log/exception log-state
                                                         ex
                                                         ::input-reducer
                                                         "handle-incoming! failed")))
                   (catch RuntimeException ex
                     (log/flush-logs! logger
                                      (log/exception log-state
                                                     ex
                                                     "Unhandled low-level exception escaped handler"))
                     (reduced nil))
                   (catch Exception ex
                     (log/flush-logs! logger
                                      (log/exception log-state
                                                     ex
                                                     "Major problem escaped handler"))
                     (reduced nil))))]
    (if-let [log-state (::weald/state result)]
      (assoc result ::weald/state (log/flush-logs! logger log-state))
      result)))

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
    :as this}]
  (let [in-chan (::state/chan client-read-chan)]
    (fn []
      @(strm/put! in-chan ::stop))))

(s/fdef do-begin
        :args (s/cat :this ::state/state)
        :ret ::weald/state)
(defn do-begin
  "Start the event loop"
  [{:keys [::state/client-read-chan]
    log-state ::weald/state
    :as this}]
  (let [log-state (log/info log-state
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
                                       :description "Periodically trigger cookie key rotation"})
    log-state))

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
    log-state ::weald/state
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
         log-state]}

  ;; Reference implementation starts by allocating the active client structs.
  ;; This is one area where updating in place simply cannot be worth it.
  ;; Q: Can it?
  ;; A: Skip it, for now
  (let [log-state (log/warn log-state
                            ::start!
                            "CurveCP Server: Starting the server state"
                            my-keys)
        ;; So we're starting by loading up the long-term keys
        keydir (::shared/keydir my-keys)
        {log-state ::weald/state
         long-pair ::crypto/java-key-pair} (crypto/do-load-keypair log-state keydir)
        this (assoc-in this [::shared/my-keys ::shared/long-pair] long-pair)
        almost (assoc this
                      ::state/cookie-cutter (state/randomized-cookie-cutter))
        log-state (log/info log-state
                            ::start!
                            "Kicking off event loop.")
        ;; Q: What are the odds that the next two piece needs to do logging?
        ;; A: They're small and straight-forward enough that it doesn't really seem useful
        base-result (assoc almost
                           ::state/event-loop-stopper! (build-event-loop-stopper almost))
        flushed-logs (log/flush-logs! logger log-state)
        result (assoc base-result ::weald/state flushed-logs)
        log-state (do-begin result)]
    (assoc result
           ::weald/state log-state)))

(s/fdef stop!
        :args (s/cat :this ::state/state)
        :ret ::post-state-options)
(defn stop!
  "Stop the ioloop (but not the read/write channels: we don't own them)"
  [{:keys [::weald/logger
           ::state/event-loop-stopper!]
    log-state ::weald/state
    :as this}]
  (let [log-state (log/do-sync-clock log-state)
        log-state (log/warn log-state
                            ::stop!
                            "Stopping server state")]
    (try
      (let [log-state
            (if event-loop-stopper!
              (try
                (let [log-state (log/flush-logs! logger (log/info log-state
                                                                  ::stop!
                                                                  "Sending stop signal to event loop"))
                      ;; The caller needs to close the client-read-chan,
                      ;; which will effectively stop the ioloop by draining
                      ;; the reduce's source.
                      ;; This will signal it to stop directly.
                      ;; It's probably redudant, but feels safer.
                      stopped (event-loop-stopper!)]
                  (log/debug log-state
                             ::stop!
                             "stopped"
                             {::side-effect-returned stopped}))
                (catch Exception ex
                  (log/exception log-state
                                 ex
                                 ::stop!))
                (catch Throwable ex
                  (log/exception log-state
                                 ex
                                 ::stop!
                                 "This was bad")
                  (throw ex)))
              (log/debug log-state
                         ::stop!
                         "No stop method"))
            log-state (log/flush-logs! logger (log/warn log-state
                                                        ::stop!
                                                        "Clearing secrets"))
            outcome (dissoc (try
                              (state/hide-secrets! this)
                              (catch Exception ex
                                ;; Very tempting to split RuntimeException
                                ;; away from Exception. And then make Exception
                                ;; fatal
                                (update this ::weald/state
                                        #(log/exception %
                                                        ex
                                                        ::stop!))))
                            ::state/event-loop-stopper!
                            ;; This doesn't make any sense here anyway.
                            ;; But it's actually breaking my spec
                            ;; check.
                            ;; Somehow.
                            ::state/current-client)

            log-state (log/warn log-state
                                ::stop!
                                "Secrets hidden")]
        (assoc outcome ::weald/state log-state))
      (catch Exception ex
        (log/exception log-state
                       ex
                       ::stop!)))))

(s/fdef ctor
        :args (s/cat :cfg ::pre-state-options)
        :ret ::pre-state)
(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::state/max-active-clients]
    log-state ::weald/state
    :or {max-active-clients default-max-clients}
    :as cfg}]
  ;; Note that this is going to call the child state spawner.
  ;; Which really isn't what I want to have happen here at all.
  ;; Then again, I'm in the process of completely and totally
  ;; rethinking how this works, so it isn't worth addressing
  ;; until after I'm happy with the way the client approach
  ;; works.
  (when-let [problem (s/explain-data ::pre-state-options (dissoc cfg
                                                                 ::msg-specs/child-spawner!
                                                                 ::msg-specs/->child))]
    (throw (ex-info "Invalid state construction attempt" problem)))

  (let [log-state (log/clean-fork log-state ::server)]
    (assoc cfg
           ::state/active-clients {}
           ::state/max-active-clients max-active-clients
           ::weald/state log-state)))
