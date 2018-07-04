(ns frereth-cp.server
  "Implement the server half of the CurveCP protocol"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            ;; FIXME: Finish the switch to log2
            [clojure.tools.logging :as log]
            [frereth-cp.server
             [cookie :as cookie]
             [hello :as hello]
             [helpers :as helpers]
             [initiate :as initiate]
             [state :as state]]
            [frereth-cp
             [shared :as shared]
             [util :as util]]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log2]
             [specs :as specs]]
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

;; Note that this really only exists as an intermediate step for the
;; sake of producing a ::state/state.
(s/def ::pre-state (s/keys :req [::state/active-clients
                                 ::state/child-spawner!
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
                                 ::state/event-loop-stopper!
                                 ::shared/my-keys
                                 ::shared/packet-management]))

(let [common-state-option-keys [::log2/logger
                                ::log2/state
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
                                                #_::state/child-spawner!)))

  (s/def ::post-state-options (s/keys :req (conj common-state-option-keys ::state/max-active-clients))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef check-packet-length
        :args (s/cat :packet bytes?)
        :ret boolean?)
(defn check-packet-length
  "Could this packet possibly be a valid CurveCP packet, based on its size?"
  [^bytes packet]
  ;; So far, for unit tests, I'm getting the [B I expect
  ;; Note that this is actually wrong: I really should be
  ;; getting ByteBuf instances off the wire.
  ;; FIXME: Revisit this.
  ;; For that matter, I should convert this over to new-style logging.
  (log/debug (str "Incoming: " packet ", a " (class packet)))
  ;; For now, retain the name r for compatibility/historical reasons
  (let [r (count packet)]
    (log/info (str "Incoming packet contains " r " somethings"))
    (and (<= 80 r 1184)
         ;; i.e. (= (rem r 16) 0)
         ;; TODO: Keep an eye out for potential benchmarks
         ;; The compiler really should be smart enough so the
         ;; two are equivalent.
         (= (bit-and r 0xf) 0))))

;;; Q: Why isn't handle-hello! part of the hello ns?
;;; A: Because it needs access to cookie/do-build-cookie-response
;;; TODO: Add that as a callback param that I can set up in a
;;; partial and then move it there
(s/fdef handle-hello!
        :args (s/cat :state ::state/state
                     :packet ::shared/network-packet)
        :ret ::state/state)
(defn handle-hello!
  [{:keys [::log2/logger]
    :as state}
   {:keys [:message]
    :as packet}]
  (println "Top of handle-hello!")
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
        :args (s/cat :this ::state
                     ;; TODO: Be more specific about these
                     :header bytes?
                     ;; This has a spec def in both client.state
                     ;; and shared.constants.
                     ;; Neither one can possibly be right, can it?
                     ;; (I kind-of suspect that shared.constants
                     ;; has to do with a serialization template)
                     :server-extension bytes?)
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
        :args (s/cat :this ::state/state
                     :msg ::shared/network-packet)
        :ret ::state/state)
(defn handle-incoming!
  "Packet arrived from client. Do something with it."
  [{log-state ::log2/state
    :as this}
   {:keys [:host
           :port]
    ;; Q: How much performance do we really lose if we
    ;; set up the socket to send a B] rather than a ByteBuf?
    ^bytes message :message
    :as packet}]
  (println "Server incoming <---------------")
  (let [log-state (log2/do-sync-clock log-state)
        log-state (log2/debug log-state
                              ::handle-incoming!
                              "Top")]
    (when-not message
      (throw (ex-info "Missing message in incoming packet"
                      {::problem packet})))
    (if (check-packet-length message)
      (let [header (byte-array K/header-length)
            server-extension (byte-array K/extension-length)]
        (b-t/byte-copy! header 0 K/header-length message)
        (b-t/byte-copy! server-extension 0 K/extension-length message K/header-length)
        (if (verify-my-packet this header server-extension)
          (let [log-state (log2/debug log-state
                                      ::handle-incoming!
                                      "This packet really is for me")
                packet-type-id (char (aget header (dec K/header-length)))
                log-state (log2/info log-state
                                     ::handle-incoming!
                                     ""
                                     {::packet-type-id packet-type-id})
                this (assoc this ::log2/state log-state)]
            (println "Packet for me:" this)
            (try
              (.flush System/out)
              (case packet-type-id
                \H (handle-hello! this packet)
                \I (initiate/handle! this packet)
                \M (handle-message! this packet))
              (catch Exception ex
                (assoc this
                       ::log2/state (log2/exception log-state
                                                    ex
                                                    ::handle-incoming!
                                                    "Failed handling packet"
                                                    {::packet-type-id packet-type-id})))))
          (assoc this
                 ::log2/state (log2/info log-state
                                         ::handle-incoming!
                                         "Ignoring packet intended for someone else"))))
      (assoc this
             ::log2/state (log2/debug log-state
                                      ::handle-incoming!
                                      "Ignoring packet of illegal length"
                                      {::message-length (count message)
                                       ::shared/network-packet packet
                                       ::pretty (b-t/->string message)})))))

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
           ::log2/logger]
    log-state ::log2/state
    :as this}
   msg]
  (let [log-state (log2/info log-state
                             ::input-reducer
                             "Top of Server Event loop"
                             {::shared/network-packet msg
                              ::state/chan (::state/chan client-read-chan)
                              ::state/client-read-chan client-read-chan})
        result (case msg
                 ::stop (do (log2/flush-logs! logger (log2/warn log-state
                                                                ::input-reducer
                                                                "Received stop signal"))
                            (reduced ::exited))
                 ::rotate (let [log-state (log2/info log-state
                                                     ::input-reducer
                                                     "Possibly Rotating")]
                            (state/handle-key-rotation this))
                 ::drained (do
                             (log2/flush-logs! logger
                                               (log2/debug log-state
                                                           ::input-reducer
                                                           "Source drained"))
                             (reduced ::drained))
                 ;; Default is "Keep going"
                 (try
                   ;; Q: Do I want unhandled exceptions to be fatal errors?
                   (let [{log-state ::log2/state
                          :as modified-state} (handle-incoming! (assoc this
                                                                       ::log2/state log-state)
                                                                msg)
                         log-state (log2/info log-state
                                              ::input-reducer
                                              "Updated state based on incoming msg"
                                              (helpers/hide-long-arrays (dissoc modified-state ::log2/state)))]
                     (assoc modified-state
                            ::log2/state log-state))
                   (catch clojure.lang.ExceptionInfo ex
                     (assoc this
                            ::log2/state (log2/exception log-state
                                                         ex
                                                         ::input-reducer
                                                         "handle-incoming! failed")))
                   (catch RuntimeException ex
                     (log2/flush-logs! logger
                                       (log2/exception log-state
                                                       ex
                                                       "Unhandled low-level exception escaped handler"))
                     (reduced nil))
                   (catch Exception ex
                     (log2/flush-logs! logger
                                       (log2/exception log-state
                                                       ex
                                                       "Major problem escaped handler"))
                     (reduced nil))))]
    (if-let [log-state (::log2/state result)]
      (assoc result ::log2/state (log2/flush-logs! logger log-state))
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

(s/fdef begin!
        :args (s/cat :this ::state/state)
        :ret any?)
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
                                       :description "Periodically trigger cookie key rotation"})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef start!
         :args (s/cat :this ::pre-state)
         :ret ::state/state)
(defn start!
  "Start the server"
  [{:keys [::log2/logger
           ::state/client-read-chan
           ::state/client-write-chan
           ::shared/extension
           ::shared/my-keys]
    log-state ::log2/state
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
  (let [log-state (log2/warn log-state
                             ::start!
                             "CurveCP Server: Starting the server state")]

    ;; Reference implementation starts by allocating the active client structs.
    ;; This is one area where updating in place simply cannot be worth it.
    ;; Q: Can it?
    ;; A: Skip it, for now

    ;; So we're starting by loading up the long-term keys
    (let [keydir (::shared/keydir my-keys)
          long-pair (crypto/do-load-keypair keydir)
          this (assoc-in this [::shared/my-keys ::shared/long-pair] long-pair)
          almost (assoc this
                        ::state/cookie-cutter (state/randomized-cookie-cutter)
                        ::shared/packet-management (shared/default-packet-manager))
          log-state (log2/info log-state
                               ::start!
                               "Kicking off event loop."
                               {::shared/packet-management (::shared/packet-management almost)})
          ;; Q: What are the odds that the next two piece needs to do logging?
          ;; A: They're small and straight-forward enough that it doesn't really seem useful
          result (assoc almost
                        ::state/event-loop-stopper! (build-event-loop-stopper almost))
          flushed-logs (log2/flush-logs! logger log-state)
          began (begin! (assoc result ::log2/state (log2/clean-fork flushed-logs ::input-reducer)))]
      (assoc result ::log2/state flushed-logs))))

(s/fdef stop!
        :args (s/cat :this ::state/state)
        :ret ::post-state-options)
(defn stop!
  "Stop the ioloop (but not the read/write channels: we don't own them)"
  [{:keys [::log2/logger
           ::state/event-loop-stopper!
           ::shared/packet-management]
    log-state ::log2/state
    :as this}]
  (let [log-state (log2/do-sync-clock log-state)
        log-state (log2/warn log-state
                             ::stop!
                             "Stopping server state")]
    (try
      (let [log-state
            (if event-loop-stopper!
              (try
                (let [log-state (log2/flush-logs! logger (log2/info log-state
                                                                    ::stop!
                                                                    "Sending stop signal to event loop"))
                      ;; The caller needs to close the client-read-chan,
                      ;; which will effectively stop the ioloop by draining
                      ;; the reduce's source.
                      ;; This will signal it to stop directly.
                      ;; It's probably redudant, but feels safer.
                      stopped (event-loop-stopper!)]
                  (log2/debug log-state
                              ::stop!
                              "stopped"
                              {::side-effect-returned stopped}))
                (catch Exception ex
                  (log2/exception log-state
                                  ex
                                  ::stop!))
                (catch Throwable ex
                  (log2/exception log-state
                                  ex
                                  ::stop!
                                  "This was bad")
                  (throw ex)))
              (log2/debug log-state
                          ::stop!
                          "No stop method"))
            log-state (log2/flush-logs! logger (log2/warn log-state
                                                          ::stop!
                                                          "Clearing secrets"))
            outcome (-> (try
                             (state/hide-secrets! this)
                             (catch Exception ex
                               ;; Very tempting to split RuntimeException
                               ;; away from Exception. And then make Exception
                               ;; fatal
                               (update this ::log2/state
                                       #(log2/exception %
                                                        ex
                                                        ::stop!))))
                        (dissoc ::state/event-loop-stopper!
                                ;; This doesn't make any sense here anyway.
                                ;; But it's actually breaking my spec
                                ;; check.
                                ;; Somehow.
                                ::state/current-client))
            log-state (log2/warn log-state
                                 ::stop!
                                 "Secrets hidden")]
        (assoc outcome ::log2/state log-state))
      (catch Exception ex
        (log2/exception log-state
                        ex
                        ::stop!)))))

(s/fdef ctor
        :args (s/cat :cfg ::pre-state-options)
        :ret ::pre-state)
(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::state/max-active-clients]
    log-state ::log2/state
    :or {max-active-clients default-max-clients}
    :as cfg}]
  ;; Note that this is going to call the child state spawner.
  ;; Which really isn't what I want to have happen here at all.
  ;; Then again, I'm in the process of completely and totally
  ;; rethinking how this works, so it isn't worth addressing
  ;; until after I'm happy with the way the client approach
  ;; works.
  (when-let [problem (s/explain-data ::pre-state-options (dissoc cfg
                                                                 ::state/child-spawner!))]
    (throw (ex-info "Invalid state construction attempt" problem)))

  (let [log-state (log2/clean-fork log-state ::server)]
    (-> cfg
        (assoc ::state/active-clients {}
               ::state/max-active-clients max-active-clients
               ::shared/working-area (shared/default-work-area)))))
