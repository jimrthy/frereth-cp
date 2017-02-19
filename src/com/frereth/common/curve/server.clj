(ns com.frereth.common.curve.server
  "Implement the server half of the CurveCP protocol"
  (:require [clojure.spec :as s]
            ;; TODO: Really need millisecond precision (at least)
            ;; associated with this log formatter
            [clojure.tools.logging :as log]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream])
  (:import io.netty.buffer.Unpooled))

(def default-max-clients 100)
(def message-len 1104)
(def minimum-initiate-packet-length 560)
(def minimum-message-packet-length 112)

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
(s/def ::current-client ::client-state)

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
   packet]
  ;; Now I have a io.netty.buffer.UnpooledHeapByteBuf.
  ;; This changes things drastically.
  (let [pkt-vec (vec packet)
        rcvd-prfx (byte-array (subvec pkt-vec 0 (dec shared/header-length)))
        rcvd-xtn (subvec pkt-vec shared/header-length (+ shared/header-length
                                                         shared/extension-length))
        verified (not= 0
                       ;; Q: Why did DJB use a bitwise and here?
                       ;; (most likely current guess: it doesn't shortcut)
                       ;; And does that reason go away when you factor in the hoops I
                       ;; have to jump through to jump between bitwise and logical
                       ;; operations?
                       (bit-and (if (shared/bytes= (.getBytes shared/client-header-prefix)
                                                   rcvd-prfx)
                                  -1 0)
                                (if (shared/bytes= extension
                                                   (byte-array rcvd-xtn))
                                  -1 0)))]
    (when-not verified
      (log/warn "Dropping packet intended for someone else. Expected" (String. shared/client-header-prefix)
                "and" (vec extension)
                "\nGot" (String. rcvd-prfx) "and" rcvd-xtn))
    verified))

(defn prepare-cookie!
  [{:keys [::client-short<->server-long
           ::client-short-pk
           ::minute-key
           ::plain-text
           ::text
           ::working-nonce]}]
  (let [keys (shared/random-key-pair)
        ;; This is just going to get thrown away, leading
        ;; to potential GC issues.
        ;; Probably need another static buffer for building
        ;; and encrypting things like this
        buffer (Unpooled/buffer shared/server-cookie-length)]
    (assert (.hasArray buffer))
    (.writeBytes buffer shared/all-zeros 0 32)
    (.writeBytes buffer client-short-pk 0 shared/key-length)
    (.writeBytes buffer (.getSecretKey keys) 0 shared/key-length)

    (shared/byte-copy! working-nonce shared/cookie-nonce-minute-prefix)
    (shared/safe-nonce working-nonce nil shared/server-nonce-prefix-length)

    ;; Reference implementation is really doing pointer math with the array
    ;; to make this work.
    ;; It's encrypting from (+ plain-text 64) over itself.
    ;; There just isn't a good way to do the same thing in java.
    ;; (The problem, really, is that I have to copy the plaintext
    ;; so it winds up at the start of the array).
    ;; Note that this is a departure from the reference implementation!
    (let [actual (.array buffer)]
      (shared/secret-box actual actual shared/server-cookie-length working-nonce minute-key)
      ;; Copy that encrypted cookie into the text working area
      (.getBytes buffer 64 text)
      ;; Along with the nonce
      (shared/byte-copy! text 64 shared/server-nonce-suffix-length working-nonce shared/server-nonce-prefix-length)

      ;; And now we need to encrypt that.
      ;; This really belongs in its own function
      (shared/byte-copy! text 0 32 shared/all-zeros)
      (shared/byte-copy! text 32 shared/key-length (.getPublicKey keys))
      ;; Reuse the other 16 bytes
      (shared/byte-copy! working-nonce 0 shared/server-nonce-prefix-length shared/cookie-nonce-prefix)
      (.after client-short<->server-long text 0 160 working-nonce))))

(defn build-cookie-packet!
  [packet client-extension server-extension working-nonce text]
  (shared/compose shared/cookie-frame {::shared/header shared/cookie-header
                                       ::shared/client-extension client-extension
                                       ::shared/server-extension server-extension
                                       ::shared/nonce (Unpooled/wrappedBuffer working-nonce
                                                                              shared/server-nonce-prefix-length
                                                                              shared/server-nonce-suffix-length)
                                       ;; This is also a great big FAIL:
                                       ;; Have to drop the first 16 bytes
                                       ::shared/cookie (Unpooled/wrappedBuffer text
                                                                               shared/box-zero-bytes
                                                                               144)}
                  packet))

(defn handle-hello!
  [state packet]
  (when (= (count packet) shared/hello-packet-length)
    (let [;; Q: Is this worth the performance hit?
          {:keys [::shared/srvr-xtn ::shared/clnt-xtn ::clnt-short-pk]} (shared/decompose shared/hello-packet-dscr packet)
          client-short-pk (get-in state [::current-client ::client-security ::short-pk])]
      (shared/byte-copy! client-short-pk
                         0 shared/key-length clnt-short-pk)
      (let [shared-secret (shared/crypto-box-prepare clnt-short-pk
                                                     (-> state
                                                         (get-in [::shared/my-keys ::long-pair])
                                                         .getSecretKey))
            ;; Q: Is this worth doing?
            ;; (it generally seems like a terrible idea)
            state (assoc-in state [::current-client ::shared-secrets ::client-short<->server-long]
                            shared-secret)
            ;; Q: How do I combine these to handle this all at once?
            ;; I think I could do something like:
            ;; {:keys [{:keys [::text ::working-nonce] :as ::working-area}]} state
            ;; (that fails spec validation)
            ;; Better Q: Would that a good idea, if it worked?
            {:keys [::working-area]} state
            {:keys [::text ::working-nonce]} working-area
            minute-key (get-in state [::cookie-cutter ::minute-key])]
        (assert minute-key)
        (shared/byte-copy! working-nonce
                           shared/hello-nonce-prefix)
        (shared/byte-copy! working-nonce 16 8 packet 136)
        ;; Q: Does tweetnacl handle this for me?
        ;; (honestly: I mostly hope not).
        (shared/byte-copy! text 0 shared/box-zero-bytes shared/all-zeros)
        (shared/byte-copy! text shared/box-zero-bytes 80 packet 144)
        (if-let [plain-text (.open_after shared-secret text 0 96 working-nonce)]
          (do
            (prepare-cookie! {::client-short<->server-long shared-secret
                              ::client-short-pk clnt-short-pk
                              ::minute-key minute-key
                              ::plain-text plain-text
                              ::text text
                              ::working-nonce working-nonce})
            (build-cookie-packet! packet clnt-xtn srvr-xtn working-nonce text)
            (let [dst (::client-chan state)]
              ;; This seems like it must be wrong.
              ;; It wouldn't work for raw netty. That requires the actual
              ;; client channel associated with the incoming UDP packet
              ;; to be able to send a response.
              ;; This may be fine here, though it doesn't seem likely.
              ;; The basic approach is doomed to failure as soon as I
              ;; start sending back unsolicited packets.
              ;; Or is aleph doing something more clever under the covers
              ;; so each server instance winds up with its own "connected"
              ;; client socket?
              ;; That seems really dubious, but it would be nice if it
              ;; worked.
              (stream/put! dst packet)
              state))
          (do
            (log/warn "Garbage in: dropping")
            state))))))

(defn handle-initiate!
  [state packet]
  (when (>= (count packet) minimum-initiate-packet-length)
    (throw (ex-info "Don't stop here!"
                    {:what "Cope with vouch/initiate"}))))

(defn handle-message!
  [state packet]
  (when (>= (count packet) minimum-message-packet-length)
    (throw (ex-info "Don't stop here!"
                    {:what "Interesting part: incoming message"}))))

(s/fdef handle-incoming!
        :args (s/cat :state ::state
                     :msg bytes?)
        :ret ::state)
(defn handle-incoming!
  "Packet arrived from client. Do something with it."
  [state
   {:keys [host
           message
           port]
    :as packet}]
  (log/info "Incoming")
  (println "Check logs in *nrepl-server common* (or in the CLI where you're running things)")
  (if (and (check-packet-length message)
           (verify-my-packet state message))
    (do
      (log/info "This packet really is for me")
      ;; Wait, what? Why is this copy happening?
      ;; Didn't we just verify that this is already true?
      ;; TODO: I strongly suspect something like a copy/paste
      ;; failure on my part
      (shared/byte-copy! (get-in state [::current-client ::shared/extension])
                         0
                         shared/extension-length
                         message
                         (+ shared/header-length
                            shared/extension-length))
      (let [packet-type-id (char (aget packet (dec shared/header-length)))]
        (try
          (case packet-type-id
            \H (handle-hello! state packet)
            \I (handle-initiate! state packet)
            \M (handle-message! state packet))
          (catch Exception ex
            (log/error ex (str "Failed handling packet type: " packet-type-id))
            state))))
    (do
      (log/debug "Ignoring gibberish")
      state)))

;;; This next seems generally useful enough that I'm making it public.
;;; At least for now.
(declare hide-long-arrays)
(defn hide-secrets!
  [this]
  (log/info "Hiding secrets")
  ;; This is almost the top of the server's for(;;)
  ;; Missing step: reset timeout
  ;; Missing step: copy :minute-key into :last-minute-key
  ;; (that's handled by key rotation. Don't need to bother
  ;; if we're "just" cleaning up on exit)
  (let [minute-key-array (get-in this [::cookie-cutter ::minute-key])]
    (assert minute-key-array)
    (shared/random-bytes! minute-key-array))

  ;; Missing step: update cookie-cutter's next-minute
  ;; (that happens in handle-key-rotation)
  (let [p-m (::shared/packet-management this)]
    (shared/randomize-buffer! (::shared/packet p-m)))
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
    (log/info "Checking whether it's time to rotate keys or not")
    (let [now (System/nanoTime)
          next-minute (::next-minute cookie-cutter)
          _ (log/debug "next-minute:" next-minute "out of" (keys state)
                     "with cookie-cutter" cookie-cutter)
          timeout (- next-minute now)]
      (log/info "Top of handle-key-rotation. Remaining timeout:" timeout)
      (if (<= timeout 0)
        (let [timeout (one-minute now)]
          (log/info "Saving key for previous minute")
          (try
            (shared/byte-copy! (::last-minute-key cookie-cutter)
                               (::minute-key cookie-cutter))
            ;; Q: Why aren't we setting up the next minute-key here and now?
            (catch Exception ex
              (log/error "Key rotation failed:" ex "a" (class ex))))
          (log/warn "Saved key for previous minute. Hiding:")
          (assoc (hide-secrets! state)
                 ::timeout timeout))
        (assoc state ::timeout timeout)))
    (catch Exception ex
      (log/error "Rotation failed:" ex "\nStack trace:")
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
      (log/info "Top of Server event loop. Timeout: " (::timeout this) "in"
               #_(util/pretty (hide-long-arrays this))
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
          (log/debug (str "Top of Server Event loop received " msg
                        "\nfrom " (:chan client-chan)
                        "\nin " client-chan))
          (if-not (or (identical? ::drained msg)
                      (identical? ::timedout msg))
            (try
              ;; Q: Do I want unhandled exceptions to be fatal errors?
              (let [modified-state (handle-incoming! this msg)]
                (log/debug "Updated state based on incoming msg:"
                         (hide-long-arrays modified-state))
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
              (log/debug "Server recv from" (:chan client-chan) ":" msg)
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
                  (log/debug "Rotating"
                           #_(util/pretty (hide-long-arrays this))
                           "...this...")
                  (deferred/recur (handle-key-rotation this)))
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
  "Try to make pretty printing less obnoxious

  By hiding the vectors that take up huge amounts of screen space"
  [state]
  (-> state
      (assoc-in [::current-client ::message] "...")
      (assoc-in [::shared/packet-management ::shared/packet] "...")
      (assoc-in [::shared/my-keys ::shared/server-name] "...decode this...")
      (assoc #_[::message "..."]
             ::shared/working-area "...")))

(defn start!
  [{:keys [::client-chan
           ::shared/extension
           ::shared/my-keys]
    :as this}]
  {:pre [client-chan
         (:chan client-chan)
         (::shared/server-name my-keys)
         (::shared/keydir my-keys)
         extension
         ;; Actually, the rule is that it must be
         ;; 32 hex characters. Which really means
         ;; a 16-byte array
           (= (count extension) shared/extension-length)]}
  (log/warn "CurveCP Server: Starting the server state")

  ;; Reference implementation starts by allocating the active client structs.
  ;; This is one area where updating in place simply cannot be worth it.
  ;; Q: Can it?
  ;; A: Skip it, for now


  ;; So we're starting by loading up the long-term keys
  (let [keydir (::shared/keydir my-keys)
        long-pair (shared/do-load-keypair keydir)
        this (assoc-in this [::shared/my-keys ::shared/long-pair] long-pair)
        almost (assoc this ::cookie-cutter (randomized-cookie-cutter))]
    (log/info "Kicking off event loop. packet-management:" (::shared/packet-management almost))
    (assoc almost ::event-loop-stopper (begin! almost))))

(defn stop!
  [{:keys [::event-loop-stopper]
    :as this}]
  (log/warn "Stopping server state")
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
                 (hide-secrets! this)
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
