(ns frereth-cp.client.state
  "Handle the inherently stateful pieces associated with the client side of things.

The fact that this is so big says a lot about needing to re-think my approach"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.schema :as schema]
            [frereth-cp.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def default-timeout 2500)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::chan->child ::schema/manifold-stream)
(s/def ::chan<-child ::schema/manifold-stream)
(s/def ::chan->server ::schema/manifold-stream)
(s/def ::chan<-server ::schema/manifold-stream)
(s/def ::release->child ::schema/manifold-stream)

(s/def ::recent nat-int?)
;; Periodically pull the client extension from...wherever it comes from.
;; Q: Why?
;; A: Has to do with randomizing and security, like sending from a random
;; UDP port. This will pull in updates when and if some mechanism is
;; added to implement that sort of thing.
;; Actually doing anything useful with this seems like it's probably
;; an exercise that's been left for later
(s/def ::client-extension-load-time nat-int?)

(s/def ::server-extension ::shared/extension)
(s/def ::server-long-term-pk ::shared/public-key)
;; TODO: Needs a real spec
;; Q: Is this the box that we decrypted with the server's
;; short-term public key?
;; Or is it the 96-byte black box that we send back as part of
;; the Vouch?
(s/def ::server-cookie any?)
;;; Q: Is there any reason at all to store this?
(s/def ::server-short-term-pk ::shared/public-key)
(s/def ::server-security (s/keys :req [::server-long-term-pk
                                       ;; Q: Is there a valid reason for this to live here?
                                       ;; I can discard it after sending the vouch, can't I?
                                       ::server-cookie
                                       ::shared/server-name
                                       ::server-short-term-pk]))

(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-long<->server-long
                                      ::client-short<->server-long
                                      ::client-short<->server-short]))

;; Q: What is this, and how is it used?
;; A: Well, it has something to do with messages from the Child to the Server.
;; c.f. client/extract-child-message
(s/def ::outgoing-message any?)

;; Because, for now, I need somewhere to hang onto the future
;; Q: So...what is this? a Future?
(s/def ::child any?)
;; The parts that change really need to be stored in a mutable
;; data structure.
;; An agent really does seem like it was specifically designed
;; for this.
;; Parts of this mutate over time. Others advance with the handshake
;; FSM. And others are really just temporary members.
;; I could also handle this with refs, but combining STM with
;; mutable byte arrays (which is where the "real work"
;; happens) seems like a recipe for disaster.
(s/def ::mutable-state (s/keys :req [::client-extension-load-time
                                     ::shared/extension
                                     ::outgoing-message
                                     ::shared/packet-management
                                     ::shared/recent
                                     ::server-security
                                     ::shared-secrets
                                     ::shared/work-area]
                               :opt [::child
                                     ;; Q: Why am I tempted to store this at all?
                                     ;; A: Well...I might need to resend it if it
                                     ;; gets dropped initially.
                                     ::vouch]))
(s/def ::immutable-value (s/keys :req [::shared/my-keys
                                       ;; Q: How do these mesh with netty's pipeline model?
                                       ;; For that matter, how much sense does the idea of
                                       ;; spawning a child process here?
                                       ::chan->server
                                       ::chan<-server
                                       ;; The circular declaration of this is very
                                       ;; suspicious.
                                       ::child-spawner
                                       ::server-extension
                                       ::timeout]))
(s/def ::state (s/merge ::mutable-state
                        ::immutable-value))

(s/def ::state-agent (s/and #(instance? clojure.lang.Agent %)
                            #(s/valid? ::state (deref %))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Implementation
;;; Q: How many (if any) of these really qualify?

(declare current-timeout)

(s/fdef fork
        :args (s/cat :wrapper ::state-agent)
        :ret ::state)
(defn fork
  "This has to 'fork' a child with access to the agent, and update the agent state

So, yes, it *is* weird.

It happens in the agent processing thread pool, during a send operation.

It's the child's responsibility to return a manifold.stream we can use to send it
bytes from the server.

It notifies us that it has bytes ready to process via the standard agent (send)
mechanism.

Although send-off might seem more appropriate, it probably isn't.

TODO: Need to ask around about that."
  [{:keys [::child-spawner]
    :as this}
   wrapper]
  (log/info "Spawning child!!")
  (when-not child-spawner
    (assert child-spawner (str "No way to spawn child.\nAvailable keys:\n"
                               (keys this))))
  (let [{:keys [::child ::reader ::release ::writer]} (child-spawner wrapper)]
    (log/info (str "Setting up initial read against the agent wrapping "
                   #_this
                   "\n...this...\naround\n"
                   child))
    ;; Q: Do these all *really* belong at the top level?
    ;; I'm torn between the basic fact that flat data structures
    ;; are easier (simpler?) and the fact that namespacing this
    ;; sort of thing makes collisions much less likely.
    ;; Not to mention the whole "What did I mean for this thing
    ;; to be?" question.
    (assoc this
           ::chan<-child writer
           ::release->child release
           ::chan->child reader
           ::child child
           ::read-queue clojure.lang.PersistentQueue/EMPTY)))

(defn decrypt-actual-cookie
  [{:keys [::shared/packet-management
           ::shared/work-area
           ::shared-secrets
           ::server-security]
    :as this}
   {:keys [::K/header
           ::K/client-extension
           ::K/server-extension
           ::K/client-nonce-suffix
           ::K/cookie]
    :as rcvd}]
  (log/info "Getting ready to try to extract cookie from" cookie)
  (let [{:keys [::shared/working-nonce
                ::shared/text]} work-area]
    (when-not working-nonce
      (log/error (str "Missing nonce buffer amongst\n"
                      (keys work-area)
                      "\nin\n"
                      (keys this)))
      (assert working-nonce))
    (log/info (str "Copying nonce prefix from\n"
                    K/cookie-nonce-prefix
                    "\ninto\n"
                    working-nonce))
    (b-t/byte-copy! working-nonce K/cookie-nonce-prefix)
    (.readBytes client-nonce-suffix
                working-nonce
                K/server-nonce-prefix-length
                K/server-nonce-suffix-length)

    (log/info "Copying encrypted cookie into " text "from" (keys this))
    (.readBytes cookie text 0 144)
    (let [shared (::client-short<->server-long shared-secrets)]
      (log/info (str "Trying to decrypt\n"
                      (with-out-str (b-s/print-bytes text))
                      "using nonce\n"
                      (with-out-str (b-s/print-bytes working-nonce))
                      "and shared secret\n"
                      (with-out-str (b-s/print-bytes shared))))
      ;; TODO: If/when an exception is thrown here, it would be nice
      ;; to notify callers immediately
      (try
        (let [decrypted (crypto/open-after text 0 144 working-nonce shared)
              extracted (shared/decompose K/cookie decrypted)
              server-short-term-pk (byte-array K/key-length)
              server-cookie (byte-array K/server-cookie-length)
              server-security (assoc (::server-security this)
                                     ::server-short-term-pk
                                     server-short-term-pk,
                                     ::server-cookie server-cookie)
              {:keys [::K/s' ::K/black-box]} extracted]
          (.readBytes s' server-short-term-pk)
          (.readBytes black-box server-cookie)
          (assoc this ::server-security server-security))
        (catch ExceptionInfo ex
          (log/error ex (str "Decryption failed:\n"
                             (util/pretty (.getData ex)))))))))

(defn decrypt-cookie-packet
  [{:keys [::shared/extension
           ::shared/packet-management
           ::server-extension]
    :as this}]
  (let [packet (::shared/packet packet-management)]
    ;; Q: How does packet length actually work?
    ;; A: We used to have the full length of the byte array here
    ;; Now that we don't, what's the next step?
    (when-not (= (.readableBytes packet) K/cookie-packet-length)
      (let [err {::expected-length K/cookie-packet-length
                 ::actual-length (.readableBytes packet)
                 ::packet packet
                 ;; Because the stack trace hides
                 ::where 'shared.curve.client/decrypt-cookie-packet}]
        (throw (ex-info "Incoming cookie packet illegal" err))))
    (log/debug (str "Incoming packet that looks like it might be a cookie:\n"
                   (with-out-str (shared/bytes->string packet))))
    (let [rcvd (shared/decompose K/cookie-frame packet)
          hdr (byte-array K/header-length)
          xtnsn (byte-array K/extension-length)
          srvr-xtnsn (byte-array K/extension-length)]
      ;; Reference implementation starts by comparing the
      ;; server IP and port vs. what we received.
      ;; Which we don't have here.
      ;; Q: Do we?
      ;; A: Not really. The original incoming message did have them,
      ;; under :host and :port, though.
      ;; TODO: Need to feed those down to here
      ;; That info's pretty unreliable/meaningless, but the server
      ;; address probably won't change very often.
      ;; Unless we're communicating with a server on someone's cell
      ;; phone.
      ;; Which, if this is successful, will totally happen.
      (log/warn "TODO: Verify that this packet came from the appropriate server")
      ;; Q: How accurate/useful is this approach?
      ;; (i.e. mostly comparing byte array hashes)
      ;; A: Not at all.
      ;; Well, it's slightly better than nothing.
      ;; But it's trivial to forge.
      ;; Q: How does the reference implementation handle this?
      ;; Well, the proof *is* in the pudding.
      ;; The most important point is whether the other side sent
      ;; us a cookie we can decrypt using our shared key.
      (.readBytes (::K/header rcvd) hdr)
      (.readBytes (::K/client-extension rcvd) xtnsn)
      (.readBytes (::K/server-extension rcvd) srvr-xtnsn)
      (log/info (str "Verifying that "
                     hdr
                     " looks like it belongs to a Cookie packet"))
      (when (and (b-t/bytes= K/cookie-header hdr)
                 (b-t/bytes= extension xtnsn)
                 (b-t/bytes= server-extension srvr-xtnsn))
        (decrypt-actual-cookie this rcvd)))))

(defn build-vouch
  [{:keys [::shared/packet-management
           ::shared/my-keys
           ::shared-secrets
           ::shared/work-area]
    :as this}]
  (let [{:keys [::shared/working-nonce
                ::shared/text]} work-area
        keydir (::shared/keydir my-keys)
        nonce-suffix (byte-array K/server-nonce-suffix-length)]
    (if working-nonce
      (do
        (log/info "Setting up working nonce " working-nonce)
        (b-t/byte-copy! working-nonce K/vouch-nonce-prefix)
        (shared/safe-nonce nonce-suffix keydir 0)
        (b-t/byte-copy! working-nonce
                        K/server-nonce-prefix-length
                        K/server-nonce-suffix-length nonce-suffix)

        (let [short-pair (::shared/short-pair my-keys)]
          (b-t/byte-copy! text 0 K/key-length (.getPublicKey short-pair)))
        (let [shared-secret (::client-long<->server-long shared-secrets)
              ;; This is the inner-most secret that the inner vouch hides.
              ;; I think the main point is to allow the server to verify
              ;; that whoever sent this packet truly has access to the
              ;; secret keys associated with both the long-term and short-
              ;; term key's we're claiming for this session.
              encrypted (crypto/box-after shared-secret
                                          text K/key-length working-nonce)
              vouch (byte-array K/vouch-length)]
          (log/info (str "Just encrypted the inner-most portion of the Initiate's Vouch\n"
                         "Nonce:\n"
                         (b-t/->string working-nonce)
                         "Shared long-long secret (FIXME: Don't log this):\n"
                         (b-t/->string shared-secret)))
          (b-t/byte-copy! vouch
                          0
                          (+ K/box-zero-bytes K/key-length)
                          encrypted)
          {::inner-i-nonce nonce-suffix
           ::vouch vouch}))
      (assert false (str "Missing nonce in packet-management:\n"
                         (keys packet-management))))))

(defn cookie->vouch
  "Got a cookie from the server.

  Replace those bytes
  in our packet buffer with the vouch bytes we'll use
  as the response.

  Handling an agent (send), which means `this` is already dereferenced"
  [this
   {:keys [host port message]
    :as cookie-packet}]
  (log/info (str "Getting ready to convert cookie\n"
                 (with-out-str (b-s/print-bytes message))
                 "into a Vouch"))
  (try
    (try
      (let [packet (get-in this
                           [::shared/packet-management
                            ::shared/packet])]
        (assert packet)
        (assert cookie-packet)
        ;; Don't even try to pretend that this approach is thread-safe
        (.clear packet)
        (.readBytes message packet 0 K/cookie-packet-length)
        ;; That doesn't modify the ByteBuf to let it know it has bytes
        ;; available
        ;; So force it.
        (.writerIndex packet K/cookie-packet-length))
      (catch NullPointerException ex
        (throw (ex-info "Error trying to copy cookie packet"
                        {::source cookie-packet
                         ::source-type (type cookie-packet)
                         ::packet-manager (::shared/packet-management this)
                         ::members (keys this)
                         ::this this
                         ::failure ex}))))
    (if-let [this (decrypt-cookie-packet this)]
      (let [{:keys [::shared/my-keys]} this
            server-short (get-in this
                                 [::server-security
                                  ::server-short-term-pk])]
        (log/debug "Managed to decrypt the cookie")
        (if server-short
          (let [this (assoc-in this
                               [::shared-secrets ::client-short<->server-short]
                               (crypto/box-prepare
                                server-short
                                (.getSecretKey (::shared/short-pair my-keys))))]
            (log/debug "Prepared shared short-term secret")
            ;; Note that this supplies new state
            ;; Though whether it should is debatable.
            ;; Q: why would I put this into ::vouch?
            ;; A: In case we need to resend it.
            ;; It's perfectly legal to send as many Initiate
            ;; packets as the client chooses.
            ;; This is especially important before the Server
            ;; has responded with its first Message so the client
            ;; can switch to sending those.
            (into this (build-vouch this)))
          (do
            (log/error (str "Missing server-short-term-pk among\n"
                            (keys (::server-security this))
                            "\namong bigger-picture\n"
                            (keys this)))
            (assert server-short))))
      (throw (ex-info
              "Unable to decrypt server cookie"
              this)))
    (finally
      (if message
        ;; Can't do this until I really done with its contents.
        ;; It acts as though readBytes into a ByteBuf just creates another
        ;; reference without increasing the reference count.
        ;; This seems incredibly brittle.
        (comment (.release message))
        (log/error "False-y message in\n"
                   cookie-packet
                   "\nQ: What happened?")))))

(defn load-keys
  [my-keys]
  (let [key-dir (::shared/keydir my-keys)
        long-pair (shared/do-load-keypair key-dir)
        short-pair (crypto/random-key-pair)]
    (log/info (str "Loaded long-term client key pair from '"
                   key-dir "'"))
    (assoc my-keys
           ::shared/long-pair long-pair
           ::shared/short-pair short-pair)))

(defn initialize-immutable-values
  "Sets up the immutable value that will be used in tandem with the mutable agent later"
  [this]
  ;; In theory, it seems like it would make sense to -> this through a chain of
  ;; these sorts of initializers.
  ;; In practice, as it stands, it seems a little silly.
  (update this ::shared/my-keys load-keys))

(defn initialize-mutable-state!
  [{:keys [::shared/my-keys
           ::server-security]
    :as this}]
  (let [long-pk (::server-long-term-pk server-security)]
    (when-not long-pk
      (throw (ex-info (str "Missing ::server-long-term-pk among"
                           (keys server-security))
                      {::this this}))))
  (let [server-long-term-pk (::server-long-term-pk server-security)
        long-pair (::shared/long-pair my-keys)
        short-pair (::shared/short-pair my-keys)
        long-shared  (crypto/box-prepare
                      server-long-term-pk
                      (.getSecretKey long-pair))]
    (log/info (str "Server long-term public key:\n"
                   (b-t/->string server-long-term-pk)
                   "My long-term public key:\n"
                   (b-t/->string (.getPublicKey long-pair))
                   "Combined, they produced this shared secret:\n"
                   (b-t/->string long-shared)))
    (into this
          {::child-packets []
           ::client-extension-load-time 0
           ::recent (System/nanoTime)
           ;; This seems like something that we should be able to set here.
           ;; djb's docs say that it's a security matter, like connecting
           ;; from a random port.
           ;; Hopefully, someday, operating systems will have some mechanism
           ;; for rotating these automatically
           ;; Q: Is nil really better than just picking something random
           ;; here?
           ;; A: Who am I to argue with one of the experts?
           ::shared/extension nil
           ::shared-secrets {::client-long<->server-long long-shared
                             ::client-short<->server-long (crypto/box-prepare
                                                           server-long-term-pk
                                                           (.getSecretKey short-pair))}
           ::server-security server-security})))

(defn ->message-exchange-mode
  "Just received first real response Message packet from the handshake.
  Now we can start doing something interesting."
  [{:keys [::chan<-server
           ::chan->server
           ::chan->child
           ::release->child
           ::chan<-child]
    :as this}
   wrapper
   initial-server-response]
  ;; I'm getting an ::interaction-test/timeout here
  (log/info "Initial Response from server:\n" initial-server-response)
  (if (not (keyword? (:message initial-server-response)))
    (if (and chan<-child chan->server)
      (do
        ;; Q: Do I want to block this thread for this?
        ;; A: As written, we can't. We're already inside an Agent$Action
        (comment (await-for (state/current-timeout wrapper) wrapper))

        ;; And then wire this up to pretty much just pass messages through
        ;; Actually, this seems totally broken from any angle, since we need
        ;; to handle decrypting, at a minimum.

        ;; And the send calls are totally wrong: I'm sure I can't just treat
        ;; the streams as functions
        ;; Important note about that "something better": it absolutely must take
        ;; the ::child ::read-queue into account.

        ;; Q: Do I want this or a plain consume?
        (strm/connect-via chan<-child #(send wrapper chan->server %) chan->server)

        ;; I'd like to just do this in final-wait and take out an indirection
        ;; level.
        ;; But I don't want children to have to know the implementation detail
        ;; that they have to wait for the initial response before the floodgates
        ;; can open.
        ;; So go with this approach until something better comes to mind
        (strm/connect-via chan<-server #(send wrapper chan->child %) chan->child)

        ;; Q: Is this approach better?
        ;; A: Well, at least it isn't total nonsense like what I wrote originally
        (comment (strm/consume (::chan<-child this)
                               (fn [bs]
                                 (send-off wrapper (fn [state]
                                                     (let [a
                                                           (update state ::child-packets
                                                                   conj bs)]
                                                       (send-messages! a))))))))
      (throw (ex-info (str "Missing either/both chan<-child and/or chan->server amongst\n" @this)
                      {::state this})))
    (log/warn "That response to Initiate was a failure")))

(defn final-wait
  "We've received the cookie and responded with a vouch.
  Now waiting for the server's first real message
  packet so we can switch into the message exchange
  loop"
  [this wrapper sent]
  (log/info "Entering [penultimate] final-wait")
  (if (not= sent ::sending-vouch-timed-out)
    (let [timeout (current-timeout wrapper)
          chan<-server (::chan<-server this)
          taken (strm/try-take! chan<-server
                                ::drained timeout
                                ::initial-response-timed-out)]
      ;; I have some comment rot here.
      ;; Big Q: Is the comment about waiting for the client's response
      ;; below correct? (The code doesn't look like it, but the behavior I'm
      ;; seeing implies a bug)
      ;; Or is the docstring above?
      (deferred/on-realized taken
        ;; Using send-off here because it potentially has to block to wait
        ;; for the child's initial message.
        ;; That really should have been ready to go quite a while before,
        ;; but "should" is a bad word.
        #(send-off wrapper (partial ->message-exchange-mode wrapper) %)
        (fn [ex]
          (send wrapper #(throw (ex-info "Server vouch response failed"
                                         (assoc % :problem ex)))))))
    (send wrapper #(throw (ex-info "Timed out trying to send vouch" %)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn current-timeout
  "How long should next step wait before giving up?"
  [wrapper]
  (-> wrapper deref ::timeout
      (or default-timeout)))

(defn clientextension-init
  "Starting from the assumption that this is neither performance critical
nor subject to timing attacks because it just won't be called very often."
  [{:keys [::client-extension-load-time
           ::shared/extension
           ::recent]
    :as this}]
  {:pre [(and client-extension-load-time recent)]}
  (let [reload (>= recent client-extension-load-time)
        _ (log/debug "curve.client/clientextension-init:"
                     reload
                     "(currently:"
                     extension
                     ") in"
                     (keys this))
        client-extension-load-time (if reload
                                     (+ recent (* 30 shared/nanos-in-second)
                                        client-extension-load-time))
        extension (if reload
                    (try (-> "/etc/curvecpextension"
                             ;; This is pretty inefficient...we really only want 16 bytes.
                             ;; Should be good enough for a starting point, though
                             slurp
                             (subs 0 16)
                             .getBytes)
                         (catch java.io.FileNotFoundException _
                           ;; This really isn't all that unexpected
                           (log/warn "Missing extension file")
                           (shared/zero-bytes 16)))
                    extension)]
    (assert (= (count extension) K/extension-length))
    (log/info "Loaded extension:" (vec extension))
    (assoc this
           ::client-extension-load-time client-extension-load-time
           ::shared/extension extension)))

(defn send-vouch!
  "Send the Vouch/Initiate packet (along with an initial Message sub-packet)

We may have to send this multiple times, because it could
very well get dropped.

Actually, if that happens, we probably need to start over
from the initial HELLO.

Depending on how much time we want to spend waiting for the
initial server message (this is one of the big reasons the
reference implementation starts out trying to contact
multiple servers).

It would be very easy to just wait
for its minute key to definitely time out, though that seems
like a naive approach with a terrible user experience.
"
  [this wrapper packet]
  (let [chan->server (::chan->server this)
        d (strm/try-put!
           chan->server
           packet
           (current-timeout wrapper)
           ::sending-vouch-timed-out)]
    ;; Note that this returns a deferred.
    ;; We're inside an agent's send.
    ;; Mixing these two paradigms was probably a bad idea.
    (deferred/on-realized d
      (fn [success]
        (log/info (str "Initiate packet sent: " success ".\nWaiting for 1st message"))
        (send-off wrapper final-wait wrapper success))
      (fn [failure]
        ;; Extremely unlikely, but
        ;; just for the sake of paranoia
        (log/error (str "Sending Initiate packet failed!\n" failure))
        (throw (ex-info "Timed out sending cookie->vouch response"
                        (assoc this
                               :problem failure)))))
    ;; Q: Do I need to hang onto that?
    this))

(defn update-client-short-term-nonce
  "Note that this can loop right back to a negative number."
  [^Long nonce]
  (let [result (unchecked-inc nonce)]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {:must "End communication immediately"})))
    result))

(defn wait-for-initial-child-bytes
  [{reader ::chan<-child
    :as this}]
  (log/info (str "wait-for-initial-child-bytes: " reader))
  ;; The redundant log message seems weird, but sometimes these
  ;; things look different
  (log/info "a.k.a." reader)
  (when-not reader
    (throw (ex-info "Missing chan<-child" {::keys (keys this)})))

  ;; The timeout here is a vital detail here, in terms of
  ;; UX responsiveness.
  ;; Half a second seems far too long for the child to
  ;; build its initial message bytes.
  ;; Reference implementation just waits forever.
  @(deferred/let-flow [available (strm/try-take! reader
                                                 ::drained
                                                 (util/minute)
                                                 ::timed-out)]
     (log/info "waiting for initial-child-bytes returned" available)
     (if-not (keyword? available)
       available   ; i.e. success
       (if-not (= available ::drained)
         (if (= available ::timed-out)
           (throw (RuntimeException. "Timed out waiting for child"))
           (throw (RuntimeException. (str "Unknown failure: " available))))
         ;; I have a lot of interaction-test/handshake runs failing because
         ;; of this.
         ;; Q: What's going on?
         ;; (I can usually re-run the test and have it work the next
         ;; time through...it almost seems like a 50/50 thing)
         (throw (RuntimeException. "Stream from child closed"))))))
