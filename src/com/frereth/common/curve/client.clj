(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS.

  This really doesn't seem to belong in here. I keep going
  back and forth about that. It seems like it would be
  cleaner to move this into the frereth.client, and the
  server component into frereth.server.

  But that makes it much more difficult to test."
  (:require [byte-streams :as b-s]
            [clojure.core.async :as async]
            [clojure.pprint :refer (pprint)]
            [clojure.spec :as s]
            [clojure.tools.logging :as log]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]
            [com.frereth.common.curve.shared.crypto :as crypto]
            [com.frereth.common.curve.shared.constants :as K]
            [com.frereth.common.schema :as schema]
            [com.frereth.common.util :as util]
            [com.stuartsierra.component :as cpt]
            [manifold.deferred :as deferred]
            ;; Mixing this and core.async seems dubious, at best
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def default-timeout 2500)
(def heartbeat-interval (* 15 shared/millis-in-second))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;; Q: More sensible to check for strm/source and sink protocols?
(s/def ::chan->child ::schema/manifold-stream)
(s/def ::chan<-child ::schema/manifold-stream)
(s/def ::chan->server ::schema/manifold-stream)
(s/def ::chan<-server ::schema/manifold-stream)

;; Periodically pull the client extension from...wherever it comes from.
;; Q: Why?
;; A: Has to do with randomizing and security, like sending from a random
;; UDP port. This will pull in updates when and if some mechanism is
;; added to implement that sort of thing.
;; Actually doing anything useful with this seems like it's probably
;; an exercise that's been left for later
(s/def ::client-extension-load-time integer?)

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
(s/def ::outgoing-message any?)

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

;; Because, for now, I need somewhere to hang onto the future
;; Q: So...what is this? a Future?
(s/def ::child any?)

(s/def ::reader (s/keys :req [::chan<-child]))
(s/def ::writer (s/keys :req [::chan->child]))
;; This stream is for sending ByteBufs back to the child when we're done
;; Tracking them in a thread-safe pool seems like a better approach.
;; Especially when we're talking about the server.
;; But I have to get a first draft written before I can worry about details
;; like that.
;; Actually, I pretty much have to have access to that pool now, so messages
;; can go the other way.
;; I could try to get clever and try to reuse buffers when we have a basic
;; request/response scenario. But that idea totally falls apart if the
;; communication is mostly one-sided.
;; It's available as a potential optimization, but it probably only
;; makes sense from the "child" perspective, where we have more knowledge
;; about the expected traffic patterns.
;; TODO: Switch to PooledByteBufAllocator
;; Instead of mucking around with this release-notifier nonsense
(s/def ::release ::writer)
;; Accepts the agent that owns "this" and returns
;; 1) a writer channel we can use to send messages to the child.
;; 2) a reader channel that the child will use to send byte
;; arrays/bufs to us
(s/def ::child-spawner (s/fspec :args (s/cat :this ::state-agent)
                                :ret (s/keys :req [::child
                                                   ::reader
                                                   ::release
                                                   ::writer])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn current-timeout
  "How long should next step wait before giving up?"
  [wrapper]
  (-> wrapper deref ::timeout
      (or default-timeout)))

(defn hide-long-arrays
  "Make pretty printing a little less verbose"
  [this]
  ;; In some scenarios, we're winding up with the client as a
  ;; deferred.
  ;; This is specifically happening when my interaction test
  ;; throws an unhandled exception.
  ;; I probably shouldn't do this to try to work around that problem,
  ;; but I really want/need as much debug info as I can get in
  ;; that sort of scenario
  (let [this (if (associative? this)
               this
               (try
                 (assoc @this ::-hide-long-array-notice "This was a deferred")
                 (catch java.lang.ClassCastException ex
                   (throw (ex-info (str @this ": deferred that breaks everything")
                                   {:cause (str ex)})))))]
    (-> this
        ;; TODO: Write a mirror image version of dns-encode to just show this
        (assoc-in [::server-security ::shared/server-name] "name")
        (assoc-in [::shared/packet-management ::shared/packet] "...packet bytes...")
        (assoc-in [::shared/work-area ::shared/working-nonce] "...FIXME: Decode nonce bytes")
        (assoc-in [::shared/work-area ::shared/text] "...plain/cipher text"))))

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

(defn update-client-short-term-nonce
  "Note that this can loop right back to a negative number."
  [^Long nonce]
  (let [result (unchecked-inc nonce)]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {:must "End communication immediately"})))
    result))

(defn build-raw-hello
  [{:keys [::server-extension
           ::shared/extension
           ::shared/my-keys
           ::shared-secrets]
    :as this}
   short-term-nonce
   working-nonce]

  (let [my-short<->their-long (::client-short<->server-long shared-secrets)
        _ (assert my-short<->their-long)
        ;; Note that this definitely inserts the 16-byte prefix for me
        boxed (crypto/box-after my-short<->their-long
                                shared/all-zeros (- K/hello-crypto-box-length K/box-zero-bytes) working-nonce)
        msg (str "Hello crypo-box:\n"
                 (with-out-str (b-s/print-bytes boxed))
                 "\nencrypted with nonce\n"
                 (with-out-str (b-s/print-bytes working-nonce))
                 "\nfrom\n"
                 (with-out-str (-> my-keys
                                   ::shared/short-pair
                                   .getPublicKey
                                   b-s/print-bytes))
                 "\nto\n"
                 (with-out-str (b-s/print-bytes (get-in this [::server-security
                                                              ::server-long-term-pk])))
                 "\nshared\n"
                 (with-out-str (b-s/print-bytes my-short<->their-long)))]
    (log/info msg)
    {::K/prefix shared/hello-header
     ::K/srvr-xtn server-extension
     ::K/clnt-xtn extension
     ::K/clnt-short-pk (.getPublicKey (::shared/short-pair my-keys))
     ::K/zeros nil
     ::K/client-nonce-suffix (b-t/sub-byte-array working-nonce K/client-nonce-prefix-length)
     ::K/crypto-box boxed}))

(s/fdef build-actual-hello-packet
        :args (s/cat :this ::state
                     ;; TODO: Verify that this is a long
                     :short-nonce integer?
                     :working-nonce bytes?)
        :ret ::state)
(defn build-actual-hello-packet
  [{:keys [::shared/packet-management]
    :as this}
   short-term-nonce
   working-nonce]
  (assert packet-management)
  (let [raw-hello (build-raw-hello this short-term-nonce working-nonce)
        {packet ::shared/packet} packet-management]
    (assert packet)
    (log/info (str "Building Hello based on\n"
                   "Description:\n\t" (with-out-str (pprint K/hello-packet-dscr))
                   "\nRaw:\n\t" (with-out-str (pprint raw-hello))
                   "\nPacket:\n\t" packet))
    (shared/compose K/hello-packet-dscr raw-hello packet)))

(defn do-build-hello
  "Puts plain-text hello packet into packet-management

Note that this is really called for side-effects"
  [{:keys [
           ::shared/packet-management

           ::shared/work-area]
    :as this}]
  (let [this (clientextension-init this) ; There's a good chance this updates my extension
        working-nonce (::shared/working-nonce work-area)
        {:keys [::shared/packet-nonce ::shared/packet]} packet-management
        short-term-nonce (update-client-short-term-nonce packet-nonce)]
    (b-t/byte-copy! working-nonce shared/hello-nonce-prefix)
    (b-t/uint64-pack! working-nonce K/client-nonce-prefix-length short-term-nonce)
    (log/info (str short-term-nonce " packed into\n"
                   (with-out-str (b-s/print-bytes working-nonce))))

    (let [packet (build-actual-hello-packet this short-term-nonce working-nonce)]
      (update this ::shared/packet-management
              (fn [current]
                (assoc current
                       ::shared/packet-nonce short-term-nonce
                       ::shared/packet (b-s/convert packet io.netty.buffer.ByteBuf)))))))

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
              extracted (shared/decompose K/cookie (Unpooled/wrappedBuffer (byte-array decrypted)))
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
        keydir (::shared/keydir my-keys)]
    (if working-nonce
      (do
        (log/info "Setting up working nonce " working-nonce)
        (b-t/byte-copy! working-nonce K/vouch-nonce-prefix)
        (shared/safe-nonce working-nonce keydir K/client-nonce-prefix-length)

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
          (b-t/byte-copy! vouch
                          0
                          K/server-nonce-suffix-length
                          working-nonce
                          K/server-nonce-prefix-length)
          (b-t/byte-copy! vouch
                          K/server-nonce-suffix-length
                          (+ K/box-zero-bytes K/key-length)
                          encrypted
                          0)
          vouch))
      (assert false (str "Missing nonce in packet-management:\n"
                         (keys packet-management))))))

(defn extract-child-message
  "Pretty much blindly translated from the CurveCP reference
implementation. This is code that I don't understand yet"
  [this buffer]
  (let [reducer (fn [{:keys [buf
                             buf-len
                             msg
                             msg-len
                             i
                             this]
                      :as acc}
                     b]
                  (when (or (< msg-len 0)
                            ;; This is the flag that the stream has exited.
                            ;; Q: Is that what it's being used for here?
                            (> msg-len 2048))
                    (throw (ex-info "done" {})))
                  ;; It seems silly to set this and then check the first byte
                  ;; for the quit signal (assuming that's what it is)
                  ;; every time through the loop.
                  (aset msg msg-len (aget buf i))
                  (let [msg-len (inc msg-len)
                        length-code (aget msg 0)]
                    (when (bit-and length-code 0x80)
                      (throw (ex-info "done" {})))
                    (if (= msg-len (inc (* 16 length-code)))
                      (let [{:keys [extension
                                    my-keys
                                    packet-management
                                    server-extension
                                    shared-secrets
                                    server-security
                                    text
                                    vouch
                                    work-area]
                             :as this} (clientextension-init this)
                            {:keys [::shared/packet
                                    ::shared/packet-nonce]} packet-management
                            _ (throw (RuntimeException. "this Component nonce isn't updated"))
                            short-term-nonce (update-client-short-term-nonce
                                              packet-nonce)
                            working-nonce (:shared/working-nonce work-area)]
                        (b-t/uint64-pack! working-nonce K/client-nonce-prefix-length
                                             short-term-nonce)
                        ;; This is where the original splits, depending on whether
                        ;; we've received a message back from the server or not.
                        ;; According to the spec:
                        ;; The server is free to send any number of Message packets
                        ;; after it sees the Initiate packet.
                        ;; The client is free to send any number of Message packets
                        ;; after it sees the server's first Message packet.
                        ;; At this point in time, we know we're still building the
                        ;; Initiate packet.
                        ;; It's tempting to try to avoid duplication the same
                        ;; way the reference implementation does, by handling
                        ;; both logical branches here.
                        ;; And maybe there's a really good reason for doing so.
                        ;; But this function feels far too complex as it is.
                        (let [r (dec msg-len)]
                          (when (or (< r 16)
                                    (> r 640))
                            (throw (ex-info "done" {})))
                          (b-t/byte-copy! working-nonce 0 K/client-nonce-prefix-length
                                          K/initiate-nonce-prefix)
                          ;; Reference version starts by zeroing first 32 bytes.
                          ;; I thought we just needed 16 for the encryption buffer
                          ;; And that doesn't really seem to apply here
                          ;; Q: What's up with this?
                          ;; (it doesn't seem to match the spec, either)
                          (b-t/byte-copy! text 0 32 shared/all-zeros)
                          (b-t/byte-copy! text 32 K/key-length
                                          (.getPublicKey (::long-pair my-keys)))
                          (b-t/byte-copy! text 64 64 vouch)
                          (b-t/byte-copy! text
                                          128
                                          K/server-name-length
                                          (::K/server-name server-security))
                          ;; First byte is a magical length marker
                          ;; TODO: Double-check the original.
                          ;; This doesn't look right at all.
                          ;; I think I need a 32-byte offset for the decryption
                          ;; padding.
                          ;; And the call to open-after really seems like it should start
                          ;; at offset 384 instead of 0
                          (b-t/byte-copy! text 384 r msg 1)
                          (let [box (crypto/open-after (::client-short<->server-short shared-secrets)
                                                       text
                                                       0
                                                       (+ r 384)
                                                       working-nonce)
                                offset K/server-nonce-prefix-length]
                            ;; TODO: Switch to compose for this
                            (b-t/byte-copy! packet
                                            0
                                            offset
                                            K/initiate-header)
                            (b-t/byte-copy! packet offset
                                            K/extension-length server-extension)
                            (let [offset (+ offset K/extension-length)]
                              (b-t/byte-copy! packet offset
                                              K/extension-length extension)
                              (let [offset (+ offset K/extension-length)]
                                (b-t/byte-copy! packet offset K/key-length
                                                (.getPublicKey (::short-pair my-keys)))
                                (let [offset (+ offset K/key-length)]
                                  (b-t/byte-copy! packet
                                                  offset
                                                  K/server-cookie-length
                                                  (::server-cookie server-security))
                                  (let [offset (+ offset K/server-cookie-length)]
                                    (b-t/byte-copy! packet offset
                                                    K/server-nonce-prefix-length
                                                    working-nonce
                                                    K/server-nonce-suffix-length)))))
                            ;; Original version sends off the packet, updates
                            ;; msg-len to 0, and goes back to pulling data from child/server.
                            (throw (ex-info "How should this really work?"
                                            {:problem "Need to break out of loop here"})))))
                      (assoc acc :msg-len msg-len))))
        extracted (reduce reducer
                          {:buf (byte-array 4096)
                           :buf-len 0
                           :msg (byte-array 2048)
                           :msg-len 0
                           :i 0
                           :this this}
                          buffer)]
    (assoc this :outgoing-message (:child-msg extracted))))

(defn load-keys
  [my-keys]
  (let [long-pair (shared/do-load-keypair (::shared/keydir my-keys))
        short-pair (crypto/random-key-pair)]
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
  {:pre [(::server-long-term-pk server-security)]}
  (let [server-long-term-pk (::server-long-term-pk server-security)
        long-pair (::shared/long-pair my-keys)
        short-pair (::shared/short-pair my-keys)]
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
           ::shared-secrets {::client-long<->server-long (crypto/box-prepare
                                                          server-long-term-pk
                                                          (.getSecretKey long-pair))
                             ::client-short<->server-long (crypto/box-prepare
                                                           server-long-term-pk
                                                           (.getSecretKey short-pair))}
           ::server-security server-security})))

(defn child-exited!
  [this]
  (throw (ex-info "child exited" this)))

(defn hello-failed!
  [this failure]
  (send this #(throw (ex-info "Hello failed"
                              (assoc %
                                     :problem failure)))))

(defn hello-response-timed-out!
  [this failure]
  (send this #(throw (ex-info "Timed out waiting for hello response"
                              (assoc %
                                     :problem failure)))))

(defn server-closed!
  "This seems pretty meaningless in a UDP context"
  [this]
  (throw (ex-info "Server Closed" this)))

(defn child->server
  "Child sent us (as an agent) a signal to add bytes to the stream to the server"
  [this msg]
  (throw (RuntimeException. "Not translated")))

(defn server->child
  "Received bytes from the server that need to be streamed back to child"
  [this msg]
  (throw (RuntimeException. "Not translated")))

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
        (comment (await-for (current-timeout wrapper) wrapper))

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
      (throw (ex-info (str "Missing either/both chan<-child and/or chan->server amongst\n" (keys @this))
                      this)))
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
            (assoc this ::vouch (build-vouch this)))
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

(defn pull-initial-message-bytes
  [wrapper msg-byte-buf]
  (when msg-byte-buf
    (log/info "pull-initial-message-bytes ByteBuf:" msg-byte-buf)
    (let [bytes-available (K/initiate-message-length-filter (.readableBytes msg-byte-buf))]
      (when (< 0 bytes-available)
        (let [buffer (byte-array bytes-available)]
          (.readBytes msg-byte-buf buffer)
          ;; TODO: Compare performance against .discardReadBytes
          ;; A lot of the difference probably depends on hardware
          ;; choices.
          ;; Though, realistically, this probably won't be running
          ;; on minimalist embedded controllers for a while.
          (.discardSomeReadBytes msg-byte-buf)

          (if (< 0 (.readableBytes msg-byte-buf))
            ;; Reference implementation just fails on this scenario.
            ;; That seems like a precedent that I'm OK breaking.
            ;; The key for it is that (in the reference) there's another
            ;; buffer program sitting between
            ;; this client and the "real" child that can guarantee that this works
            ;; correctly.
            (send wrapper update ::read-queue conj msg-byte-buf)
            ;; I actually have a gaping question about performance here:
            ;; will I be able to out-perform java's garbage collector by
            ;; recycling used ByteBufs?
            ;; A: Absolutely not!
            ;; It was ridiculous to ever even contemplate.
            (strm/put! (::release->child @wrapper) msg-byte-buf))
          buffer)))))

(defn build-initiate-interior
  "This is the 368+M cryptographic box that's the real payload/Vouch+message portion of the Initiate pack"
  [this msg nonce-suffix]
  ;; Important detail: we can use up to 640 bytes that we've
  ;; received from the client/child.
  (let [msg-length (count msg)
        _ (assert (< 0 msg-length))
        tmplt (assoc-in K/vouch-wrapper [::K/child-message ::K/length] msg-length)
        server-name (get-in this [::shared/my-keys ::K/server-name])
        _ (assert server-name)
        src {::K/client-long-term-key (.getPublicKey (get-in this [::shared/my-keys ::shared/long-pair]))
             ::K/inner-vouch (::vouch this)
             ::K/server-name server-name
             ::K/child-message msg}
        work-area (::shared/work-area this)]
    ;; This seems to be dropping the child-message part.
    ;; Or maybe it's happening later on.
    ;; Wherever it's breaking between here and there, we're only putting together 368 bytes here
    ;; to send to the server.
    (shared/build-crypto-box tmplt
                             src
                             (::shared/text work-area)
                             (get-in this [::shared-secrets ::client-short<->server-short])
                             K/initiate-nonce-prefix
                             nonce-suffix)))

;; TODO: Surely I have a ByteBuf spec somewhere.
(s/fdef build-initiate-packet!
        :args (s/cat :this ::state
                     :msg-byte-buf #(instance? ByteBuf %))
        :fn #(= (count (:ret %)) (+ 544 (count (-> % :args :msg-byte-buf K/initiate-message-length-filter))))
        :ret #(instance? ByteBuf %))
(defn build-initiate-packet!
  "This is destructive in the sense that it reads from msg-byte-buf"
  [wrapper msg-byte-buf]
  (let [this @wrapper
        msg (pull-initial-message-bytes wrapper msg-byte-buf)
        work-area (::shared/work-area this)
        ;; Just reuse a subset of whatever the server sent us.
        ;; Legal because a) it uses a different prefix and b) it's a different number anyway
        nonce-suffix (b-t/sub-byte-array (::shared/working-nonce work-area) K/client-nonce-prefix-length)
        crypto-box (build-initiate-interior this msg nonce-suffix)]
    (log/debug (str "Stuffing " crypto-box " into the initiate packet"))
    (let [dscr (update-in K/initiate-packet-dscr [::K/vouch-wrapper ::K/length] + (count msg))
          fields #::K{:prefix K/initiate-header
                      :srvr-xtn (::server-extension this)
                      :clnt-xtn (::shared/extension this)
                      :clnt-short-pk (.getPublicKey (get-in this [::shared/my-keys ::shared/short-pair]))
                      :cookie (get-in this [::server-security ::server-cookie])
                      :nonce nonce-suffix
                      :vouch-wrapper crypto-box}]
      (shared/compose dscr
                      fields
                      (get-in this [::shared/packet-management ::shared/packet])))))

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

(defn build-and-send-vouch
"param wrapper: the agent that's managing the state
param cookie-packet: what arrived over the stream

The current implementation is based on the assumption that cookie-packet
is either a byte stream or a byte array.

And that I can just write the response byte-buffer back to the output
stream.

That assumption does not seem valid at all.

I have to have an address/port destination so the stream can know
where to route the message.

According to the Aleph docs, cookie-packet really should be a map that
includes :address and :port keys, along with the :message value which is
the actual byte-array (ByteBuf?).

That's what I've set up the server side to send, so that's what I'm
currently receiving here.

TODO: Need to validate that assumption.

To make matters worse, this entire premise is built around side-effects.

We send a request to the agent in wrapper to update its state with the
Vouch, based on the cookie packet. Then we do another send to get it to
send the vouch

This matches the original implementation, but it seems like a really
terrible approach in an environment that's intended to multi-thread."
  [wrapper cookie-packet]
  (if (and (not= cookie-packet ::hello-response-timed-out)
           (not= cookie-packet ::drained))
    (do
      (assert cookie-packet)
      (log/info "Received cookie in " wrapper ". Forking child")
      ;; Got a Cookie response packet from server.
      ;; Theory in the reference implementation is that this is
      ;; a good signal that it's time to spawn the child to do
      ;; the real work.
      ;; That really seems to complect the concerns.
      ;; Q: Why not set up the child in its own thread and start
      ;; listening for its activity now?
      ;; Partial Answer: original version is geared toward converting
      ;; existing apps that pipe data over STDIN/OUT so they don't
      ;; have to be changed at all.
      (send wrapper fork wrapper)

      ;; Once that that's ready to start doing its own thing,
      ;; cope with the cookie we just received.
      ;; Doing this statefully seems like a terrible
      ;; idea, but I don't want to go back and rewrite it
      ;; until I have a working prototype
      (log/info "send cookie->vouch")
      (send wrapper cookie->vouch cookie-packet)
      (let [timeout (current-timeout wrapper)]
        ;; Give the other thread(s) a chance to catch up and get
        ;; the incoming cookie converted into a Vouch
        (if (await-for timeout wrapper)
          (let [this @wrapper
                initial-bytes (wait-for-initial-child-bytes this)
                vouch (build-initiate-packet! wrapper initial-bytes)]
            (log/info "send-off send-vouch!")
            (send-off wrapper send-vouch! wrapper vouch))
          (do
            (log/error (str "Converting cookie to vouch took longer than "
                            timeout
                            " milliseconds.\nSwitching agent into an error state"))
            (send wrapper
                  #(throw (ex-info "cookie->vouch timed out" %)))))))
    (send wrapper #(throw (ex-info (str cookie-packet " waiting for Cookie")
                                   (assoc %
                                          :problem (if (= cookie-packet ::drained)
                                                     ::server-closed
                                                     ::response-timeout)))))))

(defn wait-for-cookie
  [wrapper sent]
  (if (not= sent ::sending-hello-timed-out)
    (do
      (log/info "client/wait-for-cookie -- Sent to server:" sent)
      (let [chan<-server (::chan<-server @wrapper)
            timeout (current-timeout wrapper)
            d (strm/try-take! chan<-server
                                ::drained
                                timeout
                                ::hello-response-timed-out)]
        (deferred/on-realized d
          (fn [cookie]
            (log/info "Incoming response from server:\n"
                      (with-out-str (pprint cookie)))
            (if-not (or (= cookie ::drained)
                        (= cookie ::hello-response-timed-out))
              (do
                (log/info "Building/sending Vouch")
                (build-and-send-vouch wrapper cookie))
              (log/error "Server didn't respond to HELLO.")))
          (partial hello-response-timed-out! wrapper))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))

(defn cope-with-successful-hello-creation
  [wrapper chan->server timeout]
  (let [raw-packet (get-in @wrapper
                           [::shared/packet-management
                            ::shared/packet])]
    (log/debug "client/start! Putting" raw-packet "onto" chan->server)
    ;; There's still an important break
    ;; with the reference implementation
    ;; here: this should be sending the
    ;; HELLO packet to multiple server
    ;; end-points to deal with them
    ;; going down.
    ;; I think it's supposed to happen
    ;; in a delayed interval, to give
    ;; each a short time to answer before
    ;; the next, but a major selling point
    ;; is not waiting for TCP buffers
    ;; to expire.
    (let [d (strm/try-put! chan->server
                           raw-packet
                           timeout
                           ::sending-hello-timed-out)]
      (deferred/on-realized d
        (partial wait-for-cookie wrapper)
        (partial hello-failed! wrapper)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef start!
        :args (s/cat :this ::state-agent)
        ;; Q: Does this return anything meaningful at all?
        ;; A: Well, to remain consistent with the Component workflow,
        ;; it really should return the "started" agent.
        ;; Even though it really is just called for side-effects.
        :ret any?)
(defn start!
  "This almost seems like it belongs in ctor.

But not quite, since it's really the first in a chain of side-effects.

Q: Is there something equivalent I can set up using core.async?

Actually, this seems to be screaming to be rewritten on top of manifold
Deferreds.

For that matter, it seems like setting up a watch on an atom that's
specifically for something like this might make a lot more sense.

That way I wouldn't be trying to multi-purpose communications channels.

OTOH, they *are* the trigger for this sort of thing.

The reference implementation mingles networking with this code.
That seems like it might make sense as an optimization,
but not until I have convincing numbers that it's needed.
Of course, I might also be opening things up for something
like a timing attack."
  [wrapper]
  (when-let [failure (agent-error wrapper)]
    (throw (ex-info "Agent failed before we started"
                    {:problem failure})))

  (let [{:keys [::chan->server]} @wrapper
        timeout (current-timeout wrapper)]
    (strm/on-drained chan->server
                     (fn []
                       (log/warn "Channel->server closed")
                       (send wrapper server-closed!)))
    ;; This feels inside-out and backwards.
    ;; But it probably should, since this is very
    ;; explicitly place-oriented programming working
    ;; with mutable state.
    (send wrapper do-build-hello)
    (if (await-for timeout wrapper)
      (cope-with-successful-hello-creation wrapper chan->server timeout)
      (throw (ex-info (str "Timed out after " timeout
                           " milliseconds waiting to build HELLO packet")
                      {:problem (agent-error wrapper)})))))

(defn stop!
  [wrapper]
  (if-let [err (agent-error wrapper)]
    (log/error (str err "\nTODO: Is there any way to recover well enough to release the Packet Manager?\n"
                    (.getStackTrace err)))
    (send wrapper
          (fn [this]
            (shared/release-packet-manager! (::shared/packet-management this))))))

(s/fdef ctor
        :args (s/keys :req [::chan<-server
                            ::chan->server
                            ::shared/my-keys
                            ::server-security])
        :ret ::state-agent)
(defn ctor
  [opts]
  (-> opts
      initialize-immutable-values
      initialize-mutable-state!
      (assoc
       ;; This seems very cheese-ball, but they
       ;; *do* need to be part of the agent.
       ;; We definitely don't want multiple threads
       ;; messing with them
       ::shared/packet-management (shared/default-packet-manager)
       ::shared/work-area (shared/default-work-area))
      ;; Using a core.async go-loop is almost guaranteed
      ;; to be faster.
      ;; TODO: Verify the "almost" with numbers.
      ;; The more I try to switching, the more dubious this
      ;; approach seems.
      ;; pipelines might not make a lot of sense on the client,
      ;; since they're at least theoretically about increasing
      ;; throughput at the expense of latency.
      ;; But they probably make a lot of sense on some servers.
      agent))
