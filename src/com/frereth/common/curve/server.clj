(ns com.frereth.common.curve.server
  "Implement the server half of the CurveCP protocol"
  (:require [byte-streams :as b-s]
            [clojure.spec :as s]
            ;; TODO: Really need millisecond precision (at least)
            ;; associated with this log formatter
            [clojure.tools.logging :as log]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]
            [com.frereth.common.curve.shared.constants :as K]
            [com.frereth.common.curve.shared.crypto :as crypto]
            [com.frereth.common.util :as util]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream])
  (:import clojure.lang.ExceptionInfo
           io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def +cookie-send-timeout+ 50)
(def default-max-clients 100)
(def message-len 1104)
(def minimum-initiate-packet-length 560)
(def minimum-message-packet-length 112)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;; For maintaining a secret symmetric pair of encryption
;; keys for the cookies.
(s/def ::last-minute-key ::shared/symmetric-key)
(s/def ::minute-key ::shared/symmetric-key)
(s/def ::next-minute integer?)
(s/def ::cookie-cutter (s/keys :req [::next-minute
                                     ::minute-key
                                     ::last-minute-key]))

;; TODO: Move these public key specs into shared
(s/def ::crypto-key (s/and bytes?
                        #(= (count %) K/key-length)))
(s/def ::long-pk ::crypto-key)
(s/def ::short-pk ::crypto-key)
(s/def ::server-short-sk ::crypto-key)
(s/def ::client-security (s/keys :opt [::long-pk  ; Q: store this?
                                       ::short-pk
                                       ::server-short-sk]))

(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::client-long<->server-long ::shared/shared-secret)
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
(s/def ::client-read-chan (s/keys :req [::chan]))
(s/def ::client-write-chan (s/keys :req [::chan]))

(s/def ::client-state (s/keys :req [::child-interaction
                                    ::client-security
                                    ::shared/extension
                                    ::message
                                    ::message-len
                                    ::received-nonce
                                    ::sent-nonce
                                    ::shared-secrets]))
(s/def ::current-client ::client-state)

;; Q: Does this really need to be an atom?
(s/def ::active-clients (s/and #(instance? clojure.lang.Atom %)
                               #(map? %)))

(s/def ::state (s/keys :req [::active-clients
                             ::client-read-chan
                             ::client-write-chan
                             ::cookie-cutter
                             ::current-client
                             ::event-loop-stopper
                             ::max-active-clients
                             ::shared/extension
                             ::shared/keydir
                             ::shared/my-keys
                             ::shared/packet-management
                             ::K/server-name
                             ::shared/working-area]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef alloc-client
        :args (s/cat)
        :ret ::client-state)
(defn alloc-client
  []
  (let [interact {::child-id -1}
        sec {::long-pk (crypto/random-key)
             ::short-pk (crypto/random-key)}]
    {::child-interaction interact
     ::client-security sec
     ::shared/extension (crypto/random-bytes! (byte-array 16))
     ::message (crypto/random-bytes! (byte-array message-len))
     ::message-len 0
     ::received-nonce 0
     ::sent-nonce (crypto/random-nonce)}))

(defn one-minute
  ([]
   (* 60 shared/nanos-in-second))
  ([now]
   (+ (one-minute) now)))

(s/fdef find-client
        :args (s/cat :state ::state
                     ::client-short-key ::shared/public-key))
(defn find-client
  [state client-short-key]
  (-> state ::active-clients deref (get client-short-key)))

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

(defn prepare-cookie!
  [{:keys [::client-short<->server-long
           ::client-short-pk
           ::minute-key
           ::plain-text
           ::text
           ::working-nonce]}]
  "Called purely for side-effects.

The most important is that it encrypts plain-text
and puts the crypto-text into the byte-array in text"
  (let [keys (crypto/random-key-pair)
        ;; This is just going to get thrown away, leading
        ;; to potential GC issues.
        ;; Probably need another static buffer for building
        ;; and encrypting things like this
        buffer (Unpooled/buffer K/server-cookie-length)]
    (.retain buffer)
    (try
      (assert (.hasArray buffer))
      ;; TODO: Rewrite this using compose
      (.writeBytes buffer shared/all-zeros 0 K/decrypt-box-zero-bytes)
      (.writeBytes buffer client-short-pk 0 K/key-length)
      (.writeBytes buffer (.getSecretKey keys) 0 K/key-length)

      (b-t/byte-copy! working-nonce K/cookie-nonce-minute-prefix)
      (shared/safe-nonce working-nonce nil K/server-nonce-prefix-length)

      ;; Reference implementation is really doing pointer math with the array
      ;; to make this work.
      ;; It's encrypting from (+ plain-text 64) over itself.
      ;; There just isn't a good way to do the same thing in java.
      ;; (The problem, really, is that I have to copy the plaintext
      ;; so it winds up at the start of the array).
      ;; Note that this is a departure from the reference implementation!
      (let [actual (.array buffer)]
        (log/info (str "Before encrypting crypto-cookie, it looks like\n"
                       (with-out-str (b-s/print-bytes actual))))
        (crypto/secret-box actual actual K/server-cookie-length working-nonce minute-key)
        (log/info (str "Encrypted cookie starting at offset "
                       (.readerIndex buffer)
                       ":\n"
                       (with-out-str (b-s/print-bytes actual))
                       "which really should match\n"
                       (with-out-str (b-s/print-bytes buffer))))
        ;; Copy that encrypted cookie into the text working area
        (.getBytes buffer 0 text 32 K/server-cookie-length)
        (log/info (str "After copying " K/server-cookie-length " bytes of that into text,\n"
                       "starting at offset 32, "
                       "it looks like\n"
                       (with-out-str (b-s/print-bytes text))
                       "and the reader index has moved to "
                       (.readerIndex buffer)))
        ;; Along with the nonce
        ;; Note that this overwrites the first 16 bytes of the box we just wrapped.
        ;; Go with the assumption that those are the initial garbage 0 bytes that should
        ;; be discarded anyway
        (b-t/byte-copy! text 32 K/server-nonce-suffix-length working-nonce
                        K/server-nonce-prefix-length)

        ;; And now we need to encrypt that.
        ;; This really belongs in its own function
        ;; And it's another place where I should probably call compose
        (b-t/byte-copy! text 0 K/key-length (.getPublicKey keys))
        ;; Reuse the other 16 byte suffix that came in from the client
        (b-t/byte-copy! working-nonce
                        0
                        K/server-nonce-prefix-length
                        K/cookie-nonce-prefix)
        (let [cookie (crypto/box-after client-short<->server-long
                                       text
                                       ;; TODO: named const for this.
                                       128
                                       working-nonce)]
          (log/info (str "Full cookie going to client that it should be able to decrypt:\n"
                         (with-out-str (b-s/print-bytes cookie))
                         "using shared secret:\n"
                         (with-out-str (b-s/print-bytes client-short<->server-long))))
          cookie))
      (finally
        (.release buffer)))))

(defn build-cookie-packet
  [packet client-extension server-extension working-nonce crypto-cookie]
  (let [composed (shared/compose K/cookie-frame {::K/header K/cookie-header
                                                 ::K/client-extension client-extension
                                                 ::K/server-extension server-extension
                                                 ::K/nonce (Unpooled/wrappedBuffer working-nonce
                                                                                   K/server-nonce-prefix-length
                                                                                   K/server-nonce-suffix-length)
                                                 ::K/cookie crypto-cookie}
                                 packet)]
    ;; I really shouldn't need to do this
    ;; FIXME: Make sure it gets released
    (.retain composed)
    composed))

(defn open-hello-crypto-box
  [{:keys [::client-short-pk
           ::cookie-cutter
           ::nonce-suffix
           ::shared/my-keys
           ::shared/working-area]
    :as state}
   message
   crypto-box]
  (let [long-keys (::shared/long-pair my-keys)]
    (when-not long-keys
      ;; Log whichever was missing and throw
      (if my-keys
        (log/error "Missing ::shared/long-pair among" (keys my-keys))
        (log/error "Missing ::shared/my-keys among" (keys state)))
      (throw (ex-info "Missing long-term keypair" state)))
    (let [my-sk (.getSecretKey long-keys)
          shared-secret (crypto/box-prepare client-short-pk my-sk)
          ;; Q: How do I combine these to handle this all at once?
          ;; I think I should be able to do something like:
          ;; {:keys [{:keys [::text ::working-nonce] :as ::work-area}]}
          ;; state
          ;; (that fails spec validation)
          ;; Better Q: Would that a good idea, if it worked?
          ;; (Pretty sure this is/was the main thrust behind a plumatic library)
          {:keys [::shared/text ::shared/working-nonce]} working-area]
      (log/debug (str "Incoming HELLO\n"
                      "Client short-term PK:\n"
                      (with-out-str (b-s/print-bytes client-short-pk))
                      "\nMy long-term PK:\n"
                      (with-out-str (b-s/print-bytes (.getPublicKey long-keys)))))
      (b-t/byte-copy! working-nonce
                      shared/hello-nonce-prefix)
      (.readBytes nonce-suffix working-nonce K/client-nonce-prefix-length K/client-nonce-suffix-length)
      (.readBytes crypto-box text #_K/decrypt-box-zero-bytes 0 K/hello-crypto-box-length)
      (let [msg (str "Trying to open "
                     K/hello-crypto-box-length
                     " bytes of\n"
                     (with-out-str (b-s/print-bytes (b-t/sub-byte-array text 0 (+ 32 K/hello-crypto-box-length))))
                     "\nusing nonce\n"
                     (with-out-str (b-s/print-bytes working-nonce))
                     "\nencrypted from\n"
                     (with-out-str (b-s/print-bytes client-short-pk))
                     "\nto\n"
                     (with-out-str (b-s/print-bytes (.getPublicKey long-keys))))]
        (log/debug msg))
      {::opened (crypto/open-after
                 text
                 0
                 K/hello-crypto-box-length
                 working-nonce
                 shared-secret)
       ::shared-secret shared-secret})))

(defn handle-hello!
  [{:keys [::shared/working-area]
    :as state}
   {:keys [host message port]
    :as packet}]
  (log/debug "Have what looks like a HELLO packet")
  (if (= (.readableBytes message) shared/hello-packet-length)
    (do
      (log/info "This is the correct size")
      (let [;; Q: Is the convenience here worth the performance hit?
            {:keys [::K/clnt-xtn
                    ::K/clnt-short-pk
                    ::K/crypto-box
                    ::K/nonce
                    ::K/srvr-xtn]
             :as decomposed} (shared/decompose K/hello-packet-dscr message)
            client-short-pk (get-in state [::current-client ::client-security ::short-pk])]
        (assert client-short-pk)
        (assert clnt-short-pk)
        ;; Q: Is there any real point to this?
        (log/info "Copying incoming short-pk bytes from" clnt-short-pk "a" (class clnt-short-pk))
        (.getBytes clnt-short-pk 0 client-short-pk)
        (let [unboxed (open-hello-crypto-box (assoc state
                                                    ::client-short-pk client-short-pk
                                                    ::nonce-suffix nonce)
                                             message
                                             crypto-box)
              plain-text (::opened unboxed)]
          (if plain-text
            (let [shared-secret (::shared-secret unboxed)
                  minute-key (get-in state [::cookie-cutter ::minute-key])
                  {:keys [::shared/text
                          ::shared/working-nonce]} working-area]
              (log/debug "asserting minute-key" minute-key "among" (keys state))
              (assert minute-key)
              (log/debug "Preparing cookie")
              ;; We don't actually care about the contents of the bytes we just decrypted.
              ;; They should be all zeroes for now, but that's really an area for possible future
              ;; expansion.
              ;; For now, the point is that they unbox correctly on the other side
              (let [crypto-box
                    (prepare-cookie! {::client-short<->server-long shared-secret
                                      ::client-short-pk clnt-short-pk
                                      ::minute-key minute-key
                                      ::plain-text plain-text
                                      ::text text
                                      ::working-nonce working-nonce})]
                ;; Note that this overrides the incoming message in place
                ;; Which seems dangerous, but it very deliberately is longer than
                ;; our response.
                ;; And it does save a malloc/GC.
                ;; Important note: I'm deliberately not releasing this, because I'm sending it back.
                (.clear message)
                (let [response
                      (build-cookie-packet message clnt-xtn srvr-xtn working-nonce crypto-box)]
                  (log/info (str "Cookie packet built. Returning it.\nByte content:\n"
                                 (with-out-str (b-s/print-bytes response))
                                 "Reference count: " (.refCnt response)))
                  (try
                    (let [dst (get-in state [::client-write-chan :chan])
                          put-future (stream/try-put! dst
                                                      (assoc packet
                                                             :message response)
                                                      ;; TODO: This really needs to be part of
                                                      ;; state so it can be tuned while running
                                                      +cookie-send-timeout+
                                                      ::timed-out)]
                      (log/info "Cookie packet scheduled to send")
                      (deferred/on-realized put-future
                        (fn [success]
                          (if success
                            (log/info "Sending Cookie succeeded")
                            (log/error "Sending Cookie failed"))
                          ;; TODO: Make sure this does get released!
                          ;; The caller has to handle that, though.
                          ;; It can't be released until after it's been put
                          ;; on the socket.
                          (comment (.release response)))
                        (fn [err]
                          (log/error "Sending Cookie failed:" err)
                          (.release response)))
                      state)
                    (catch Exception ex
                      (log/error ex "Failed to send Cookie response")
                      state)))))
            (do
              (log/warn "Unable to open the HELLO crypto-box: dropping")
              state)))))
    (log/warn "Wrong size for a HELLO packet. Need"
              shared/hello-packet-length
              "got"
              (.readableBytes message))))

(s/fdef decrypt-initiate-vouch
        :args (s/cat :nonce :shared/client-nonce
                     :box (s/and bytes?
                                 #(< (count %) K/minimum-vouch-length)))
        :ret (s/nilable bytes?))
;; TODO: Write server-test/vouch-extraction to gain confidence that
;; this works
(defn decrypt-initiate-vouch
  [shared-key nonce-suffix box nonce]
  (b-t/byte-copy! nonce K/initiate-nonce-prefix)
  (b-t/byte-copy! nonce
                  K/client-nonce-prefix-length
                  K/client-nonce-suffix-length
                  nonce-suffix)
  (try
    (let [plain-vector (crypto/open-after box 0 (count box) nonce shared-key)]
      (byte-array plain-vector))
    (catch ExceptionInfo ex
      (log/error ex (util/pretty (.getData ex))))))

(s/fdef possibly-add-new-client-connection
        :args (s/cat :state ::state
                     :initiate-packet ::K/initiate-packet-spec)
        :ret boolean?)
(defn possibly-re-initiate-existing-client-connection!
  "Client can send as many Initiate packets as it likes.

If this matches a connection we've already seen, append the Message
portion to the child-handler's queue.

returns:
  true:  Handled here
  false: Not handled. Propagate the event

This seems like it ought to be part of a bigger, more comprehensive
event handling system.

To be fair, this layer *is* pretty special."
  [state initiate]
  ;; In the reference implementation, this basically corresponds to
  ;; lines 341-358.
  ;; Find the matching client (if any).
  ;; If there is one, extract the message portion and send that to
  ;; its child (since the ).
  (let [client-short-key (::clnt-short-pk initiate)]
    (when-let [client (find-client state client-short-key)]
      (let [packet-nonce-bytes (::nonce initiate)
            packet-nonce (b-t/uint64-unpack packet-nonce-bytes)
            last-packet-nonce (::received-nonce client)]
        (if (< last-packet-nonce packet-nonce)
          (let [vouch (:K/vouch initiate)
                shared-key (::client-short<->server-short client)]
            (if-let [plain-text (decrypt-initiate-vouch shared-key
                                                        packet-nonce-bytes
                                                        vouch)]
              (do
                (swap! (::active-clients state)
                       update-in [client-short-key ::received-nonce]
                       packet-nonce)
                ;; That takes us down to line 352.
                ;; Q: What's going on there?
                ;; text[383] = (r - 544) >> 4;
                ;; Translation:
                ;; The message associated with the Initiate packet starts
                ;; at byte 384.
                ;; The reference implementation inserts a prefix byte
                ;; (length/16)
                ;; before sending the array to the associated child
                ;; process in the next line:
                ;; writeall(activeclients[i].tochild, text+383, r-543)
                (throw (RuntimeException. "start back here")))
              (do
                (log/warn "Unable to decrypt incoming vouch")
                true)))
          (do
            (log/debug "Discarding obsolete nonce:" packet-nonce "/" last-packet-nonce)
            true))))))

(s/fdef decrypt-inner-vouch!
        :args (s/cat :cookie-cutter ::cookie-cutter
                     :dst any?
                     :hello-cookie any?)
        :ret boolean?)
(defn decrypt-inner-vouch!
  [cookie-cutter dst hello-cookie]
  (log/debug "Trying to extract cookie based on current minute-key")
  ;;; Set it up to extract from the current minute key

  ;; Start with the initial 0-padding
  (b-t/byte-copy! dst 0 K/box-zero-bytes shared/all-zeros)
  ;; Copy over the 80 bytes of crypto text from the initial cookie.
  ;; Note that this part is tricky:
  ;; The "real" initial cookie is 96 bytes long:
  ;; * 32 bytes of padding
  ;; * 32 bytes of client short-term key
  ;; * 32 bytes of server short-term key
  ;; That's 80 bytes crypto text.
  ;; But then the "crypto black box" that just round-tripped
  ;; through the client includes 16 bytes of a nonce, taking
  ;; it back up to 96 bytes.
  (b-t/byte-copy! dst
                  K/box-zero-bytes
                  K/hello-crypto-box-length
                  hello-cookie
                  K/server-nonce-suffix-length)
  (let [;; Q: How much faster/more efficient is it to have a
        ;; io.netty.buffer.PooledByteBufAllocator around that
        ;; I could use for either .heapBuffer or .directBuffer?
        ;; (as opposed to creating my own local in the let above)
        nonce (byte-array K/nonce-length)]
    (try
      (b-t/byte-copy! nonce K/cookie-nonce-minute-prefix)
      (b-t/byte-copy! nonce
                      K/server-nonce-prefix-length
                      K/server-nonce-suffix-length
                      hello-cookie)
      (crypto/secret-unbox dst dst K/server-cookie-length nonce (::minute-key cookie-cutter))
      true
      (catch ExceptionInfo _
        ;; Try again with the previous minute-key
        (log/debug "That failed. Try again with the previous minute-key")
        (b-t/byte-copy! dst 0 K/box-zero-bytes shared/zero-bytes)
        (b-t/byte-copy! dst
                        K/box-zero-bytes
                        K/hello-crypto-box-length
                        hello-cookie
                        K/server-nonce-suffix-length)

        (try
          (crypto/secret-unbox dst
                               dst
                               K/server-cookie-length
                               nonce
                               (::last-minute-key cookie-cutter))
          true
          (catch ExceptionInfo _
            ;; Reference implementation just silently discards the
            ;; failure.
            ;; That's more efficient at this level, but seems to
            ;; discard the possibilities of attack mitigation.
            (log/warn "Extracting the original crypto-box failed")
            ;; Be explicit about returning failure
            false))))))

(s/fdef verify-client-pk-in-vouch
        :args (s/cat :destructured-initiate-packet ::K/initiate-packet-spec
                     :inner-vouch-decrypted-box (s/and bytes?
                                                       #(= K/key-length
                                                           (count %))))
        :ret boolean?)
(defn verify-client-pk-in-vouch
  [initiate hidden-pk]
  (let [expected-buffer (::K/clnt-short-pk initiate)
        expected (byte-array K/key-length)]
    (.getBytes expected-buffer 0 expected)
    (log/debug "Cookie extraction succeeded. Q: Do the contents match?"
               "\nExpected:\n"
               (shared/bytes->string expected)
               "\nActual:\n"
               (shared/bytes->string hidden-pk))
    (b-t/bytes= hidden-pk expected)))

(s/fdef extract-cookie
        :args (s/cat :cookie-cutter ::cookie-cutter
                     :initiate-packet ::K/initiate-packet-spec)
        :ret ::K/cookie-spec)
(defn extract-cookie
  [{:keys [::minute-key
           ::last-minute-key]
    :as cookie-cutter}
   initiate]
  ;; This corresponds to lines 359-368. Just verify that
  ;; we can open our secret cryptobox cookie using either
  ;; the current or previous minute-key

  ;; Errors here get logged, but there's no good way for the
  ;; caller to know that there was a problem.
  ;; Well, the "client" that put the message onto the stream.
  ;; This is annoying for unit tests, but realistic for
  ;; the real world.
  ;; Outside the unit test scenario, the "client" is whatever
  ;; pulled data from the UDP socket.
  ;; And that shouldn't be coping with problems at this level.
  ;; In a way, this beats the reference implementation, which
  ;; just silently discards the packet.
  ;; Although that approach is undeniably faster than throwing
  ;; an exception and logging the problem
  (let [hello-cookie-buffer (::K/cookie initiate)
        hello-cookie (byte-array K/server-cookie-length)]
    (.getBytes hello-cookie-buffer 0 hello-cookie)
    (let [inner-vouch-bytes (byte-array K/server-cookie-length)]
      (when (decrypt-inner-vouch! cookie-cutter inner-vouch-bytes hello-cookie)
        ;; Reference code:
        ;; Verifies that the "first" 32 bytes (after the 32 bytes of
        ;; decrypted 0 padding) of the 80 bytes it decrypted
        ;; out of the inner vouch match the client short-term
        ;; key in the outer initiate packet.
        (let [full-decrypted-vouch (vec inner-vouch-bytes)
              ;; Round-tripping through a vector seems pretty ridiculous.
              ;; I really just want to verify that the first 32 bytes match
              ;; the supplied key.
              ;; Except that it's really bytes 16-47, isn't it?
              key-array (byte-array (subvec full-decrypted-vouch 0 K/key-length))]
          (when (verify-client-pk-in-vouch initiate key-array)
            (let [vouch-buf (Unpooled/wrappedBuffer inner-vouch-bytes)]
              (shared/decompose K/black-box-dscr vouch-buf))))))))

(s/fdef configure-shared-secrets
        :args (s/cat :client ::client-state
                     :server-short-sk ::shared/secret-key
                     :client-short-pk ::shared/public-key)
        :ret ::client-state)
(defn configure-shared-secrets
  "Return altered client state that reflects new shared key
  This should correspond to lines 369-371 in reference implementation"
  [client
   server-short-sk
   client-short-pk]
  (-> client
      (assoc-in [::shared-secrets ::client-short<->server-short] (crypto/box-prepare client-short-pk server-short-sk))
      (assoc-in [::client-security ::short-pk] client-short-pk)
      (assoc-in [::client-security ::server-short-sk] server-short-sk)))

(defn handle-initiate!
  [state
   {:keys [host message port]
    :as packet}]
  (or
   (let [n (.readableBytes message)]
     (if (>= n minimum-initiate-packet-length)
       (let [tmplt (update-in K/initiate-packet-dscr [::K/vouch ::K/length] + (- n minimum-initiate-packet-length))
             initiate (shared/decompose tmplt message)
             client-short-key (::K/clnt-short-pk initiate)]
         (if-not (possibly-re-initiate-existing-client-connection! state initiate)
           (let [active-client (find-client state client-short-key)]
             (if-let [cookie (extract-cookie (::cookie-cutter state)
                                             initiate)]
               (do
                 (log/info (str "Succssfully extracted cookie:\n")
                           (util/pretty cookie))
                 (let [server-short-sk-buffer (::K/srvr-short-sk cookie)
                       server-short-sk (byte-array K/key-length)
                       client-short-pk (byte-array K/key-length)]
                   (.getBytes server-short-sk-buffer 0 server-short-sk)
                   (.getBytes client-short-key 0 client-short-pk)
                   (let [active-client (configure-shared-secrets active-client
                                                                 server-short-sk
                                                                 client-short-pk)]
                     (throw (ex-info "Don't stop here!"
                                     {:what "Cope with vouch/initiate"})))))
               (log/error "FIXME: Debug only: cookie extraction failed")))
           (log/info "Received additional Initiate packet from" client-short-key)))
       (log/warn (str "Truncated initiate packet. Only received " n " bytes"))))
   ;; If nothing's changing, just maintain status quo
   state))

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
                \H (handle-hello! state packet)
                \I (handle-initiate! state packet)
                \M (handle-message! state packet))
              (catch Exception ex
                (log/error ex (str "Failed handling packet type: " packet-type-id))
                state))))
        (do (log/info "Ignoring packet intended for someone else")
            state)))
    (do
      (log/debug "Ignoring packet of illegal length")
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
    (crypto/random-bytes! minute-key-array))

  ;; Missing step: update cookie-cutter's next-minute
  ;; (that happens in handle-key-rotation)
  (let [p-m (::shared/packet-management this)]
    ;; The atom below this causes an NPE.
    ;; Trying to sort out why.
    (do
      (log/warn "FIXME: Debug only")
      (if-not p-m
        (log/error (str "Missing ::shared/packet-management in\n" this))
        (if-let [packet (::shared/packet p-m)]
          (log/warn (str "Getting ready to have a problem calling .clear on\n" packet))
          (log/error "Missing ::shared/packet inside\n" p-m))))
    (crypto/randomize-buffer! (::shared/packet p-m)))
  (crypto/random-bytes! (-> this ::current-client ::client-security ::short-pk))
  ;; These are all private, so I really can't touch them
  ;; Q: What *is* the best approach to clearing them then?
  ;; For now, just explicitly set to nil once we get past these side-effects
  ;; (i.e. at the bottom)
  #_(crypto/random-bytes (-> this :current-client ::shared-secrets :what?))
  (let [work-area (::shared/working-area this)]
    ;; These next two may make more sense once I have a better idea about
    ;; the actual messaging implementation.
    ;; Until then, plan on just sending objects across core.async.
    ;; Of course, the entire point may be messages that are too big
    ;; and need to be sharded.
    #_(crypto/random-bytes! (-> this :child-buffer ::buf))
    #_(crypto/random-bytes! (-> this :child-buffer ::msg))
    (crypto/random-bytes! (::shared/working-nonce work-area))
    (crypto/random-bytes! (::shared/text work-area)))
  (when-let [short-term-keys (get-in this [::shared/my-keys ::short-pair])]
    (crypto/random-bytes! (.getPublicKey short-term-keys))
    (crypto/random-bytes! (.getSecretKey short-term-keys)))
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
            (b-t/byte-copy! (::last-minute-key cookie-cutter)
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
  [{:keys [::client-read-chan]
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
                  (log/debug "Possibly Rotating"
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
  {::minute-key (crypto/random-key)
   ::last-minute-key (crypto/random-key)
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
      (assoc-in [::shared/my-keys ::K/server-name] "...decode this...")
      (assoc #_[::message "..."]
             ::shared/working-area "...")))

(defn start!
  [{:keys [::client-read-chan
           ::client-write-chan
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
        almost (assoc this ::cookie-cutter (randomized-cookie-cutter))]
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
      outcome)
    (finally
      (shared/release-packet-manager! packet-management))))

(defn ctor
  "Just like in the Component lifecycle, this is about setting up a value that's ready to start"
  [{:keys [::max-active-clients]
    :or {max-active-clients default-max-clients}
    :as cfg}]
  (-> cfg
      (assoc ::active-clients (atom #{})  ; Q: set or map?
             ::current-client (alloc-client)  ; Q: What's the point?
             ::max-active-clients max-active-clients
             ::shared/working-area (shared/default-work-area))))
