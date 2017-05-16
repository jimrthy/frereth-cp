(ns frereth-cp.server.initiate
  "For coping with Initiate packets"
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.util :as util])
  (:import clojure.lang.ExceptionInfo
           io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Named Constants

;; This number is based on the basic Client Initiate packet details spec:
;; (+ 8 96 32 16 16 8 368)
(def packet-header-length 544)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal implementation

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
  ;; Q: Where was I going with that comment?
  (let [client-short-key (::clnt-short-pk initiate)]
    (when-let [client (state/find-client state client-short-key)]
      (log/info "I packet from known client")
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef decrypt-inner-vouch!
        :args (s/cat :cookie-cutter ::state/cookie-cutter
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
      (crypto/secret-unbox dst dst K/server-cookie-length nonce (::state/minute-key cookie-cutter))
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
                               (::state/last-minute-key cookie-cutter))
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
        :args (s/cat :cookie-cutter ::state/cookie-cutter
                     :initiate-packet ::K/initiate-packet-spec)
        :ret ::K/cookie-spec)
(defn extract-cookie
  [{:keys [::state/minute-key
           ::state/last-minute-key]
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
            ;; TODO: Need to add a Pooled Allocator to the server state
            ;; for this.
            ;; Q: Don't I?
            (let [vouch-buf (Unpooled/wrappedBuffer inner-vouch-bytes)]
              (shared/decompose K/black-box-dscr vouch-buf))))))))

(s/fdef open-client-crypto-box
        :args (s/cat :initiate ::K/initiate-packet-spec
                     :current-client ::client-state)
        :ret ::K/initiate-client-vouch-wrapper)
(defn open-client-crypto-box
  [{:keys [::K/outer-i-nonce
           ::K/vouch-wrapper]
    :as initiate}
   current-client]

  (log/info "Opening the Crypto box we just received from the client")
  (log/debug "The box we're opening is" (.readableBytes vouch-wrapper) "bytes long")
  (let [message-length (- (.readableBytes vouch-wrapper) K/minimum-vouch-length)]
    ;; Back to a mostly-unexplained "Failed to open box" error.
    (if-let [clear-text (crypto/open-crypto-box K/initiate-nonce-prefix
                                                outer-i-nonce
                                                vouch-wrapper
                                                (get-in current-client [::state/shared-secrets
                                                                        ::state/client-short<->server-short]))]
      (do
        (log/info "Decomposing...")
        (shared/decompose (assoc-in K/initiate-client-vouch-wrapper
                                    [::K/message ::K/length]
                                    message-length)
                          clear-text))
      (do (log/info "Opening client crypto vouch failed")
          nil))))

(s/fdef validate-server-name
        :args (s/cat :state ::state/state
                     :inner-client-box ::K/initiate-client-vouch-wrapper)
        :ret boolean?)
(defn validate-server-name
  [state inner-client-box]
  (let [rcvd-name-buffer (::K/server-name inner-client-box)
        rcvd-name (byte-array (.readableBytes rcvd-name-buffer))]
    (.readBytes rcvd-name-buffer rcvd-name)
    (let [my-name (get-in state [::shared/my-keys ::K/server-name])
          match (b-t/bytes= rcvd-name my-name)]
      (when-not match
        (log/warn (str "Message was intended for another server\n"
                       "Sent to:\n"
                       (b-t/->string rcvd-name)
                       "My name:\n\""
                       (b-t/->string my-name)
                       "\"\nout of:\n"
                       (keys (::shared/my-keys state)))))
      match)))

(s/fdef verify-client-public-key-triad
        :args (s/cat :state ::state/state
                     :client-long-key ::shared/long-pk
                     :supplied-client-short-key ::shared/short-pk
                     ;; TODO: Come up with a ByteBuf spec
                     ::client-message-box any?)
        :ret (s/nilable boolean?))
(defn verify-client-public-key-triad
  "We unwrapped the our original cookie, using the minute-key.

And the actual message box using the client's short-term public key.
That box included the client's long-term public key.

Now there's a final box nested that contains the short-term key again,
encrypted with the long-term key.

This step verifies that the client really does have access to that key.

It's flagged as \"optional\" in the reference implementation, ut that seems
a bit silly.

This corresponds, roughly, to lines 382-391 in the reference implementation.

Note that that includes TODOs re:
* impose policy limitations on clients: known, maxconn
* for known clients, retrieve shared secret from cache
"
  [state supplied-client-short-key client-message-box]
  (let [client-long-buffer (::K/long-term-public-key client-message-box)
        client-long-key (byte-array K/key-length)
        my-long-secret (.getSecretKey (get-in state [::shared/my-keys ::shared/long-pair]))
        shared-secret (crypto/box-prepare client-long-key
                                          my-long-secret)]
    (.getBytes client-long-buffer 0 client-long-key)
    (log/info (str "Getting ready to decrypt the inner-most hidden public key\n"
                   "Supplied client long-term key:\n"
                   ;; This next should match:
                   #_[0x26 0x9f 0x81 0x8d
                    0x4a 0xfc 0x55 0x04
                    0xad 0x01 0x34 0xfd
                    0xb0 0xa4 0xf4 0x12
                    0xe3 0x64 0x96 0xae
                    0x8c 0xe7 0x14 0xb5
                    0x70 0x76 0x62 0xb2
                    0x64 0xb8 0x3f 0x19]
                   (b-t/->string client-long-key)
                   "My long-term secret key:\n"
                   (b-t/->string my-long-secret)
                   "My long-term public key:\n"
                   (b-t/->string (.getPublicKey (get-in state [::shared/my-keys ::shared/long-pair])))
                   "Shared:\n"
                   ;; Client's version:
                   #_[0xc5 0x91 0x62 0xcd
                    0xfe 0xc1 0x33 0x89
                    0xa3 0xff 0x82 0x3d
                    0x26 0x2d 0x09 0x03
                    0x09 0xbc 0x9e 0xdd
                    0x35 0x87 0x1b 0x1c
                    0x81 0xb5 0xff 0x2a
                    0xa9 0xe1 0x6b 0x58]
                   (b-t/->string shared-secret)))
    ;; Failing here.
    ;; The shared secret doesn't match what the client used to encrypt the box.
    (when-let [inner-pk (crypto/open-crypto-box
                         K/vouch-nonce-prefix
                         (::K/inner-i-nonce client-message-box)
                         (::K/hidden-client-short-pk client-message-box)
                         shared-secret)]
      (b-t/bytes= supplied-client-short-key inner-pk))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef handle!
        :args (s/cat :state ::state/state
                     :packet ::shared/network-packet))
(defn handle!
  [state
   {:keys [:host :message :port]
    :as packet}]
  (log/info "Handling incoming initiate packet: " packet)
  (or
   (let [n (.readableBytes message)]
     (if (>= n (+ K/box-zero-bytes packet-header-length))
       ;; Note the extra 16 bytes
       ;; The minimum packet length is actually
       ;; (+ 544 K/box-zero-bytes)
       ;; Because the message *has* to have the bytes for 0
       ;; padding, even if it's 0 length.
       (let [tmplt (update-in K/initiate-packet-dscr
                              [::K/vouch-wrapper ::K/length]
                              +
                              (- n packet-header-length))
             initiate (shared/decompose tmplt message)
             client-short-key (::K/clnt-short-pk initiate)]
         (if-not (possibly-re-initiate-existing-client-connection! state initiate)
           (let [active-client (state/find-client state client-short-key)]
             (if-let [cookie (extract-cookie (::state/cookie-cutter state)
                                             initiate)]
               (do
                 (log/info (str "Succssfully extracted cookie"))
                 (let [server-short-sk-buffer (::K/srvr-short-sk cookie)
                       server-short-sk (byte-array K/key-length)
                       client-short-pk (byte-array K/key-length)]
                   (.getBytes server-short-sk-buffer 0 server-short-sk)
                   (.getBytes client-short-key 0 client-short-pk)
                   (let [active-client (state/configure-shared-secrets active-client
                                                                       server-short-sk
                                                                       client-short-pk)]
                     (state/alter-client-state! state active-client)
                     ;; Now we've verified that the Initiate packet came from a
                     ;; client that has the secret key associated with the short-term
                     ;; public key.
                     ;; It included a secret cookie that we generated sometime within the
                     ;; past couple of minutes.
                     ;; Now we're ready to tackle handling the main message body cryptobox.
                     ;; This corresponds to line 373 in the reference implementation.
                     (try
                       (when-let [client-message-box (open-client-crypto-box initiate active-client)]
                         (try
                           (if (validate-server-name state client-message-box)
                             ;; This takes us down to line 381
                             (when (verify-client-public-key-triad state client-short-key client-message-box)
                               ;; line 392
                               (throw (ex-info "Don't stop here!"
                                               {:what "Cope with vouch/initiate"}))))
                           (catch ExceptionInfo ex
                             (log/error ex "Failure after decrypting inner client cryptobox"))))
                          (catch ExceptionInfo ex
                            (log/error ex "Initiate packet looked good enough to establish client session, but failed later"))))))
               (log/error "FIXME: Debug only: cookie extraction failed")))
           (log/warn "TODO: Handle additional Initiate packet from " client-short-key)))
       (log/warn (str "Truncated initiate packet. Only received " n " bytes"))))
   ;; If nothing's changing, just maintain status quo
   state))
