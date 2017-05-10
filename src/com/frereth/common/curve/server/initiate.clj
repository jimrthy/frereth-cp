(ns com.frereth.common.curve.server.initiate
  "For coping with Initiate packets"
  (:require [com.frereth.common.curve.server.state :as state]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]
            [com.frereth.common.curve.shared.constants :as K]
            [com.frereth.common.curve.shared.crypto :as crypto]
            [com.frereth.common.util :as util]
            [clojure.spec :as s]
            [clojure.tools.logging :as log])
  (:import clojure.lang.ExceptionInfo
           io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Named Constants

(def minimum-initiate-packet-length 560)

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
            (let [vouch-buf (Unpooled/wrappedBuffer inner-vouch-bytes)]
              (shared/decompose K/black-box-dscr vouch-buf))))))))

(defn open-client-crypto-box
  [{:keys [::K/nonce
           ::K/vouch-wrapper]
    :as initiate}
   current-client]
  (log/info "Opening the Crypto box we just received from the client using\n"
            (b-t/->string nonce)
            "(reference count: " (.refCnt nonce) ") "
            "on\n"
            (b-t/->string vouch-wrapper))
  (let [message-length (- (.readableBytes vouch-wrapper) K/minimum-vouch-length)]
    ;; Now this is triggering an io.netty.util.IllegalReferenceCountException
    ;; That seems like forward progress.
    ;; It beats my unexplained "opening crypto box failed" error.
    (if-let [clear-text (crypto/open-crypto-box K/initiate-nonce-prefix
                                                nonce
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

(defn validate-server-name
  [state inner-client-box]
  (let [rcvd-name-buffer (::K/server-name inner-client-box)]
    (throw (RuntimeException. "Get this translated"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

;; TODO: Needs spec
(defn handle!
  [state
   {:keys [:host :message :port]
    :as packet}]
  (log/info "Handling incoming initiate packet: " packet)
  (or
   (let [n (.readableBytes message)]
     (if (>= n minimum-initiate-packet-length)
       (let [tmplt (update-in K/initiate-packet-dscr [::K/vouch-wrapper ::K/length] + (- n minimum-initiate-packet-length))
             initiate (shared/decompose tmplt message)
             client-short-key (::K/clnt-short-pk initiate)]
         ;; The nonce's reference count has been cleared before it ever gets here.
         ;; This is silly.
         (log/info (str "******************************************\n"
                        "* Nonce:\n* "
                        (b-t/->string (::K/nonce initiate))
                        "* Reference Count: " (.refCnt (::K/nonce initiate))))
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
                     ;; client that has the secret key associated with both the short-term
                     ;; public key.
                     ;; It included a secret cookie that we generated sometime within the
                     ;; past couple of minutes.
                     ;; Now we're ready to tackle handling the main message body cryptobox.
                     ;; This corresponds to line 373 in the reference implementation.
                     (try
                       (when-let [inner-client-box (open-client-crypto-box initiate active-client)]
                         (try
                           (when (validate-server-name state inner-client-box)
                             ;; This takes us down to line 381
                             (throw (ex-info "Don't stop here!"
                                             {:what "Cope with vouch/initiate"})))
                           (catch ExceptionInfo ex
                             (log/error ex "Failure after decrypting inner client cryptobox"))))
                          (catch ExceptionInfo ex
                            (log/error ex "Initiate packet looked good enough to establish client session, but failed later"))))))
               (log/error "FIXME: Debug only: cookie extraction failed")))
           (log/warn "TODO: Handle additional Initiate packet from " client-short-key)))
       (log/warn (str "Truncated initiate packet. Only received " n " bytes"))))
   ;; If nothing's changing, just maintain status quo
   state))
