(ns frereth-cp.server.cookie
  "For dealing with cookie packets on the server side"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.server
             [shared-specs :as srvr-specs]
             [state :as state]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log2]
             [serialization :as serial]
             [specs :as specs]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal Helpers

(defn build-inner-cookie-original
  "This is the way it used to be done"
  [log-state
   client-short-pk
   my-sk
   minute-key
   nonce-suffix]
  (let [^ByteBuf buffer (Unpooled/buffer K/server-cookie-length)
        client-short-pk (bytes client-short-pk)
        working-nonce (byte-array K/nonce-length)
        my-sk (bytes my-sk)]
    (b-t/byte-copy! working-nonce 8 specs/server-nonce-suffix-length nonce-suffix)
    (try
      ;; Set up the raw plaintext cookie
      (.writeBytes buffer K/all-zeros 0 K/decrypt-box-zero-bytes) ; line 315
      (.writeBytes buffer client-short-pk 0 K/key-length)
      (.writeBytes buffer my-sk 0 K/key-length)

      (b-t/byte-copy! working-nonce K/cookie-nonce-minute-prefix)

      (let [actual (.array buffer)
            result (byte-array K/server-cookie-length)]
        (println )
        (crypto/secret-box actual actual K/server-cookie-length working-nonce minute-key)
        ;; Original needs to leave 0 padding up front
        ;; Note that the first 16 of those 32 bytes are garbage.
        ;; They're meant to be overwritten by the nonce-suffix
        (comment (.getBytes buffer 0 text 32 K/server-cookie-length))
        (.getBytes buffer 0 result)
        (b-t/byte-copy! result nonce-suffix)
        result))))

(s/fdef build-inner-cookie
        :args (s/or :sans-nonce (s/cat :log-state ::log2/state
                                       :other-short-pk ::specs/public-short
                                       :my-short-sk ::specs/secret-short
                                       :minute-key ::specs/crypto-key)
                    :with-nonce (s/cat :log-state ::log2/state
                                       :client-short-pk ::specs/public-short
                                       :my-short-sk ::specs/secret-short
                                       :minute-key ::specs/crypto-key
                                       :working-nonce ::specs/nonce))
        :ret (s/keys :req [::specs/byte-array
                           ::log2/log-state
                           ::specs/server-nonce-suffix]))
(defn build-inner-cookie
  "Build the inner black-box Cookie portion of the Cookie Packet"
  ([log-state
    client-short-pk
    my-short-sk
    minute-key]
   (let [{log-state ::log2/state
          working-nonce ::crypto/safe-nance} (crypto/get-safe-nonce log-state)]
     (build-inner-cookie log-state client-short-pk my-short-sk minute-key working-nonce)))
  ;; This arity really only exists for the sake of testing:
  ;; Being able to reproduce the nonce makes like much easier in that regard
  ([log-state
    client-short-pk
    my-short-sk
    minute-key
    nonce-suffix]
   ;; I feel like my problems start later, around line 87 when I start
   ;; running byte-copy.
   ;; STARTED: Verify that this approach generates the same output as the
   ;; original.
   ;; Currently, it does not.
   ;; Q: What are the odds that this has something to do with the 0 padding
   ;; and the extra 16 bytes the test needs to drop from the return value here?
   (let [boxed-cookie (crypto/build-crypto-box K/black-box-dscr
                                               {::K/clnt-short-pk client-short-pk
                                                ::K/srvr-short-sk my-short-sk}
                                               minute-key
                                               K/cookie-nonce-minute-prefix
                                               nonce-suffix)]
     ;; Alternative approach here would be to just prepend the nonce suffix
     ;; to boxed-cookie. Which is similar to what the reference implementation
     ;; does when it just overwrites the garbage portion of the zero-padding
     ;; with it on line 321
     {::specs/byte-array (bytes boxed-cookie)
      ::log2/log-state log-state
      ::specs/server-nonce-suffix nonce-suffix})))

;; FIXME: Write this spec
(s/fdef prepare-packet
        :args (s/cat :this ::state/state)
        :ret bytes?)
(defn prepare-packet!
  [{:keys [::state/client-short<->server-long
           ::log2/logger
           ::state/minute-key
           ;; Q: What is/was this for?
           ;; A: Well, it's supposed to be the buffer of bytes
           ;; that get encrypted
           ::clear-text
           ::shared/working-nonce]
    client-short-pk ::state/client-short-pk
    ;; This is really the destination for the crypto-box
    ;; being built from clear-text
    ^bytes text ::shared/text}]
  "Called purely for side-effects.

The most important is that it encrypts clear-text
and puts the crypto-text into the byte-array in text.

Except that it doesn't seem to do that at all."
  (let [client-short-pk (bytes client-short-pk)
        ^com.iwebpp.crypto.TweetNaclFast$Box$KeyPair key-pair (crypto/random-key-pair)
        log-state (log2/init "pointless-cookie-prep")
        {actual ::specs/byte-array
         log-state ::log2/state
         working-nonce ::specs/server-nonce-suffix} (build-inner-cookie log-state
                                                                   client-short-pk
                                                                   (.getSecretKey key-pair)
                                                                   minute-key)
        actual (bytes actual)]
    (try
      ;; Reference implementation is really doing pointer math with the array
      ;; to make this work.
      ;; It's encrypting from (+ clear-text 64) over itself.
      ;; There just isn't a good way to do the same thing in java.
      ;; (The problem, really, is that I have to copy the plaintext
      ;; so it winds up at the start of the array).
      ;; Note that this is a departure from the reference implementation!

      ;; Copy that encrypted cookie into the text working area
      (b-t/byte-copy! text K/key-length K/server-cookie-length actual)
      ;; Along with the nonce
      ;; Note that this overwrites the first 16 bytes of the box we just wrapped.
      ;; Go with the assumption that those are the initial garbage 0 bytes that should
      ;; be discarded anyway
      (b-t/byte-copy! text
                      ;; reference starts at offset 64 here.
                      ;; Then zeros out the first 32 bytes.
                      ;; Don't need that much, since the encryption library
                      ;; copes with that extra padding.
                      ;; TODO: Verify that.
                      K/key-length
                      specs/server-nonce-suffix-length
                      working-nonce
                      specs/server-nonce-prefix-length)  ; line 321

      ;; And now we need to encrypt that.
      ;; This really belongs in its own function
      ;; And it's another place where I should probably call compose
      (b-t/byte-copy! text 0 K/key-length (.getPublicKey key-pair))

      ;; Overwrite the prefix.
      ;; Reuse the 16 byte suffix that came in from the client.
      ;; Note that, as written, we have to access this suffix
      ;; later in build-cookie-packet.
      ;; That may technically be functionally pure, but it seems
      ;; pretty awful.
      ;; If nothing else, it's far too tightly coupled.
      (b-t/byte-copy! working-nonce
                      0
                      specs/server-nonce-prefix-length
                      K/cookie-nonce-prefix)
      (let [cookie (crypto/box-after client-short<->server-long
                                     text
                                     ;; TODO: named const for this.
                                     K/unboxed-crypto-cookie-length ; 128
                                     working-nonce)]
        (log/info (str "Full cookie going to client that it should be able to decrypt:\n"
                       (with-out-str (b-s/print-bytes cookie))
                       "using shared secret:\n"
                       (with-out-str (b-s/print-bytes client-short<->server-long))))
        cookie))))

(defn build-cookie-packet
  [{client-extension ::K/clnt-xtn
    server-extension ::K/srvr-xtn}
   ^bytes working-nonce
   crypto-cookie]
  (let [nonce-suffix (byte-array specs/server-nonce-suffix-length)]
    (b-t/byte-copy! nonce-suffix 0
                    specs/server-nonce-suffix-length
                    working-nonce
                    specs/server-nonce-prefix-length)
    (let [^ByteBuf composed (serial/compose K/cookie-frame {::K/header K/cookie-header
                                                            ::K/client-extension client-extension
                                                            ::K/server-extension server-extension
                                                            ::K/client-nonce-suffix nonce-suffix
                                                            ::K/cookie crypto-cookie})]
      ;; I really shouldn't need to do this
      ;; FIXME: Make sure it gets released
      (.retain composed)
      composed)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-build-response
        :args (s/cat :state ::state/state
                     :recipe (s/keys :req [::srvr-specs/cookie-components ::K/hello-spec]))
        :ret ::specs/byte-buf)
(defn do-build-response
  [state
   {{:keys [::shared/working-nonce]
     :as cookie-components} ::srvr-specs/cookie-components
    hello-spec ::K/hello-spec}]
  (log/info "Preparing cookie")
  (let [crypto-box (prepare-packet! cookie-components)]
    ;; Note that the reference implementation overwrites this incoming message in place.
    ;; That seems dangerous, but it very deliberately is longer than
    ;; our response.
    ;; And it does save a malloc/GC.
    ;; I can't do that, because of the way compose works.
    ;; TODO: Revisit this decision if/when the GC turns into a problem.
    (build-cookie-packet hello-spec working-nonce crypto-box)))
