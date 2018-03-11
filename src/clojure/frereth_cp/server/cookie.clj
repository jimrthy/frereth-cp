(ns frereth-cp.server.cookie
  "For dealing with cookie packets on the server side"
  (:require [byte-streams :as b-s]
            [clojure.tools.logging :as log]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.serialization :as serial])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(def send-timeout 50)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(defn prepare-cookie!
  [{:keys [::state/client-short<->server-long
           ::state/minute-key
           ;; Q: What is/was this for?
           ;; A: This is/was supposed to be the buffer of bytes
           ;; that get encrypted
           ::clear-text
           ::shared/working-nonce]
    ^bytes client-short-pk ::state/client-short-pk
    ;; This is really the destination for the crypto-box
    ;; being built from clear-text
    ^bytes text ::shared/text}]
  "Called purely for side-effects.

The most important is that it encrypts clear-text
and puts the crypto-text into the byte-array in text.

Except that it doesn't seem to do that at all."
  (let [^com.iwebpp.crypto.TweetNaclFast$Box$KeyPair keys (crypto/random-key-pair)
        ;; This is just going to get thrown away, leading
        ;; to potential GC issues.
        ;; Probably need another static buffer for building
        ;; and encrypting things like this.
        ;; Or just use text. That's what the reference implementation
        ;; does.
        ^ByteBuf buffer (Unpooled/buffer K/server-cookie-length)]
    (.retain buffer)
    (try
      ;; Q: Do I care whether it's an array-backed buffer?
      ;; A: Well, I'm interacting with the array directly
      ;; below.
      ;; So...maybe.
      (assert (.hasArray buffer))
      ;; TODO: Rewrite this using compose
      (.writeBytes buffer K/all-zeros 0 K/decrypt-box-zero-bytes)  ; line 315
      (.writeBytes buffer client-short-pk 0 K/key-length)
      (.writeBytes buffer (.getSecretKey keys) 0 K/key-length)

      (b-t/byte-copy! working-nonce K/cookie-nonce-minute-prefix)
      (crypto/safe-nonce working-nonce nil K/server-nonce-prefix-length)

      ;; Reference implementation is really doing pointer math with the array
      ;; to make this work.
      ;; It's encrypting from (+ clear-text 64) over itself.
      ;; There just isn't a good way to do the same thing in java.
      ;; (The problem, really, is that I have to copy the plaintext
      ;; so it winds up at the start of the array).
      ;; Note that this is a departure from the reference implementation!
      (let [actual (.array buffer)]
        (crypto/secret-box actual actual K/server-cookie-length working-nonce minute-key)
        ;; Copy that encrypted cookie into the text working area
        (.getBytes buffer 0 text 32 K/server-cookie-length)
        ;; Along with the nonce
        ;; Note that this overwrites the first 16 bytes of the box we just wrapped.
        ;; Go with the assumption that those are the initial garbage 0 bytes that should
        ;; be discarded anyway
        (b-t/byte-copy! text
                        K/key-length  ; reference uses 64 bytes here. 32 bytes of zeros
                        K/server-nonce-suffix-length
                        working-nonce
                        K/server-nonce-prefix-length)  ; line 321

        ;; And now we need to encrypt that.
        ;; This really belongs in its own function
        ;; And it's another place where I should probably call compose
        (b-t/byte-copy! text 0 K/key-length (.getPublicKey keys))
        ;; Overwrite the prefix.
        ;; Reuse the 16 byte suffix that came in from the client.
        ;; Note that, as written, we have to access this suffix
        ;; later in build-cookie-packet.
        ;; That may technically be functionally pure, but it seems
        ;; pretty awful.
        ;; If nothing else, it's far too tightly coupled.
        (b-t/byte-copy! working-nonce
                        0
                        K/server-nonce-prefix-length
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
          cookie))
      (finally
        (.release buffer)))))

(defn build-cookie-packet
  [client-extension server-extension ^bytes working-nonce crypto-cookie]
  (let [nonce-suffix (byte-array K/server-nonce-suffix-length)]
    (b-t/byte-copy! nonce-suffix 0 K/server-nonce-suffix-length working-nonce K/server-nonce-prefix-length)
    (let [^ByteBuf composed (serial/compose K/cookie-frame {::K/header K/cookie-header
                                                            ::K/client-extension client-extension
                                                            ::K/server-extension server-extension
                                                            ::K/client-nonce-suffix nonce-suffix
                                                            ::K/cookie crypto-cookie})]
      ;; I really shouldn't need to do this
      ;; FIXME: Make sure it gets released
      (.retain composed)
      composed)))
