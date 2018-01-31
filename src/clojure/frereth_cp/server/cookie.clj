(ns frereth-cp.server.cookie
  "For dealing with cookie packets on the server side"
  (:require [byte-streams :as b-s]
            [clojure.tools.logging :as log]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto])
  (:import io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(set! *warn-on-reflection* true)

(def send-timeout 50)

(defn prepare-cookie!
  [{:keys [::state/client-short<->server-long
           ::state/minute-key
           ;; Q: What is/was this for?
           ::clear-text
           ::shared/working-nonce]
    ^bytes client-short-pk ::state/client-short-pk
    ^bytes text ::shared/text}]
  "Called purely for side-effects.

The most important is that it encrypts clear-text
and puts the crypto-text into the byte-array in text.

Except that it doesn't seem to do that at all."
  (let [^com.iwebpp.crypto.TweetNaclFast$Box$KeyPair keys (crypto/random-key-pair)
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
  [packet client-extension server-extension ^bytes working-nonce crypto-cookie]
  (let [composed (shared/compose K/cookie-frame {::K/header K/cookie-header
                                                 ::K/client-extension client-extension
                                                 ::K/server-extension server-extension
                                                 ;; Q: Could this possibly be worth using Pooled?
                                                 ::K/client-nonce-suffix (Unpooled/wrappedBuffer working-nonce
                                                                                                 K/server-nonce-prefix-length
                                                                                                 K/server-nonce-suffix-length)
                                                 ::K/cookie crypto-cookie}
                                 packet)]
    ;; I really shouldn't need to do this
    ;; FIXME: Make sure it gets released
    (.retain composed)
    composed))
