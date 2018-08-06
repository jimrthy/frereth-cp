(ns frereth-cp.handshake-test
  "Test the different pieces involved in connection establishment"
  (:require [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.client :as clnt]
            [frereth-cp.client.initiate :as clnt-init]
            [frereth-cp.server :as server]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [constants :as K]
             [specs :as specs]
             [templates :as templates]])
  (:import io.netty.buffer.Unpooled))

(deftest test-cookie-composition
  ;; The different magic numbers I'm using for the extensions and
  ;; nonce are just so I have a way to distinguish the different bits
  ;; when I need to look at the individual bytes
  (let [client-extension (byte-array (take K/extension-length (repeat 0)))
        server-extension (byte-array (take K/extension-length (range)))
        safe-nonce (byte-array (take K/nonce-length (drop 40 (range))))
        boxed (byte-array K/cookie-packet-length)
        ;; Make sure we have plenty of room for writing
        dst (Unpooled/buffer (* 2 K/cookie-packet-length))
        ;; Built from the array, offset, and the length
        client-nonce-suffix-buffer (Unpooled/wrappedBuffer safe-nonce
                                                           specs/server-nonce-prefix-length
                                                           specs/server-nonce-suffix-length)
        client-nonce-suffix (byte-array specs/server-nonce-suffix-length)
        cookie-buffer (Unpooled/wrappedBuffer boxed
                                              K/box-zero-bytes
                                              K/cookie-frame-length)
        cookie (byte-array K/cookie-frame-length)]
    (.readBytes client-nonce-suffix-buffer client-nonce-suffix)
    (.readBytes cookie-buffer cookie)
    (let [to-encode {::K/header K/cookie-header
                     ::K/client-extension client-extension
                     ::K/server-extension server-extension
                     ::K/client-nonce-suffix client-nonce-suffix
                     ::K/cookie cookie}]
      (try
        (let [composed (shared/compose templates/cookie-frame to-encode dst)]
          ;; It's very tempting to dissect this for a round trip.
          ;; But, honestly, that's what property-based tests are best at
          (is composed))
        (catch clojure.lang.ExceptionInfo ex
          (is (not (.getData ex))))))))

(deftest vouch-encoding
  (throw (RuntimeException. "Really want to exercise-fn clnt/build-initiate-packet!")))

(deftest vouch-round-trip
  (let [client-state (clnt/ctor {})
        ;; This is totally wrong.
        ;; The ByteBuf argument is the message that goes along with the initiate packet.
        raw-vouches (s/exercise ::K/initiate-packet-spec)
        vouches (map (partial clnt-init/build-initiate-packet! client-state) raw-vouches)]
    ;; TODO:
    ;; Use client/build-vouch to generate a vouch wrapper.
    ;; Then call server/decrypt-initiate-vouch to verify that
    ;; it extracted correctly.
    (throw (RuntimeException. "Not Implemented"))))
