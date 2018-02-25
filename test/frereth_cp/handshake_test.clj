(ns frereth-cp.handshake-test
  "Test the different pieces involved in connection establishment"
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.server :as server]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K])
  (:import io.netty.buffer.Unpooled))

(deftest test-cookie-composition
  ;; The different magic numbers I'm using for the extensions and
  ;; nonce are just so I have a way to distinguish the different bits
  ;; when I need to look at the individual bytes
  (let [client-extension (byte-array (take K/extension-length (repeat 0)))
        server-extension (byte-array (take K/extension-length (range)))
        working-nonce (byte-array (take K/nonce-length (drop 40 (range))))
        boxed (byte-array K/cookie-packet-length)
        dst (Unpooled/buffer (* 2 K/cookie-packet-length))
        client-nonce-suffix-buffer (Unpooled/wrappedBuffer working-nonce
                                                           K/server-nonce-prefix-length
                                                           K/server-nonce-suffix-length)
        client-nonce-suffix (byte-array K/server-nonce-suffix-length)
        cookie-buffer (Unpooled/wrappedBuffer boxed
                                              K/box-zero-bytes
                                              K/cookie-frame-length)
        cookie (byte-array K/cookie-frame-length)]
    (.readBytes client-nonce-suffix-buffer client-nonce-suffix)
    (let [to-encode {::K/header K/cookie-header
                     ::K/client-extension client-extension
                     ::K/server-extension server-extension
                     ::K/client-nonce-suffix client-nonce-suffix
                     ;; This is also a great big FAIL:
                     ;; Have to drop the first 16 bytes
                     ;; Q: Have I fixed that yet?
                     ::K/cookie cookie}]
      (try
        (let [composed (shared/compose K/cookie-frame to-encode dst)]
          (is composed))
        (catch clojure.lang.ExceptionInfo ex
          (is (not (.getData ex))))))))

(deftest vouch-extraction
  ;; TODO:
  ;; Use client/build-vouch to generate a vouch wrapper.
  ;; Then call server/decrypt-initiate-vouch to verify that
  ;; it extracted correctly.
  (throw (RuntimeException. "Not Implemented")))
