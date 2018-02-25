(ns frereth-cp.handshake-test
  "Test the different pieces involved in connection establishment"
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.server :as server]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K])
  (:import io.netty.buffer.Unpooled))

(deftest test-cookie-composition
  (let [client-extension (byte-array (take 16 (repeat 0)))
        server-extension (byte-array (take 16 (range)))
        working-nonce (byte-array (take 24 (drop 40 (range))))
        boxed (byte-array 200)
        dst (Unpooled/buffer 400)
        to-encode {::K/header K/cookie-header
                   ::K/client-extension client-extension
                   ::K/server-extension server-extension
                   ::K/client-nonce-suffix (Unpooled/wrappedBuffer working-nonce
                                                                   K/server-nonce-prefix-length
                                                                   K/server-nonce-suffix-length)
                   ;; This is also a great big FAIL:
                   ;; Have to drop the first 16 bytes
                   ;; Q: Have I fixed that yet?
                   ::K/cookie (Unpooled/wrappedBuffer boxed
                                                      K/box-zero-bytes
                                                      144)}]
    (try
      ;; FIXME: This fails because we can't cast a ByteBuf to a B]
      (let [composed (shared/compose K/cookie-frame to-encode dst)]
        (is composed))
      (catch clojure.lang.ExceptionInfo ex
        (is (not (.getData ex)))))))

(deftest vouch-extraction
  ;; TODO:
  ;; Use client/build-vouch to generate a vouch wrapper.
  ;; Then call server/decrypt-initiate-vouch to verify that
  ;; it extracted correctly.
  (throw (RuntimeException. "Not Implemented")))
