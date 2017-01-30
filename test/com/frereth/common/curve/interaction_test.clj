(ns com.frereth.common.curve.interaction-test
  (:require [clojure.test :refer (deftest is)]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.server :as srvr]
            [com.frereth.common.curve.client :as clnt]
            [com.stuartsierra.component :as cpt]
            [component-dsl.system :as cpt-dsl]
            [manifold.deferred :as deferred]
            [manifold.stream :as strm]))

(deftest handshake
  (let [server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                      0x0d 0x0e 0x0f 0x10])
        server-long-pk (byte-array [37 108 -55 -28 25 -45 24 93
                                    51 -105 -107 -125 -120 -41 83 -46
                                    -23 -72 109 -58 -100 87 115 95
                                    89 -74 -21 -33 20 21 110 95])
        server-name (shared/encode-server-name "test.frereth.com")
        options {:server {::shared/extension server-extension
                          ::shared/my-keys {::shared/server-name server-name}
                          :security {::shared/keydir "curve-test"
                                     ;; Note that name really isn't legal.
                                     ;; It needs to be something we can pass
                                     ;; along to DNS, padded to 255 bytes.
                                     ;; This bug really should show up in
                                     ;; a test.
                                     ::shared/server-name "local.test"}}
                 :client {::shared/extension (byte-array [0x10 0x0f 0x0e 0x0d
                                                          0x0c 0x0b 0x0a 0x09
                                                          0x08 0x07 0x06 0x05
                                                          0x04 0x03 0x02 0x01])
                          ::clnt/server-extension server-extension
                          ;; Q: Where do I get the server's public key?
                          ;; A: Right now, I just have the secret key's 32 bytes encoded as
                          ;; the alphabet.
                          ;; TODO: Really need to mirror what the code does to load the
                          ;; secret key from a file.
                          ;; Then I can just generate a random key pair for the server.
                          ;; Use the key-put functionality to store the secret, then
                          ;; hard-code the public key here.
                          ::clnt/server-security {::clnt/server-long-term-pk server-long-pk
                                                  ::shared/server-name server-name}}}
        ;; TODO: This seems like it would be a great place to try switching to integrant
        ;; Or, at least, just ditching the Component Lifecycle parts.
        ;; Actually, this is just another step in that direction: I've already
        ;; started by eliminating it from Client.
        system (-> #:component-dsl.system {:structure {:client 'com.frereth.common.curve.client/ctor
                                                       :server 'com.frereth.common.curve.server/ctor
                                                       ;; Flip the meaning of these channel names,
                                                       ;; because we're looking at things inside out.
                                                       ;; From the perspective of the client, this is
                                                       ;; the stream it uses to communicate with the
                                                       ;; server.
                                                       ;; But it's the one we use to communicate with
                                                       ;; the client.
                                                       :client-chan 'com.frereth.common.curve.server-test/chan-ctor
                                                       ;; This one is inverted in the same way.
                                                       :server-chan 'com.frereth.common.curve.server-test/chan-ctor}
                                           :dependencies {:client {:server-chan :client-chan}
                                                          :server {:client-chan :server-chan}}}
                   (cpt-dsl/build options)
                   cpt/start)]
    (try
      (let [fut (deferred/chain (strm/take! (:chan (:client-chan system)))
                  (fn [hello]
                    (is (= 224 (count hello)))))]
        (is (not= (deref fut 500 ::timeout) ::timeout))
        (throw (Exception. "Don't stop there!")))
      (finally (cpt/stop system)))))
