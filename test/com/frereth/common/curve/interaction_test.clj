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
  (let [options {:server {:security {::shared/keydir "curve-test"
                                     ;; Note that name really isn't legal.
                                     ;; It needs to be something we can pass
                                     ;; along to DNS, padded to 255 bytes.
                                     ;; This bug really should show up in
                                     ;; a test.
                                     ::shared/server-name "local.test"}
                          :extension (byte-array [0x01 0x02 0x03 0x04
                                                  0x05 0x06 0x07 0x08
                                                  0x09 0x0a 0x0b 0x0c
                                                  0x0d 0x0e 0x0f 0x10])}
                 :cp-client {}}
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
        (is (not= (deref fut 500 ::timeout) ::timeout)))
      (finally (cpt/stop system)))))
