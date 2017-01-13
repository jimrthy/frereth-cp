(ns com.frereth.common.curve.interaction-test
  (:require [clojure.test :refer (deftest is)]
            [com.frereth.common.curve.server :as srvr]
            [com.frereth.common.curve.client :as clnt]
            [component-dsl :as cpt-dsl]
            [manifold.deferred :as deferred]
            [manifold.stream :as strm]))

(deftest handshake
  (let [options {:server {:security {:keydir "curve-test"
                                     ;; Note that name really isn't legal.
                                     ;; It needs to be something we can pass
                                     ;; along to DNS, padded to 255 bytes.
                                     ;; This bug really should show up in
                                     ;; a test.
                                     :name "local.test"}
                          :extension (byte-array [0x01 0x02 0x03 0x04
                                                  0x05 0x06 0x07 0x08
                                                  0x09 0x0a 0x0b 0x0c
                                                  0x0d 0x0e 0x0f 0x10])}
                 :cp-client {}}
        system (-> #:component-dsl.system {:structure {:client-chan 'com.frereth.common.curve.server-test/chan-ctor
                                                       :client 'com.frereth.common.curve.client/ctor
                                                       :server 'com.frereth.common.curve.server/ctor
                                                       :server-chan 'com.frereth.common.curve.server-test/chan-ctor}
                                           :dependencies {:client [:server-chan]
                                                          :server [:client-chan]}}
                   (cpt-dsl/build options)
                   cpt/start)]
    (try
      (let [fut (deferred/chain (strm/take! (:chan (:server-chan system)))
                  )])
      (finally (cpt/stop system)))))
