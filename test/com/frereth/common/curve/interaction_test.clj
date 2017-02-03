(ns com.frereth.common.curve.interaction-test
  (:require [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is)]
            [com.frereth.common.curve.client :as clnt]
            [com.frereth.common.curve.server :as srvr]
            [com.frereth.common.curve.server-test :as server-test]
            [com.frereth.common.curve.shared :as shared]
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
        options {::server #::shared{:extension server-extension
                                    :my-keys #::shared{:server-name server-name
                                                       :keydir "curve-test"}}
                 ::client {::shared/extension (byte-array [0x10 0x0f 0x0e 0x0d
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
        client (clnt/ctor (assoc (::client options)
                                 ::clnt/chan<-server (strm/stream)
                                 ::chan->server (strm/stream)))
        unstarted-server (srvr/ctor (::server options))
        ;; Flip the meaning of these channel names,
        ;; because we're looking at things inside out.
        ;; From the perspective of the client, this is
        ;; the stream it uses to communicate with the
        ;; server.
        ;; But it's the one we use to communicate with
        ;; the client.
        unstarted-client-chan (server-test/chan-ctor nil)
        client-chan (.start unstarted-client-chan)]
    (try
      (println "Starting server based on\n"
               (with-out-str (pprint (srvr/hide-long-arrays unstarted-server))))
      (try
        (let [server (srvr/start! (assoc unstarted-server ::srvr/client-chan client-chan))]
          (try
            ;; Currently just called for side-effects.
            ;; TODO: Seems like I really should hide that little detail
            ;; by having it return this.
            ;; Except that that "little detail" really sets off the handshake
            ;; Q: Is there anything interesting about the deferred that it
            ;; currently returns?
            (clnt/start! client)
            (let [fut (deferred/chain (strm/take! (::clnt/chan->server client-chan))
                        (fn [hello]
                          (is (= 224 (count hello)))))]
              (is (not= (deref fut 500 ::timeout) ::timeout))
              (throw (Exception. "Don't stop there!")))
            (srvr/stop! server)))
        (catch clojure.lang.ExceptionInfo ex
          (is (not (.getData ex)))))
      (finally (.stop client-chan)))))
