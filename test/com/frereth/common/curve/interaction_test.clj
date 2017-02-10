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
        chan->server (strm/stream)
        chan<-server (strm/stream)
        ;; TODO: This seems like it would be a great place to try switching to integrant
        client (clnt/ctor (assoc (::client options)
                                 ::clnt/chan<-server chan<-server
                                 ::clnt/chan->server chan->server))
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
               (comment (with-out-str (pprint (srvr/hide-long-arrays unstarted-server))))
               "...stuff...")
      (try
        (let [server (srvr/start! (assoc unstarted-server ::srvr/client-chan client-chan))]
          (try
            ;; Currently just called for side-effects.
            ;; TODO: Seems like I really should hide that little detail
            ;; by having it return this.
            ;; Except that that "little detail" really sets off the handshake
            ;; Q: Is there anything interesting about the deferred that it
            ;; currently returns?
            (let [eventually-started (clnt/start! client)]
              ;; Getting a false here.
              ;; Q: What gives?
              (let [chan->server2 (::clnt/chan->server @client)
                    _ (when-not (= chan->server chan->server2)
                        (assert false (str "Client channels don't match.\n"
                                           "Expected:" chan->server
                                           "\nHave:" chan->server2)))
                    clnt->srvr (:chan chan->server2)
                    fut (deferred/chain (strm/take! clnt->srvr)
                          (fn [hello]
                            (is (= 224 (count hello)))
                            (strm/put! client-chan hello))
                          (fn [success]
                            (is success "Failed to write hello to server")
                            ;; TODO: I'm pretty sure I need to split
                            ;; this into 2 channels so I don't pull back
                            ;; the hello that I just put on there
                            (strm/try-take! client-chan ::drained 500 ::timeout))
                          (fn [cookie]
                            (is (= 200 (count cookie)))
                            (strm/try-put! chan<-server cookie 500 ::timeout))
                          (fn [success]
                            (is success)
                            (is (not= success ::timeout))
                            (strm/try-take! clnt->srvr ::drained 500 ::timeout))
                          (fn [vouch]
                            (if (and (not= vouch ::drained)
                                     (not= vouch ::timeout))
                              (strm/try-put! client-chan vouch 500 ::timeout)
                              (throw (ex-info "Retrieving Vouch from client failed"
                                              {:failure vouch}))))
                          (fn [success]
                            (if success
                              (strm/try-take! client-chan ::drained 500 ::timeout)
                              (throw (RuntimeException. "Failed writing Vouch to client"))))
                          (fn [response]
                            (is response "Handshake should be complete")
                            (strm/try-put! chan<-server response 500 ::timeout))
                          (fn [responded]
                            (is (not= responded ::timeout))))]
                (is (not= (deref fut 500 ::timeout) ::timeout))
                ;; This really should have been completed as soon as
                ;; I read from chan->server2 the first time
                ;; Q: Right?
                (is (not= (deref eventually-started 500 ::timeout)
                          ::timeout))
                (throw (Exception. "Don't stop there!"))))
            (srvr/stop! server)))
        (catch clojure.lang.ExceptionInfo ex
          (is (not (.getData ex)))))
      (finally (.stop client-chan)))))
