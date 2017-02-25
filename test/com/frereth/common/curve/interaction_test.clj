(ns com.frereth.common.curve.interaction-test
  (:require [aleph.udp :as udp]
            [byte-streams :as bs]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.client :as clnt]
            [com.frereth.common.curve.server :as srvr]
            [com.frereth.common.curve.server-test :as server-test]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.constants :as K]
            [com.frereth.common.curve.shared.crypto :as crypto]
            [com.frereth.common.curve.shared.bit-twiddling :as b-t]
            [manifold.deferred :as deferred]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box
           io.netty.buffer.Unpooled))

(defn retrieve-hello
  "This is really a server-side method"
  [client-chan hello]
  (println "Pulled HELLO from client")
  (let [n (.readableBytes hello)]
    (println "Have" n "bytes to write to " client-chan)
    (if (= 224 n)
      (strm/put! (:chan client-chan)
                 {:message (Unpooled/wrappedBuffer hello)
                  :host "test-client"
                  :port 65536})
      (throw (RuntimeException. "Bad Hello")))))

(defn wrote-hello
  [client-chan success]
  (is success "Failed to write hello to server")
  ;; I'm pretty sure I need to split
  ;; this into 2 channels so I don't pull back
  ;; the hello that I just put on there
  ;; Although it would be really sweet if ztellman
  ;; handled this for me.
  (strm/try-take! (:chan client-chan) ::drained 500 ::timeout))

(defn forward-cookie
  [client<-server cookie]
  (println "Received cookie packet from server:" cookie)
  (if-not (keyword? cookie)
    (do
      (is (= 200 (count (:message cookie))))
      (strm/try-put! client<-server
                     cookie
                     500
                     ::timeout))
    (throw (ex-info "Bad cookie"
                    {:problem cookie}))))

(defn wrote-cookie
  [clnt->srvr success]
  (println "Server cookie sent. Waiting for vouch")
  (is success)
  (is (not= success ::timeout))
  (strm/try-take! clnt->srvr ::drained 500 ::timeout))

(defn vouch->server
  [client-chan vouch]
  (if-not (or (= vouch ::drained)
              (= vouch ::timeout))
    (strm/try-put! client-chan
                   {:message vouch
                    :host "tester"
                    :port 65536}
                   500
                   ::timeout)
    (throw (ex-info "Retrieving Vouch from client failed"
                    {:failure vouch}))))

(defn wrote-vouch
  [client-chan success]
  (if success
    (strm/try-take! client-chan ::drained 500 ::timeout)
    (throw (RuntimeException. "Failed writing Vouch to client"))))

(defn finalize
  [client<-server response]
  (is response "Handshake should be complete")
  (strm/try-put! client<-server
                 {:message response
                  :host "interaction-test-server"
                  :port -1}
                 500
                 ::timeout))

(defn client-child-spawner
  [client-agent]
  (comment (spit "/home/james/hey-you.txt" "Spawning child"))
  (println "Top of client-child-spawner")
  ;; Q: What should this really do?
  (let [result (strm/stream)
        child (future
                (println "Client child sending bytes to server via client")
                (let [written (strm/try-put! result
                                             "Hello, out there!"
                                             2500
                                             ::timedout)]
                  (println "Client-child send result:" @written)))]
    {::clnt/child child
     ::clnt/reader result
     ::clnt/writer strm/stream}))

(deftest basic-sanity
  (testing "Does the basic idea work?"
      (let [server-long-pk (byte-array [37 108 -55 -28 25 -45 24 93
                                        51 -105 -107 -125 -120 -41 83 -46
                                        -23 -72 109 -58 -100 87 115 95
                                        89 -74 -21 -33 20 21 110 95])
            keydir "curve-test"
            server-pair (shared/do-load-keypair keydir)
            client-pair (crypto/random-key-pair)
            client-shared (TweetNaclFast$Box. server-long-pk (.getSecretKey client-pair))
            server-shared (TweetNaclFast$Box.
                           (.getPublicKey client-pair)
                           (.getSecretKey server-pair))
            block-length 50
            plain-text (byte-array (range block-length))
            nonce (byte-array K/nonce-length)]
        (aset-byte nonce 7 1)
        (let [crypto-text (.box client-shared plain-text nonce)
              decrypted (.open server-shared crypto-text nonce)]
          (is (b-t/bytes= decrypted plain-text))))))

(deftest verify-keys
  "Did I botch up my server keys?"
  (let [server-long-pk (byte-array [37 108 -55 -28 25 -45 24 93
                                    51 -105 -107 -125 -120 -41 83 -46
                                    -23 -72 109 -58 -100 87 115 95
                                    89 -74 -21 -33 20 21 110 95])
        keydir "curve-test"
        server-pair (shared/do-load-keypair keydir)
        pk (.getPublicKey server-pair)]
    (testing "Disk matches hard-coded in-memory"
        (is (b-t/bytes= pk server-long-pk)))
    (let [client-pair (crypto/random-key-pair)
          client-shared-bytes (crypto/box-prepare server-long-pk (.getSecretKey client-pair))
          client-standard-shared (TweetNaclFast$Box. server-long-pk (.getSecretKey client-pair))
          server-shared (TweetNaclFast$Box.
                         (.getPublicKey client-pair)
                         (.getSecretKey server-pair))
          server-shared-nm (crypto/box-prepare
                            (.getPublicKey client-pair)
                            (.getSecretKey server-pair))
          block-length 50
          plain-text (byte-array (range block-length))
          offset 32
          offset-text (byte-array (+ offset block-length))
          nonce (byte-array K/nonce-length)]
      (b-t/byte-copy! offset-text offset block-length plain-text)
      ;; TODO: Roll back my debugging changes to the java code
      ;; to get back to the canonical version.
      ;; Then work with copies and never change that one again.
      ;; Getting public access to the shared key like this was one
      ;; of the more drastic changes
      ;; Q: Why can't I access this?
      (comment)
      (is (b-t/bytes= client-shared-bytes (.-sharedKey client-standard-shared)))
      (is (b-t/bytes= server-shared-nm (.-sharedKey server-shared)))
      ;; This is fairly arbitrary...24 random-bytes seems better
      (aset-byte nonce 7 1)
      (testing "Offset and standard boxing"
        (let [crypto-text (crypto/box-after client-shared-bytes plain-text block-length nonce)
              crypto-text2 (crypto/box-after client-shared-bytes offset-text offset block-length nonce)
              crypto-text3 (.box client-standard-shared plain-text nonce)]
          (testing "Low-level crypto I want"
            (is crypto-text)
            (testing "Encrypted box length"
                (is (= (count crypto-text) (+ (count plain-text)
                                              K/box-zero-bytes))))
            (testing "Something happened"
              (is (not (b-t/bytes= crypto-text plain-text)))))
          (comment
            (is crypto-text2 "Figure out a good way to make this version work"))
          (testing "High-level interface"
            (is crypto-text3))
          ;; Something really strange is going on here.
          ;; This comparison succeeds.
          ;; The two sets of bytes are absolutely *not* equal.
          ;; Maybe it's computing a hash, and there's a collision?
          ;; I can regularly decrypt crypto-text3, but not crypto-text.
          (is (b-t/bytes= crypto-text crypto-text3))
          (testing "Hashing vs. byte-wise"
            ;; Demonstrate that, really, those values look totally different
            ;; to someone as clueless as I.
            (is (= 0 (bs/compare-bytes crypto-text crypto-text3))
                (str "Just proved that\n"
                     (with-out-str (bs/print-bytes crypto-text))
                     "==\n"
                     (with-out-str (bs/print-bytes crypto-text3))
                     "even though they really are not")))
          (testing "Decryption"
            (let [de2 (.open server-shared crypto-text3 nonce)  ; easiest, slowest approach
                  ;; This is the approach that almost everyone will use
                  decrypted (.open_after server-shared crypto-text3 0 (count crypto-text) nonce)]
              (testing "Most likely decryption approach"
                (if decrypted
                  (is (b-t/bytes= decrypted plain-text))
                  (is false "Most common decryption approach failed")))
              (testing "Most obvious high level decryption"
                (if de2
                  (is (b-t/bytes= de2 plain-text))
                  (is false (str "Simplest decryption failed\n"
                                 "Trying to decrypt\n"
                                 (with-out-str (bs/print-bytes crypto-text)))))))
            (testing "Low-level 'nm' decryption"
              (try
                (println "Getting ready to try to decrypt. Including using" server-shared-nm "a" (class server-shared-nm)
                         "containing" (count server-shared-nm) "bytes")
                (let [;; This is the approach that I really should use
                      de3 (crypto/open-after crypto-text3 0 (count crypto-text) nonce server-shared-nm)
                      de4 (crypto/open-after crypto-text 0 (count crypto-text) nonce server-shared-nm)]
                  (if de3
                    (let [bs (byte-array de3)]
                      (is (b-t/bytes= bs plain-text)))
                    (is false "Failed to open the box I care about"))
                  (if de4
                    (let [bs (byte-array de4)]
                      (is (= 0 (bs/compare-bytes bs plain-text))))
                    (is false "Failed to open the box I care about")))))))))))

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
                           ::clnt/child-spawner client-child-spawner
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
               #_(with-out-str (pprint (srvr/hide-long-arrays unstarted-server)))
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
            (let [eventually-started (clnt/start! client)
                  clnt->srvr (::clnt/chan->server @client)]
              (assert (= chan->server clnt->srvr)
                      (str "Client channels don't match.\n"
                           "Expected:" chan->server
                           "\nHave:" clnt->srvr))
              (assert clnt->srvr)
              (let [write-hello (partial retrieve-hello client-chan)
                    build-cookie (partial wrote-hello client-chan)
                    write-cookie (partial forward-cookie chan<-server)
                    get-cookie (partial wrote-cookie client-chan)
                    write-vouch (partial vouch->server client-chan)
                    get-server-response (partial wrote-vouch client-chan)
                    write-server-response (partial finalize chan<-server)
                    _ (println "interaction-test: Starting the stream "
                               clnt->srvr)
                    fut (deferred/chain (strm/take! clnt->srvr)
                          write-hello
                          build-cookie
                          write-cookie
                          get-cookie
                          write-vouch
                          get-server-response
                          write-server-response
                          (fn [wrote]
                            (is (not= wrote ::timeout))))]
                (println "Dereferencing the deferreds set up by handshake")
                (let [outcome (deref fut 5000 ::timeout)]
                  (when (instance? Exception outcome)
                    (if (instance? RuntimeException outcome)
                      (if (instance? ExceptionInfo outcome)
                        (do
                          (println "FAIL:" outcome)
                          (pprint (.getData outcome)))
                        (do
                          (println "Ugly failure:" outcome)))
                      (println "Low Level Failure:" outcome))
                    (.printStackTrace outcome)
                    (throw outcome))
                  (is (not= outcome ::timeout)))
                ;; This really should have been completed as soon as
                ;; I read from chan->server2 the first time
                ;; Q: Right?
                (is (not= (deref eventually-started 500 ::timeout)
                          ::timeout))))
            (catch Exception ex
              (println "Unhandled exception escaped!")
              (.printStackTrace ex)
              (println "Client state:" (with-out-str (pprint (clnt/hide-long-arrays @client))))
              (if-let [err (agent-error client)]
                (println "Client failure:\n" err)
                (println "(client agent thinks everything is fine)"))
              (is (not ex)))
            (finally
              (println "Test done. Stopping server.")
              (srvr/stop! server))))
        (catch clojure.lang.ExceptionInfo ex
          (is (not (.getData ex)))))
      (finally (.stop client-chan)))))

(defn translate-raw-incoming
  [{:keys [host message port]
    :as packet}]
  (println "Server received a map:" packet "with a" (class message) ":message")
  (assoc packet :translated (Unpooled/wrappedBuffer message)))

(deftest basic-udp-handler
  (testing "Really just verifying that I receive byte arrays and can trivially convert them to ByteBuf."
    ;; Although it also demonstrates the basic point behind writing responses.
    ;; It isn't complicated, but I'm responsible for the details
    (let [port 26453
          client1-socket @(udp/socket {})]
      (try
        (let [client2-socket @(udp/socket {})]
          (try
            (let [server-socket @(udp/socket {:port port})]
              (try
                (testing "Sending"
                  (->> server-socket
                       (strm/map translate-raw-incoming)
                       (strm/consume (fn [incoming]
                                       (let [buf (:translated incoming)
                                             n (.readLong buf)]
                                         (println "Server read:" n)
                                         (let [write (strm/try-put! server-socket
                                                                    {:message (byte-array [0 0 0 0 0 0 0 (inc n)])
                                                                     :host (:host incoming)
                                                                     :port (:port incoming)}
                                                                    10
                                                                    ::timed-out)]
                                           (is (not= @write ::timed-out)))
                                         ))))
                  (let [put1 @(strm/try-put! client1-socket
                                             {:message (byte-array [0 0 0 0 0 0 0 1])
                                              :host "localhost"
                                              :port port}
                                             10
                                             ::timed-out)]
                    (is (not= put1 ::timed-out)))
                  (let [put2 @(strm/try-put! client2-socket
                                             {:message (byte-array [0 0 0 0 0 0 0 16])
                                              :host "localhost"
                                              :port port}
                                             10
                                             ::timed-out)]
                    (is (not= put2 ::timed-out))))
                (testing "Response"
                  ;; To make this realistic, I should convert the :message pieces to ByteBuf
                  ;; and call .readInt.
                  (let [pull1 @(strm/try-take! client1-socket ::drained 20 ::timed-out)]
                    (is (= 2 (aget (:message pull1) 7))))
                  (let [pull2 @(strm/try-take! client2-socket ::drained 20 ::timed-out)]
                    (is (= 17 (aget (:message pull2) 7)))))
                (finally
                  (strm/close! server-socket))))
            (finally
              (strm/close! client2-socket))))
        (finally
          (strm/close! client1-socket))))))
