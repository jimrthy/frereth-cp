(ns com.frereth.common.curve.interaction-test
  (:require [aleph.netty :as netty]
            [aleph.udp :as udp]
            [byte-streams :as bs]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is testing)]
            [clojure.tools.logging :as log]
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

(deftest verify-basic-round-trips
  "Can I encrypt/decrypt using the keys from the handshake test?"
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
      (testing "That keys match"
        (let [official (.-sharedKey client-standard-shared)]
          (is (b-t/bytes= client-shared-bytes official))
          (is (= 0 (bs/compare-bytes client-shared-bytes official))))
        (let [official (.-sharedKey server-shared)]
          (is (b-t/bytes= server-shared-nm official))
          (is (= 0 (bs/compare-bytes server-shared-nm official))))
        (testing "symmetric"
          (is (= 0 (bs/compare-bytes server-shared-nm client-shared-bytes)))))

      ;; This is fairly arbitrary...24 random-bytes seems better
      (aset-byte nonce 7 1)
      (testing "Offset and standard boxing"
        (let [crypto-text (crypto/box-after client-shared-bytes plain-text block-length nonce)
              crypto-text2 (crypto/box-after client-shared-bytes offset-text offset block-length nonce)
              crypto-text3 (.box client-standard-shared plain-text nonce)
              crypto-text3a (.box client-standard-shared plain-text nonce)]
          (testing "Low-level crypto I want"
            (is crypto-text)
            (testing "Encrypted box length"
                (is (= (count crypto-text) (+ (count plain-text)
                                              K/box-zero-bytes)))
                (when-not (= (count crypto-text) (count crypto-text3))
                  (println "My version is" (count crypto-text) "bytes long. The real thing is" (count crypto-text3)))
                (is (= (count crypto-text) (count crypto-text3))))
            (testing "Accomplished *something*"
              (is (not (b-t/bytes= crypto-text plain-text)))))
          (is crypto-text2 "Encrypting w/ offset failed")
          (testing "High-level interface"
            (is crypto-text3))
          (testing "Hashing vs. byte-wise"
            ;; When I was handling the initial padding incorrectly
            ;; (just prepending 16 zero bytes, and then returning
            ;; what that created without dropping anything,
            ;; as opposed to starting with 32 zero prefix bytes and
            ;; dropping 16 of them),
            ;; bytes= returned true.
            ;; That's what this particular part of this test
            ;; was all about
            (is (b-t/bytes= crypto-text crypto-text3))
            (is (= 0 (bs/compare-bytes crypto-text crypto-text3))
                (str "Just proved that\n"
                     (with-out-str (bs/print-bytes crypto-text))
                     "==\n"
                     (with-out-str (bs/print-bytes crypto-text3))
                     "even though they really are not"))
            (testing "Encryption is purely functional"
              ;; But the two boxed values really are the same
              (is (= 0 (bs/compare-bytes crypto-text3a crypto-text3)))))
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
                (let [;; This is the approach that I really think I should use
                      de3 (crypto/open-after crypto-text3 0 (count crypto-text) nonce server-shared-nm)
                      ;; Verify that my low-level open function can decrypt a box that was
                      ;; wrapped using the high-level approach
                      de4 (crypto/open-after crypto-text 0 (count crypto-text) nonce server-shared-nm)]
                  (if de3
                    (let [bs (byte-array de3)]
                      (is (b-t/bytes= bs plain-text)))
                    (is false "Failed to open the box I care about"))
                  (if de4
                    (let [bs (byte-array de4)]
                      (is (= 0 (bs/compare-bytes bs plain-text))))
                    (is false "Failed to open the box I care about")))))))))))

(defn retrieve-hello
  "This is really a server-side method"
  [client-chan hello]
  (println "Pulled HELLO from client")
  (let [n (.readableBytes hello)]
    (println "Have" n "bytes to write to " client-chan)
    (if (= 224 n)
      (strm/try-put! (:chan client-chan)
                     {:message (Unpooled/wrappedBuffer hello)
                      :host "test-client"
                      :port 65536}
                     500
                     ::timed-out)
      (throw (RuntimeException. "Bad Hello")))))

(defn wrote-hello
  [client-chan success]
  (is success "Failed to write hello to server")
  (is (not= success ::timed-out "Timed out waiting for server to read HELLO"))
  ;; This is timing out both here and in the server side.
  ;; So either I'm taking from the wrong channel here (which
  ;; seems more likely) or I've botched up the server basics.
  ;; Actually, even though it's seemed to work before, I
  ;; almost definitely need 2 channels for the server like
  ;; I set up for the client.
  (when (and success
             (not= success ::timed-out))
    ;; Note that the real thing has to be more robust.
    (log/debug "Waiting for server to send back HELLO response")
    (strm/try-take! (:chan client-chan) ::drained 500 ::timeout)))

(defn forward-cookie
  [client<-server cookie]
  (log/info "Received cookie packet from server:" cookie)
  (if-not (keyword? cookie)
    (let [msg (:message cookie)]
      ;; Q: So...how/when can I call release?
      (netty/acquire msg)
      (let [msg-size (.readableBytes msg)]
        (is (= 200 msg-size)))
      (when-not (< 0 (.refCnt msg))
        (log/error (str msg
                        ", a " (class msg)
                        "\nhas already been released.\n"
                        "This is going to be a very short trip.")))
        ;; Important detail: client/server are responsible
        ;; for coping with managing address/port manipulation
        ;; details.
        ;; This couples them more tightly than I like to aleph,
        ;; but life will get messy no matter what if/when I try
        ;; to switch to something like raw netty.

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
  (log/info "Top of client-child-spawner")
  ;; TODO: Other variants
  ;; 1. Start by writing 0 bytes
  ;; 2. Write, say, 480 bytes, send notification, then 320 more
  (let [read-notifier (strm/stream)
        buffer (Unpooled/buffer 2048)
        child (future
                (log/debug "Client child sending bytes to server via client")
                (.writeBytes buffer (byte-array (range 1025)))
                (let [wrote (strm/try-put! read-notifier
                                           buffer
                                           2500
                                           ::timedout)]
                  (log/debug "Client-child send result:" @wrote)
                  (is (not= @wrote ::timedout))))
        write-notifier (strm/stream)
        release-notifier (strm/stream)
        hidden [(strm/try-take! write-notifier ::drained 2500 ::timed-out)
                (strm/try-take! release-notifier ::drained 2500 ::timed-out)]]
    ;; It belongs under shared: it's even more vital on the server side.
    ;; The flip side to this is that it basically leads to writing my own
    ;; heap management, with things like performance analysis and tuning.
    ;; And I don't think I want to go down that rabbit hole.
    (comment (throw (RuntimeException. "Really have to use a shared ByteBuf pool instead")))
    (deferred/chain (hidden 1)
      (fn [success]
        (is (not (or (= success ::drained)
                     (= success ::timed-out))))
        ;; TODO: Make this more interesting.
        ;; Verify what we really got back
        ;; Send back a second block of data,
        ;; and wait for *that* response.
        (strm/close! write-notifier)
        (strm/close! release-notifier)
        (strm/close! read-notifier)))
    {::clnt/child child
     ::clnt/reader  read-notifier
     ::clnt/release release-notifier
     ::clnt/writer write-notifier
     ;; Q: Does it make any difference if I keep this around?
     ::hidden-child hidden}))

(deftest handshake
  (log/info "**********************************\nNew Hand-Shake test")
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
                                    :my-keys #::shared{::K/server-name server-name
                                                       :keydir "curve-test"}}
                 ::client {::shared/extension (byte-array [0x10 0x0f 0x0e 0x0d
                                                           0x0c 0x0b 0x0a 0x09
                                                           0x08 0x07 0x06 0x05
                                                           0x04 0x03 0x02 0x01])
                           ::clnt/child-spawner client-child-spawner
                           ::shared/my-keys {::K/server-name server-name}
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
                                 ::clnt/chan->server chan->server))]
    (try
      (let [unstarted-server (srvr/ctor (::server options))
            server<-client {:chan (strm/stream)}
            server->client {:chan (strm/stream)}]
        (try
          (log/debug "Starting server based on\n"
                     #_(with-out-str (pprint (srvr/hide-long-arrays unstarted-server)))
                     "...stuff...")
          (try
            (let [server (srvr/start! (assoc unstarted-server
                                             ::srvr/client-read-chan server<-client
                                             ::srvr/client-write-chan server->client))]
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
                  (let [write-hello (partial retrieve-hello server<-client)
                        build-cookie (partial wrote-hello server->client)
                        write-cookie (partial forward-cookie chan<-server)
                        get-cookie (partial wrote-cookie chan->server)
                        write-vouch (partial vouch->server server<-client)
                        get-server-response (partial wrote-vouch server->client)
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
                  (log/error (str "Unhandled exception escaped!\n"
                                  (with-out-str (.printStackTrace ex))))
                  (log/error "Client state:" (with-out-str (pprint (clnt/hide-long-arrays @client))))
                  (if-let [err (agent-error client)]
                    (println "Client failure:\n" err)
                    (println "(client agent thinks everything is fine)"))
                  (is (not ex)))
                (finally
                  (println "Test done. Stopping server.")
                  (srvr/stop! server))))
            (catch clojure.lang.ExceptionInfo ex
              (is (not (.getData ex)))))
          (finally (strm/close! (:chan server->client))
                   (strm/close! (:chan server<-client)))))
      (finally
        (clnt/stop! client)))))

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
