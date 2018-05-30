(ns frereth-cp.interaction-test
  ;; FIXME: Rename
  "This is really about message interactions"
  (:require [aleph.netty :as netty]
            [aleph.udp :as udp]
            [byte-streams :as bs]
            [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.client :as clnt]
            [frereth-cp.client.state :as clnt-state]
            [frereth-cp.server :as srvr]
            [frereth-cp.server.state :as srvr-state]
            [frereth-cp.server-test :as server-test]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.specs :as specs]
            [manifold.deferred :as dfrd]
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
            server-pair (crypto/do-load-keypair keydir)
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
        server-pair (crypto/do-load-keypair keydir)
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

      (testing "symmetric"
        (is (= 0 (bs/compare-bytes server-shared-nm client-shared-bytes))))

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
                    (let [bs (byte-array (.readableBytes de3))]
                      (.readBytes de3 bs)
                      (is (b-t/bytes= bs plain-text)))
                    (is false "Failed to open the box I care about"))
                  (if de4
                    (let [bs (byte-array (.readableBytes de4))]
                      (.readBytes de4 bs)
                      (is (= 0 (bs/compare-bytes bs plain-text))))
                    (is false "Failed to open the box I care about")))))))))))

(defn retrieve-hello
  "This is really a server-side method"
  [mem-pool client-chan hello]
  (log/info "Pulled HELLO from client")
  (let [n (.readableBytes hello)]
    (println "Have" n "bytes to write to " client-chan)
    (if (= 224 n)
      (let [copy (.directBuffer mem-pool n)]
        (.readBytes hello copy)
        (.release hello)
        (strm/try-put! (:chan client-chan)
                       {:message copy
                        :host "test-client"
                        :port 65536}
                       500
                       ::timed-out))
      (throw (RuntimeException. "Bad Hello")))))

(defn wrote-hello
  [client-chan success]
  (log/info "Wrote HELLO to server")
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
      ;; And do I really need to?
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
    (throw (ex-info "Bad Cookie packet from Server"
                    {:problem cookie}))))

(defn wrote-cookie
  [clnt-> success]
  (log/info "Wrote cookie packet to Client")
  (assert success)
  (assert (not (keyword? success)))
  (when (not= success ::timeout)
    (log/info "Server Cookie sent to client. Waiting for Initiate packet in response")
    (strm/try-take! clnt-> ::drained 500 ::timeout)))

(defn vouch->server
  [mem-pool ->server vouch]
  ;; I don't have any real failure indication available
  ;; if something goes wrong with/on the server trying
  ;; to cope with this incoming vouch.
  ;; I almost need an error stream for dealing with exceptions.
  (log/info "Got Initiate packet from client: "
            vouch
            " for forwarding along to "
            ->server)
  (is (not (keyword? vouch)))
  ;; We just forwarded the from the server to the
  ;; client (in forward-cookie).
  ;; Now we pulled the Initiate packet in response
  ;; (in wrote-cookie).
  ;; The main point here is to forward that packet
  ;; back to the Server.
  (if-not (or (= vouch ::drained)
              (= vouch ::timeout))
    (let [copy (.directBuffer mem-pool (.readableBytes vouch))]
      (.readBytes vouch copy)
      (.release vouch)
      (strm/try-put! (:chan ->server)
                     {:message copy
                      :host "tester-client"
                      :port 65536}
                     500
                     ::timeout))
    (throw (ex-info "Retrieving Vouch from client failed"
                    {:failure vouch}))))

(defn wrote-vouch
  "Vouch went to server. Now pull its response"
  [server-> success]
  (is (not (keyword? success)))
  (if success
    (strm/try-take! (:chan server->) ::drained 500 ::timeout)
    (throw (RuntimeException. "Failed writing Vouch to server"))))

(defn finalize
  [->client response]
  (if (and response
             (not (keyword? response)))
    (strm/try-put! ->client
                   {:message response
                    :host "interaction-test-server"
                    :port -1}
                   500
                   ::timeout)
    (throw (ex-info "Waiting for a server ACK failed"
                    {::received response}))))

(defn notified-about-release
  [write-notifier release-notifier read-notifier released-buffer]
  ;; The release-notifier times out now.
  ;; I don't think the client's getting a response here
  (log/info (str "Client is releasing child buffer: " released-buffer
                 "\nwrite-notifier:\n\t" write-notifier
                 "\nrelease-notifier:\n\t" release-notifier
                 "\nread-notifier:\n\t" read-notifier
                 "\nat: " (System/nanoTime)))
  ;; I definitely see this failure, but it isn't showing up as
  ;; a test failure.
  ;; Q: Is this a background-thread hidden sort of thing?
  ;; Maybe CIDER just isn't clever enough to spot it?

  (is (not (= released-buffer ::timed-out)))
  (is (not (= released-buffer ::drained)))
  ;; This is just the tip of the iceberg showing
  ;; why this approach was a terrible idea.
  (is (= released-buffer released-buffer))
  ;; TODO: Make this more interesting.
  ;; Verify what we really got back
  ;; Send back a second block of data,
  ;; and wait for *that* response.

  (strm/close! write-notifier)
  (strm/close! release-notifier)
  (strm/close! read-notifier))

(defn client-child
  [buffer write-notifier release-notifier read-notifier]
  (log/info "Client child sending bytes to server via client at "
            (System/nanoTime))
  (.writeBytes buffer (byte-array (range 1025)))
  (let [wrote (strm/try-put! write-notifier
                             buffer
                             2500
                             ::timedout)]
    ;; This is timing out or failing.
    ;; So the client is reading/waiting for the wrong thing.
    ;; Sometimes.
    ;; Q: What's up with that?
    (let [succeeded (deref wrote 3000 ::check-timeout)]
      (log/info (str "Client-child send result to " write-notifier " => "  succeeded " @ " (System/nanoTime)))
      ;; That should work around my current bug, though it's ignoring a
      ;; fundamental design flaw.
      (dfrd/chain release-notifier (partial notified-about-release write-notifier release-notifier read-notifier))
      (is succeeded)
      (is (not= succeeded ::timedout)))))

(defn client-child-spawner
  [client-agent]
  (log/info "Top of client-child-spawner")
  ;; TODO: Other variants
  ;; 1. Start by writing 0 bytes
  ;; 2. Write, say, 480 bytes, send notification, then 320 more
  (let [write-notifier (strm/stream)
        ;; Real implementations really must use a
        ;; PooledByteBufAllocator.
        ;; Of course, that needs to get set up at the
        ;; outer pipeline level.
        ;; Client shouldn't care: when it's done
        ;; reading a buffer, it should call .release
        ;; and be done with it.
        ;; TODO: Make that happen (just not tonight)
        buffer (Unpooled/buffer 2048)
        release-notifier (strm/stream)
        read-notifier (strm/stream)
        child (future (client-child buffer
                                    write-notifier
                                    release-notifier
                                    read-notifier))
        hidden [(strm/try-take! read-notifier ::drained 2500 ::timed-out)
                (strm/try-take! release-notifier ::drained 2500 ::timed-out)]]
    {::clnt-state/child child
     ::clnt-state/reader  read-notifier
     ::clnt-state/release release-notifier
     ::clnt-state/writer write-notifier
     ;; Q: Does it make any difference if I keep this around?
     ::hidden-child hidden}))

(s/fdef server-child-spawner
        :args (s/cat :write-stream strm/stream?)
        :ret ::srvr-state/child-interaction)
(defn server-child-spawner
  [read-stream]
  (log/info "Spawning a server child")
  (let [write-stream (strm/stream)
        echoer (strm/consume (fn [buffer]
                               (log/info "Incoming:" buffer)
                               (assert buffer)
                               ;; Realistically, this needs to read the bytes
                               ;; from the buffer we just received, .release
                               ;; it, then do something with them.
                               ;; I don't much care about realism
                               (let [responded (strm/try-put! write-stream buffer 250 ::time-out)]
                                 (dfrd/on-realized responded
                                                   (fn [success]
                                                     (is success "Did the parent side close its channel?")
                                                     (is (not= success ::time-out) "Parent too busy"))
                                                   (fn [failure]
                                                     (throw (ex-info "Shouldn't be possible"
                                                                     {::problem failure}))))))
                             read-stream)]
    (when (not echoer)
      (throw (ex-info "strm/consume returned falsey"
                      {::problem echoer
                       ::details "Docstring claims it returns a deferred"})))
    (dfrd/on-realized echoer
                      (fn [success]
                        (is success "Per docstring: consume yields true on channel close"))
                      (fn [failure]
                        (throw (ex-info "Could this happen if consume throws an exception?"
                                        {:problem failure}))))
    #:frereth-cp.server.state {:child-id (gensym)
                               :read<-child write-stream
                               :write->child read-stream
                               ::hidden echoer}))

(defn double-check-long-term-shared-secrets
  [client server]
  (let [client-long (-> client
                        deref
                        (get-in [::shared/my-keys ::shared/long-pair]))
        client-public (.getPublicKey client-long)
        client-secret (.getSecretKey client-long)
        server-long (get-in server [::shared/my-keys ::shared/long-pair])
        server-public (.getPublicKey server-long)
        server-secret (.getSecretKey server-long)
        client->server (crypto/box-prepare server-public client-secret)
        server->client (crypto/box-prepare client-public server-secret)]
    (testing "Shared secrets match"
      (log/info "Initial shared secrets:\n"
                "Client-Secret<->Server-Public:\n"
                (b-t/->string client->server)
                "Server-Secret<->Client-Public:\n"
                (b-t/->string server->client))
      ;; The shared secret this produces:
      #_[0xB0 0x99 0xE8 0x62
       0xC9 0xC0 0x47 0x95
       0x6E 0xF7 0x14 0xEE
       0xBC 0xF6 0x82 0x54
       0x23 0x1B 0x0D 0x88
       0x1F 0x29 0xA3 0x4C
       0x22 0xA8 0xAA 0xAA
         0x56 0xAE 0x75 0x23]
      ;; This matches what the client generated
      (is (b-t/bytes= client->server server->client))
      (is (= (vec client->server) (vec server->client))))))

(deftest viable-server
  ;; TODO: Start this from build-hand-shake-options
  ;; to be sure I'm comparing apples to apples
  (testing "Does handshake start with a usable server?"
    (let [server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                        0x0d 0x0e 0x0f 0x10])
          server-name (shared/encode-server-name "test.frereth.com")
          options #::shared{:extension server-extension
                            :my-keys #::shared{::K/server-name server-name
                                               :keydir "curve-test"}}
          unstarted-server (srvr/ctor options)
          server<-client {:chan (strm/stream)}
          server->client {:chan (strm/stream)}]
      (try
        (let [server (srvr/start! (assoc unstarted-server
                                         ::srvr-state/client-read-chan server<-client
                                         ::srvr-state/client-write-chan server->client))]
          (try
            (is (-> server ::srvr-state/active-clients deref))
            (is (= 0 (-> server ::srvr-state/active-clients deref count)))
            (is (not (srvr-state/find-client server (.getBytes "won't find this"))))
            (finally (srvr/stop! server))))
        (finally
          (strm/close! (:chan server->client))
          (strm/close! (:chan server<-client)))))))

(comment
  (let [v1 (byte-array [0x25 0x6C 0xC9 0xE4
                        0x19 0xD3 0x18 0x5D
                        0x33 0x97 0x95 0x83
                        0x88 0xD7 0x53 0xD2
                        0xE9 0xB8 0x6D 0xC6
                        0x9C 0x57 0x73 0x5F
                        0x59 0xB6 0xEB 0xDF
                        0x14 0x15 0x6E 0x5F])]
    (vec v1)))

(defn build-hand-shake-options
  []
  (let [server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                      0x0d 0x0e 0x0f 0x10])
        ;; This is the value we're supplying to the client.
        ;; At first glance, it looks like it does not match reality.
        ;; Except that it does
        original-server-long-pk (byte-array [37 108 -55 -28
                                             25 -45 24 93
                                             51 -105 -107 -125
                                             -120 -41 83 -46
                                             -23 -72 109 -58
                                             -100 87 115 95
                                             89 -74 -21 -33
                                             20 21 110 95])
        actual-server-long-pk (byte-array [0x25 0x6C 0xC9 0xE4
                                           0x19 0xD3 0x18 0x5D
                                           0x33 0x97 0x95 0x83
                                           0x88 0xD7 0x53 0xD2
                                           0xE9 0xB8 0x6D 0xC6
                                           0x9C 0x57 0x73 0x5F
                                           0x59 0xB6 0xEB 0xDF
                                           0x14 0x15 0x6E 0x5F])
        ;; This is the decimal those translate into
        server-long-pk (byte-array [37 108 -55 -28
                                    25 -45 24 93
                                    51 -105 -107 -125
                                    -120 -41 83 -46
                                    -23 -72 109 -58
                                    -100 87 115 95
                                    89 -74 -21 -33
                                    20 21 110 95])
        server-name (shared/encode-server-name "test.frereth.com")]
    {::server #::shared{:extension server-extension
                        :my-keys #::shared{::K/server-name server-name
                                           :keydir "curve-test"}
                        ::srvr-state/child-spawner! server-child-spawner}
     ::client {::shared/extension (byte-array [0x10 0x0f 0x0e 0x0d
                                               0x0c 0x0b 0x0a 0x09
                                               0x08 0x07 0x06 0x05
                                               0x04 0x03 0x02 0x01])
               ::specs/child-spawner! client-child-spawner
               ;; Based on this, the client should be setting up
               ;; a random key pair every time.
               ;; Maybe I'm screwing something up royally and
               ;; missing a random number generator seed call,
               ;; but the keys I'm seeing look suspiciously
               ;; uniform
               ::shared/my-keys {::K/server-name server-name}
               ::clnt-state/server-extension server-extension
               ;; Q: Where did I get the server's public key?
               ;; A: By manually copying over what NaCl produces
               ;; when I hand it the hard-coded secret key that
               ;; I'm reusing.
               ;; Q: Do I want to mirror what the code does to load the
               ;; secret key from a file?
               ;; I could just generate a random key pair for the server.
               ;; Use the key-put functionality to store the secret, then
               ;; hard-code the public key here.
               ;; A: Maybe for some other test.
               ;; For this one, it's too useful to have known keys
               ;; getting passed around
               ::clnt-state/server-security {::clnt-state/server-long-term-pk server-long-pk
                                             ::K/server-name server-name}}}))

(deftest handshake
  (log/info "**********************************\nNew Hand-Shake test")
  ;; Shouldn't be trying to re-use buffers produced at client side on the server.
  ;; And vice-versa.
  ;; That's just adding needless complexity
  (let [options (build-hand-shake-options)
        ;; Note that the channel names in here seem backward.
        ;; Remember that they're really a mirror image:
        ;; So this is really the stream that the client uses
        ;; to send data to us
        chan->server (strm/stream)
        chan<-server (strm/stream)
        ;; TODO: This seems like it would be a great place to try switching to integrant
        client (clnt/ctor (assoc (::client options)
                                 ::clnt-state/chan<-server chan<-server
                                 ::clnt-state/chan->server chan->server))]
    (log/warn "Verify that (crypto/random-keypair) really is random")
    (log/warn "TODO: Switch to hard-coded client key pair for debugging ease")
    (try
      (let [unstarted-server (srvr/ctor (::server options))
            chan<-client {:chan (strm/stream)}
            chan->client {:chan (strm/stream)}]
        (try
          (log/debug "Starting server based on\n"
                     #_(with-out-str (pprint (srvr/hide-long-arrays unstarted-server)))
                     "...stuff...")
          (try
            (let [server (srvr/start! (assoc unstarted-server
                                             ::srvr-state/client-read-chan chan<-client
                                             ::srvr-state/client-write-chan chan->client))]
              (try
                (double-check-long-term-shared-secrets client server)
                ;; Currently just called for side-effects.
                ;; TODO: Seems like I really should hide that little detail
                ;; by having it return this.
                ;; Except that that "little detail" really sets off the handshake
                ;; Q: Is there anything interesting about the deferred that it
                ;; currently returns?
                (let [eventually-started (clnt/start! client)
                      clnt->srvr (::clnt-state/chan->server @client)
                      ;; Start with one that prefers direct buffers, even though it doesn't
                      ;; make a lot of sense for this test.
                      ;; I'm as certain as I can be (without actual metrics) that's the most
                      ;; realistic picture I'll get of the way it needs to really work
                      mem-pool (io.netty.buffer.PooledByteBufAllocator. true)]
                  (assert (= chan->server clnt->srvr)
                          (str "Client channels don't match.\n"
                               "Expected:" chan->server
                               "\nHave:" clnt->srvr))
                  (assert chan->server)
                  (let [write-hello (partial retrieve-hello mem-pool chan<-client)
                        build-cookie (partial wrote-hello chan->client)
                        write-cookie (partial forward-cookie chan<-server)
                        ;; This pulls the Initiate packet from the client
                        get-cookie (partial wrote-cookie chan->server)
                        write-vouch (partial vouch->server mem-pool chan<-client)
                        get-server-response (partial wrote-vouch chan->client)
                        write-server-response (partial finalize chan<-server)
                        _ (log/info "interaction-test: Starting the stream "
                                    clnt->srvr)
                        fut (dfrd/chain (strm/take! clnt->srvr)
                              write-hello
                              build-cookie
                              write-cookie
                              get-cookie
                              write-vouch
                              get-server-response
                              write-server-response
                              (fn [wrote]
                                (is (not= wrote ::timeout))))]
                    (log/info "Dereferencing the deferreds set up by handshake")
                    (let [outcome (deref fut 5000 ::timeout)]
                      (when (instance? Exception outcome)
                        (if (instance? RuntimeException outcome)
                          (if (instance? ExceptionInfo outcome)
                            (log/error outcome (str "FAIL:\n"
                                                    (with-out-str (pprint (.getData outcome)))))
                            (do
                              (log/error outcome "Ugly failure:")))
                          (log/error outcome "Low Level Failure:"))
                        (.printStackTrace outcome)
                        (throw outcome))
                      (is (not= outcome ::timeout)))
                    ;; This really should have been completed as soon as
                    ;; I read from chan->server2 the first time
                    ;; Q: Right?
                    (is (not= (deref eventually-started 500 ::timeout)
                              ::timeout))))
                (catch Exception ex
                  ;; FIXME: This is failing due to "Bad Cookie packet from Server"
                  (log/error ex
                             (str "Unhandled exception escaped!\n"
                                  "Stack Trace:\n"
                                  ;; TODO: Switch to util/get-stack-trace
                                  (with-out-str (.printStackTrace ex))
                                  "\nClient state:\n"
                                  (with-out-str (pprint (clnt/hide-long-arrays @client)))
                                  (if-let [err (agent-error client)]
                                    (str "\nClient failure:\n" err)
                                    (str "\n(client agent thinks everything is fine)"))))
                  (is (not ex)))
                (finally
                  (log/info "Test done. Stopping server.")
                  (srvr/stop! server))))
            (catch clojure.lang.ExceptionInfo ex
              (let [msg (str "Unhandled ex-info:\n"
                             ex
                             "\nAssociated Data:\n"
                             (.getData ex)
                             "\nStack Trace:\n"
                             (with-out-str (.printStackTrace ex)))]
                (is false msg))))
          (finally (strm/close! (:chan chan->client))
                   (strm/close! (:chan chan<-client)))))
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
