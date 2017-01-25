(ns com.frereth.common.curve.client-test
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.client :as clnt]
            [com.frereth.common.curve.shared :as shared]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm]))

(defn raw-client
  [child-spawner]
  (let [server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                      0x0d 0x0e 0x0f 0x10])
        server-long-pk (byte-array [37 108 -55 -28 25 -45 24 93
                                    51 -105 -107 -125 -120 -41 83 -46
                                    -23 -72 109 -58 -100 87 115 95
                                    89 -74 -21 -33 20 21 110 95])
        server-name (shared/encode-server-name "hypothet.i.cal")]
    (clnt/ctor {;; It seems wrong for this to be a bidirectional stream
                ;; instead of a pair of core.async channel that I treat
                ;; as unidirectional.
                ;; But this is what aleph is going to give me.
                ::clnt/chan<->server (strm/stream)
                ::clnt/child-spawner child-spawner
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
                                        ::shared/server-name server-name}})))

(deftest step-1
  (testing "The first basic thing that clnt/start does"
    (let [client (raw-client nil)
          chan<->server (-> client deref ::clnt/chan<->server)]
        (strm/on-drained chan<->server
                         #(send client clnt/server-closed!))
        (send client clnt/do-build-hello)
        (await-for 150 client)
        (is @client)
        (let [basic-check "Did this work?"
              fut (future (let [d (strm/try-put! chan<->server basic-check 150 ::timed-out)]
                            (dfrd/on-realized d
                                              #(is (not= % ::timed-out))
                                              #(is false (str "put! " %)))))]
          (let [d' (strm/try-take! chan<->server ::nada 200 ::response-timed-out)]
            (dfrd/on-realized d'
                              #(is (= % basic-check))
                              #(is false (str "take! " %))))))))

(deftest build-hello
  (testing "Can I build a Hello packet?"
    (let [client-agent (raw-client)
          client @client-agent
          updated (clnt/do-build-hello client)]
      (let [p-m (::shared/packet-management updated)
            nonce (::shared/packet-nonce p-m)]
        (is p-m)
        (is (and (integer? nonce)
                 (not= 0 nonce)))
        (let [buffer (::shared/packet p-m)]
          (is buffer)
          (let [v (subvec (vec buffer) 0 224)]
            (is (= (subvec v 0 (count shared/hello-header)) (vec shared/hello-header)))
            (is (= (subvec v 72 136) (take 64 (repeat 0))))))))))

(deftest start-stop
  (let [spawner (fn [owner-agent]
                  ;; Note that this is really
                  ;; the first time I've ever
                  ;; given any thought at all to
                  ;; what this side of things might
                  ;; look like.
                  ;; And there isn't much thought
                  ;; involved yet
                  (let [ch (strm/stream)
                        fut (strm/take! ch ::drained)
                        ;; Note that this is absolutely just a toy approach.
                        ;; The entire point is that we should be doing things
                        ;; and responding to input from the server.
                        ;; This is were the protocol starts to get really
                        ;; interesting and controversial.
                        owner-updater
                        (fn
                          [owner msg]
                          ;; My OOP background thinks we should just
                          ;; be notifying the owner agent that we have
                          ;; state updates it might want to consider
                          ;; forwarding along to the server
                          (println "This is definitely wrong:" msg)
                          owner)]
                    (dfrd/on-realized fut
                                      (fn [msg]
                                        (send owner-agent owner-updater msg))
                                      (fn [ex]
                                        (println "Either way, this is obviously broken")))
                    ch))
        client (raw-client spawner)
        chan<->server (-> client deref ::clnt/chan<->server)]
    (if chan<->server
      (try
        (let [client-thread (future (clnt/start! client))]
          (try
            (let [hello-future (strm/try-take! chan<->server ::drained 500 ::timeout)
                  hello (deref hello-future)]
              (if (not (or (= hello ::timeout)
                           (= hello ::drained)))
                (do
                  ;; Q: Can we do anything else meaningful here?
                  ;; I mean...I have access to the private server key.
                  ;; I could decrypt that packet to see what's in it.
                  ;; But that seems to belong in the actual interactive
                  ;; tests
                  (is (instance? io.netty.buffer.ByteBuf hello))
                  ;; Actually, this is an interesting point:
                  ;; hello should really be a ByteBuffer.
                  ;; Or a portion of a ByteArray that will be
                  ;; copied into a ByteBuffer.
                  (is (= shared/hello-packet-length (.readableBytes hello)))
                  (let [backing-array (.array hello)]
                    ;; Really don't want to mess with the backing array at all.
                    ;; Especially since, realistically, I should build everything
                    ;; except the crypto box in a Direct buffer, then copy that in
                    ;; and send it to the network.
                    (is (shared/bytes= (.getBytes shared/hello-header)
                                       (byte-array (subvec (vec backing-array) 0
                                                           (count shared/hello-header)))))))
                (throw (ex-info "Failed pulling hello packet"
                                {:client-errors (agent-error client)
                                 :client-thread client-thread}))))
            (finally
              (let [client-start-outcome (deref client-thread 500 ::awaiting-handshake-start)]
                (is (not= client-start-outcome ::awaiting-handshake-start))
                ;; That's actually a deferred chain
                (let [hand-shake-result (deref client-start-outcome 500 ::awaiting-handshake)]
                  ;; That timeout is almost definitely too low
                  ;; But it should short-circuit pretty quickly, once it fails.
                  ;; Q: Shouldn't it?
                  (is hand-shake-result))))))
        (finally
          (strm/close! chan<->server)
          ;; Give that a chance to percolate through...
          (Thread/sleep 0.2)
          (let [ex (agent-error client)]
            (if (instance? clojure.lang.ExceptionInfo ex)
              ;; So far, I haven't had a chance to come up with a better alternative to
              ;; "just set the agent state to an error when a channel closes"
              (is (= ::server-closed (-> ex .getData :problem))
                  "Not elegant, but really should be closed")
              (do
                ;; I'm winding up with an NPE here, which doesn't seem to make
                ;; any sense at all
                (.printStackTrace ex)
                (is (not ex)))))))
      (is chan<->server "No channel to pull data from server"))))

(comment
  (def junk (raw-client))
  (-> junk :extension vec)
  (-> junk :server-extension vec)o
  junk
  (-> junk keys)
  (alter-var-root #'junk #(.start %))
  (alter-var-root #'junk #(.stop %)))

(defn basic-test
  "This should probably go away"
  []
  (let [client-keys (shared/random-key-pair)
        ;; Q: Do I want to use this or TweetNaclFast/keyPair?
        server-keys (shared/random-key-pair)
        msg "Hold on, my child needs my attention"
        bs (.getBytes msg)
        nonce (byte-array [1 2 3 4 5 6 7 8 9 10
                           11 12 13 14 15 16 17
                           18 19 20 21 22 23 24])
        boxer (shared/crypto-box-prepare (.getPublicKey server-keys) (.getSecretKey client-keys))
        ;; This seems likely to get confused due to arity issues
        boxed (.box boxer bs nonce)
        unboxer (shared/crypto-box-prepare (.getPublicKey client-keys) (.getSecretKey server-keys))]
    (String. (.open unboxer boxed nonce))))
(comment (basic-test))
