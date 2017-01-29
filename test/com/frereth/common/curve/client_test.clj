(ns com.frereth.common.curve.client-test
  (:require [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is testing)]
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
    (clnt/ctor {;; Aleph supplies a single bi-directional channel.
                ;; My tests break trying to use that here.
                ;; For now, take a step back and get them working
                ::clnt/chan<-server (strm/stream)
                ::clnt/chan->server (strm/stream)
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
    (let [client-agent (raw-client nil)
          client @client-agent
          {:keys [::clnt/chan<-server ::clnt/chan->server]} client]
        (strm/on-drained chan<-server
                         #(send client-agent clnt/server-closed!))
        ;; Q: Doesn't this also need to send the packet?
        ;; A: Probably.
        ;; Trying to send a bogus response fails below.
        (send client-agent clnt/do-build-hello)
        (if (await-for 150 client-agent)
          (do
            (is (not (agent-error client-agent)))
            (let [cookie-waiter (dfrd/future (clnt/wait-for-cookie))
                  ;; Q: Worth building a real Cookie response packet instead?
                  basic-check "Did this work?"
                  fut (dfrd/future (let [d (strm/try-put! chan<-server basic-check 150 ::timed-out)]
                                     ;; Important detail:
                                     ;; This test fails, if you look at the actual output in the
                                     ;; REPL.
                                     ;; But it looks like it's succeeding in CIDER.
                                     (dfrd/on-realized d
                                                       #(is (not= % ::timed-out))
                                                       #(is false (str "put! " %)))))]
              ;; TODO: Need to make sure both cookie-waiter and fut resolve
              ;; Q: Should they be promises?
              (is false "Get this working, for real")
              (let [d' (strm/try-take! chan->server ::nada 200 ::response-timed-out)]
                (dfrd/on-realized d'
                                  #(is (= % basic-check))
                                  #(is false (str "take! " %))))))
          (is false "Timed out waiting for client agent to build HELLO packet")))))

(deftest build-hello
  (testing "Can I build a Hello packet?"
    (let [client-agent (raw-client nil)
          client @client-agent
          updated (clnt/do-build-hello client)]
      (let [p-m (::shared/packet-management updated)
            nonce (::shared/packet-nonce p-m)]
        (is p-m)
        (is (and (integer? nonce)
                 (not= 0 nonce)))
        (let [buffer (::shared/packet p-m)]
          (is buffer)
          (is (= shared/hello-packet-length (.readableBytes buffer)))
          (let [dst (byte-array shared/hello-packet-length)]
            (.readBytes buffer dst)
            (let [v (vec dst)]
              (is (= (subvec v 0 (count shared/hello-header)) (vec shared/hello-header)))
              (is (= (subvec v 72 136) (take 64 (repeat 0)))))))))))

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
        client-agent (raw-client spawner)
        ;; One major advantage of using agents over async-loops:
        ;; Have state instantly available for the asking
        client @client-agent
        {:keys [::clnt/chan->server ::clnt/chan<-server]
         :as client} client]
    (if (and chan<-server chan->server)
      (try
        (let [client-thread (future (clnt/start! client-agent))]
          (try
            (let [hello-future (strm/try-take! chan->server ::drained 500 ::timeout)
                  hello (deref hello-future)]
              (if (not (or (= hello ::timeout)
                           (= hello ::drained)))
                (do
                  ;; Pretty sure I'm running into a race condition over this shared
                  ;; resource.
                  ;; i.e. sender is clearing the packet as soon as I receive it,
                  ;; before I could have possibly forwarded it along to the server.
                  ;; Q: Do I have any good alternatives that don't involve creating
                  ;; copies?
                  (println "Hello message ready to send to server. Validating it:")
                  ;; Q: Can we do anything else meaningful here?
                  ;; I mean...I have access to the private server key.
                  ;; I could decrypt that packet to see what's in it.
                  ;; But that seems to belong in the actual interactive
                  ;; tests.
                  ;; This should probably grow into that, but changes
                  ;; in behavior here should portend test failures there.
                  ;; This approach is more tightly couple with the actual
                  ;; implementation, but that also means it's more likely
                  ;; to catch problems when that implementation changes.
                  (is (instance? io.netty.buffer.ByteBuf hello))
                  ;; Actually, this is an interesting point:
                  ;; hello should really be a ByteBuffer.
                  ;; Or a portion of a ByteArray that will be
                  ;; copied into a ByteBuffer.
                  (is (= shared/hello-packet-length (.readableBytes hello)))
                  (if (.hasArray hello)
                    (let [backing-array (.array hello)]
                      ;; Really don't want to mess with the backing array at all.
                      ;; Especially since, realistically, I should build everything
                      ;; except the crypto box in a Direct buffer, then copy that in
                      ;; and send it to the network.
                      (is (shared/bytes= (.getBytes shared/hello-header)
                                         (byte-array (subvec (vec backing-array) 0
                                                             (count shared/hello-header))))))
                    (do
                      (if (.isDirect hello)
                        (let [array (byte-array shared/hello-packet-length)]
                          (.getBytes hello 0 array)
                          ;; Q: Anything else useful I can check here?
                          (is (shared/bytes= shared/hello-header
                                             (byte-array (subvec (vec array) 0
                                                                 (count shared/hello-header))))))
                        ;; Q: What's going on here?
                        (println "Got an nio Buffer from a ByteBuf that isn't an Array, but it isn't direct."))))
                  (println "Hello packet verified. Now I'd send it to the server"))
                (throw (ex-info "Failed pulling hello packet"
                                {:client-errors (agent-error client)
                                 :client-thread client-thread}))))
            (finally
              (let [client-start-outcome (deref client-thread 500 ::awaiting-handshake-start)]
                (is (not= client-start-outcome ::awaiting-handshake-start))
                (when-not (= client-start-outcome ::awaiting-handshake-start)
                  ;; That's actually a deferred chain
                  (let [hand-shake-result (deref client-start-outcome 500 ::awaiting-handshake)]
                    ;; That timeout is almost definitely too low
                    ;; But it should short-circuit pretty quickly, once it fails.
                    ;; Q: Shouldn't it?
                    (is hand-shake-result))))
                )))
        (finally
          (strm/close! chan<-server)
          ;; Give that a chance to percolate through...
          (Thread/sleep 200)
          (if-let [ex (agent-error client-agent)]
            (if (instance? clojure.lang.ExceptionInfo ex)
              ;; So far, I haven't had a chance to come up with a better alternative to
              ;; "just set the agent state to an error when a channel closes"
              (let [details (.getData ex)]
                (if (= ::server-closed (:problem details))
                  (is true "Not elegant, but this *is* expected")
                  ;; Unexpected failures are worrisome.
                  ;; And some things are failing almost silently
                  (do
                    (is false (with-out-str (pprint details)))
                    ;; So we can get a stack trace
                    (deref client-agent))))
              (do
                ;; I'm winding up with an NPE here, which doesn't seem to make
                ;; any sense at all
                (.printStackTrace ex)
                (is (not ex))))
            (let [unexpected-success @client-agent]
              (is (not unexpected-success) "Did I just not wait long enough?")))))
      (is chan<-server "No channel to pull data from server"))))

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
