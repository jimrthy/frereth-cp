(ns frereth-cp.client-test
  (:require [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.client :as clnt]
            [frereth-cp.client
             [cookie :as cookie]
             [hello :as hello]
             [state :as state]]
            [frereth-cp.message :as message]
            [frereth-cp.message
             [registry :as registry]
             [specs :as msg-specs]]
            [frereth-cp.server.cookie :as srvr-cookie]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log]]
            [frereth-cp.test-factory :as factory]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helpers

(defn check-success
  [client where result]
  (or (and (not= result ::nada)
           (not= result ::timed-out)
           result)
      (throw (ex-info (str "Failed at '" where "'")
                      {::details client
                       ::result result}))))

(s/fdef step-1-fork!
        :args (s/cat :io-handle ::msg-specs/io-handle)
        :ret any?)
(defn step-1-fork!
  [io-handle]
  ;; Main point: try to send more bytes than will fit
  ;; into a single Initiate packet
  (message/child->! io-handle (byte-array (range 1024)))
  ;; Q: Do I want to mess with anything after this?
  (message/child-close! io-handle))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(deftest step-1
  ;; This test seems a little bit silly, as written.
  ;; It was meant to be a jumping-off point to demonstrate basically
  ;; what the client scaffolding needs to look like.
  ;; It really can't get very far, since the bogus server can't
  ;; send back a valid Cookie without getting as complicated as the
  ;; server-test/handshake.

  ;; However, there is value in an edge case that it revealed.
  (testing "The first basic thing that clnt/start does"
    ;; Q: Should I have run clnt/start! on this?
    ;; A: Yes. Absolutely.
    ;; Q: What does that actually do?
    ;; A: It starts by sending a HELO
    ;; packet, then setting the client up to wait for a
    ;; Cookie back from the server.
    (let [parent-cb (fn [client
                         chunk]
                      (println "parent-cb: getting ready to fail")
                      (throw (ex-info "Didn't really expect anything at parent callback"
                                      {::client-state client
                                       ::message chunk})))
          child-cb (fn [chunk]
                     (println "child-cb: getting ready to fail")
                     (throw (ex-info "Didn't really expect anything at child callback"
                                     {::message chunk})))
          keydir "curve-test"
          srvr-long-pair (crypto/do-load-keypair keydir)
          srvr-pk-long (.getPublicKey srvr-long-pair)
          log-state (log/init ::step-1)
          child-spawner step-1-fork!
          client (factory/raw-client "step-1"
                                     log/std-out-log-factory
                                     log-state
                                     [127 0 0 1]
                                     64921
                                     srvr-pk-long
                                     child-cb
                                     child-spawner)
          {:keys [::log/logger
                  ::state/chan<-server
                  ::state/chan->server]} client]
      (when-not chan<-server
        (throw (ex-info "Missing from-server channel"
                        client)))
      (strm/on-drained chan<-server
                       (fn []
                         (log/flush-logs! logger
                                          (log/warn (log/init ::drained)
                                                    ::chan<-server
                                                    "Channel from server drained"))))
      (let [cookie (byte-array 200)  ;  <---- Note that this is gibberish that should get discarded.
            ;; The edge case: I'm currently failing to decrypt that Cookie, but then proceeding
            ;; as though it succeeded. And then the Client fails to build the Initiate packet
            ;; because it doesn't have access to the short-term key that should have arrived with
            ;; the Cookie.
            cookie-wrapper {:host "10.0.0.12"
                            :port 48637
                            :message cookie}
            ;; The test-factory signals the raw-client to start, which starts by
            ;; building a Hello Packet and polling the available servers with it
            ;; until 1 responsd.
            success (dfrd/chain (strm/try-take! chan->server ::nada 200 ::timed-out)
                                (partial check-success client "Waiting for hello")
                                ;; Mimic the server sending back its Cookie, which
                                ;; we filled with garbage above.
                                (fn [hello]
                                  (let [hello
                                        (update hello :message
                                                (fn [current]
                                                  (if (bytes? current)
                                                    current
                                                    (let [^ByteBuf src current
                                                          n (.readableBytes src)
                                                          dst (byte-array n)]
                                                      (.readBytes src dst)
                                                      dst))))]
                                    (is (not (s/explain-data ::shared/network-packet hello))))
                                  (log/flush-logs! logger (log/info log-state
                                                                    "Sending garbage Cookie from mock-server to Client"
                                                                    ::step-1))
                                  (strm/try-put! chan<-server cookie-wrapper 150 ::timed-out))
                                (partial check-success client "Putting the cookie")
                                ;; Next step (which is all about pulling the Initiate packet) fails
                                ;; because we can't build it: the Client doesn't have the server's
                                ;; short-term key yet.
                                ;; Q: Is that because I just sent garbage in the Cookie?
                                ;; Or is there a bigger problem?
                                (fn [cookie]
                                  (println "Bogus cookie arrived from \"server.\" This would trigger the Initiate, if it weren't broken")
                                  (strm/try-take! chan->server ::nada 200 ::timed-out))
                                (partial check-success client "Taking the vouch")
                                (fn [{:keys [:host :message :port]
                                      :as network-packet}]
                                  ;; This is actually a PersistentArrayMap
                                  ;; Probably a ::shared/network-packet
                                  ;; TODO: Fix this next problem
                                  (is (instance? ByteBuf message)
                                      (str "Expected ByteBuf. Got " (class message)))
                                  ;; FIXME: Need to extract the cookie from the vouch that
                                  ;; we just received.
                                  (let [expected-n (count cookie)
                                        actual-n (.readableBytes message)]
                                    (is (= expected-n actual-n)))
                                  (let [response (byte-array (.readableBytes message))]
                                    (.getBytes message 0 response)
                                    (is (= (vec response) (vec cookie)))
                                    true)))]
        (is @success)))))
(comment
  ;; Maybe the problem isn't just CIDER. This also looks as
  ;; though it produces a false positive
  (step-1))

(deftest build-hello
  (testing "Can I build a Hello packet?"
    (let [{:keys [::client]} (factory/raw-client nil)
          updated (hello/do-build-packet client)]
      (let [p-m (::shared/packet-management updated)
            nonce (::shared/packet-nonce p-m)]
        (is p-m)
        (is (and (integer? nonce)
                 (not= 0 nonce)))
        (let [buffer (::shared/packet p-m)]
          (is buffer)
          (is (= K/hello-packet-length (.readableBytes buffer)))
          (let [dst (byte-array K/hello-packet-length)]
            (.readBytes buffer dst)
            (let [v (vec dst)]
              (is (= (subvec v 0 (count K/hello-header))
                     (vec K/hello-header)))
              (is (= (subvec v 72 136) (take 64 (repeat 0)))))))))))
(comment
  (vec shared/hello-header))

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
        client-agent (factory/raw-client spawner)
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
                  (is (or (instance? io.netty.buffer.ByteBuf hello)
                          ;; Q: What happens if I try to send a byte array
                          ;; directly?
                          ;; (it looks like this is probably what needs to
                          ;; get sent, but the actual answer isn't obvious)
                          (bytes? hello)))
                  ;; Actually, this is an interesting point:
                  ;; hello should really be a ByteBuffer.
                  ;; Or a portion of a ByteArray that will be
                  ;; copied into a ByteBuffer.
                  (is (= K/hello-packet-length
                         (if (bytes? hello)
                           (count hello)
                           (.readableBytes hello))))
                  (if-not (bytes? hello)
                    (if (.hasArray hello)
                      (let [backing-array (.array hello)]
                        ;; Really don't want to mess with the backing array at all.
                        ;; Especially since, realistically, I should build everything
                        ;; except the crypto box in a Direct buffer, then copy that in
                        ;; and send it to the network.
                        (is (b-t/bytes= (.getBytes K/hello-header)
                                           (byte-array (subvec (vec backing-array) 0
                                                               (count K/hello-header))))))
                      (do
                        (if (.isDirect hello)
                          (let [array (byte-array K/hello-packet-length)]
                            (.getBytes hello 0 array)
                            ;; Q: Anything else useful I can check here?
                            (is (b-t/bytes= K/hello-header
                                               (byte-array (subvec (vec array) 0
                                                                   (count K/hello-header))))))
                          ;; Q: What's going on here?
                          (println "Got an nio Buffer from a ByteBuf that isn't an Array, but it isn't direct."))))
                    (is (b-t/bytes= K/hello-header
                                       (byte-array (subvec (vec hello) 0
                                                           (count K/hello-header))))))
                  (println "Hello packet verified. Now I'd send it to the server"))
                (throw (ex-info "Failed pulling hello packet"
                                {:client-thread client-thread}))))
            (finally
              (let [client-start-outcome (deref client-thread 500 ::awaiting-handshake-start)]
                (is (not= client-start-outcome ::awaiting-handshake-start))
                (when-not (= client-start-outcome ::awaiting-handshake-start)
                  ;; That's actually a deferred chain
                  (let [hand-shake-result (deref client-start-outcome 500 ::awaiting-handshake)]
                    ;; That timeout is almost definitely too low
                    ;; But it should short-circuit pretty quickly, once it fails.
                    ;; Q: Shouldn't it?
                    (is hand-shake-result)))))))
        (finally
          (strm/close! chan<-server)
          ;; Give that a chance to percolate through...
          (Thread/sleep 500)
          (let [unexpected-success client]
            ;; Agent really should be in an exception state by now.
            (is (not unexpected-success) "Did I just not wait long enough?"))))
      (is chan<-server "No channel to pull data from server"))))

(comment
  (def junk (factory/raw-client nil))
  (-> junk :extension vec)
  (-> junk :server-extension vec)
  junk
  (-> junk keys)
  (alter-var-root #'junk #(.start %))
  (alter-var-root #'junk #(.stop %)))

(defn basic-test
  "This should probably go away"
  []
  (let [client-keys (crypto/random-key-pair)
        ;; Q: Do I want to use this or TweetNaclFast/keyPair?
        server-keys (crypto/random-key-pair)
        msg "Hold on, my child needs my attention"
        bs (.getBytes msg)
        nonce (byte-array [1 2 3 4 5 6 7 8 9 10
                           11 12 13 14 15 16 17
                           18 19 20 21 22 23 24])
        boxer (crypto/box-prepare (.getPublicKey server-keys) (.getSecretKey client-keys))
        ;; This seems likely to get confused due to arity issues
        boxed (.box boxer bs nonce)
        unboxer (crypto/box-prepare (.getPublicKey client-keys) (.getSecretKey server-keys))]
    (String. (.open unboxer boxed nonce))))
(comment (basic-test))
