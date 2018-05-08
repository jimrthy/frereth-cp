(ns frereth-cp.server-test
  (:require [clojure.java.io :as jio]
            [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.client :as client]
            [frereth-cp.client.state :as client-state]
            [frereth-cp.message :as msg]
            [frereth-cp.server :as server]
            [frereth-cp.server.state :as srvr-state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.test-factory :as factory]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import io.netty.buffer.ByteBuf))

(defn build-hello
  [srvr-xtn
   {:keys [::specs/public-short]
    :as my-short-keys}]
  (throw (RuntimeException. "This is obsolete"))
  ;; frereth-cp.client.hello is really my model for setting
  ;; this up.
  ;; I'm not overly fond of the current implementation.
  ;; Still, it's silly not to use whatever the client does.
  ;; TODO: Make what the client does less objectionable
  ;; Although, realistically, this is the wrong place for
  ;; tackling that.
  (let [empty-crypto-box "Q: What is this?"  ; A: a B] of (- K/hello-crypto-box-length K/box-zero-bytes) zeros
        crypto-box "FIXME: How do I encrypt this?"
        hello-dscr {::K/hello-prefix K/hello-header
                    ::K/srvr-xtn srvr-xtn
                    ::K/clnt-xtn (byte-array (take K/extension-length (drop 256 (range))))
                    ::K/clnt-short-pk public-short
                    ::K/zeros (K/zero-bytes K/zero-box-length)
                    ::K/client-nonce-suffix (byte-array [0 0 0 0 0 0 0 1])
                    ::K/crypto-box crypto-box}]
    (serial/compose K/hello-packet-dscr hello-dscr)))

(defn handshake->client-child
  "Client-child callback for bytes arriving on the message stream"
  [ch
   ks-or-bs]
  (println "client-child Incoming:" ks-or-bs)
  ;; FIXME: This has to cope with buffering.
  ;; I really should use something like gloss again.
  (if (bytes? ks-or-bs)
    (strm/put! ch ks-or-bs)
    (strm/close! ch)))

(defn handshake-client-cb
  [io-handle ^bytes bs]
  ;; It's tempting to write another interaction test, like
  ;; the one in message.handshake-test.
  ;; That would be a waste of time/energy.
  ;; This really is a straight request/response test.
  ;; As soon as the server sends back a message packet
  ;; response, the client quits caring.
  ;; Except that I also need to test the transition from
  ;; Initiate-sending mode to full-size Message packets.
  ;; So there has to be more than this.
  (throw (RuntimeException. "Need to send at least 1 more request"))
  (msg/child-close! io-handle))

(defn handshake-client-child-spawner!
  "Spawn the client-child for the handshake test and initiate the fun"
  [ch
   {log-state-atom ::log/state-atom
    logger ::log/logger
    :as io-handle}]
  {:pre [io-handle]}
  (when-not log-state-atom
    (throw (ex-info "Missing log-state-atom"
                    {::keys (keys io-handle)
                     ::io-handle io-handle})))
  (swap! log-state-atom #(log/debug %
                                    ::handshake-client-child-spawner!
                                    "Forking child process"
                                    {::now (System/currentTimeMillis)}))
  (swap! log-state-atom #(log/flush-logs! logger %))

  ;; Doing a req/rep sort of thing from server is honestly
  ;; pretty boring. But it's easy to test.
  ;; Assume the client reacts to server messages.
  ;; Pull them off the network, shove them into this
  ;; stream, and than have the handshake-client-cb
  ;; cope with them.
  (try
    (strm/consume (partial handshake-client-cb
                           (assoc io-handle
                                  ::log/state
                                  @log-state-atom))
                  ch)
    ;; Q: Worth converting this to something like an HTTP request
    ;; that's too big to fit in a single packet?
    ;; A: Well, I've really already done that in
    ;; message-test/bigger-outbound
    ;; All this *should* test would be whichever means I
    ;; use on the server side to reassemble the bytes that
    ;; were streamed in packets.
    ;; Which is interesting from the standpoint of example
    ;; usage, but not so much from this angle.

    (let [helo (-> ::helo
                   pr-str
                   .getBytes)]
      (msg/child->! io-handle helo))
    (swap! log-state-atom
           #(log/flush-logs! logger (log/debug %
                                               ::handshake-client-child-spawner!
                                               "Child HELO sent")))
    (catch Exception ex
      (swap! log-state-atom
             #(log/flush-logs! logger
                               (log/exception %
                                              ex
                                              ::handshake-client-child-spawner!
                                              "Forking child failed"))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(deftest start-stop
  (testing "That we can start and stop successfully"
    (let [logger (log/std-out-log-factory)
          log-state (log/init ::verify-start-stop)
          inited (factory/build-server logger log-state)
          started (factory/start-server inited)]
      (is started)
      (is (factory/stop-server started)))))
(comment
  (def test-sys (factory/build-server))
  (alter-var-root #'test-sys factory/start-server)
  (-> test-sys :client-chan keys)
  (alter-var-root #'test-sys cpt/stop-server)
  )

(deftest verify-ctor-spec
  (testing "Does the spec really work as intended?"
    (let [base-options {::log/logger (log/std-out-log-factory)
                        ::log/state (log/init ::verify-ctor-spec)
                        ::shared/extension factory/server-extension
                        ::srvr-state/child-spawner! (fn []
                                                      {::srvr-state/child-id 8
                                                       ::srvr-state/read<-child (strm/stream)
                                                       ::srvr-state/write->child (strm/stream)})
                        ::srvr-state/client-read-chan {::srvr-state/chan (strm/stream)}
                        ::srvr-state/client-write-chan {::srvr-state/chan (strm/stream)}}]
      ;; Honestly, this is just testing the clause that chooses between these two possibilities.
      ;; FIXME: Since that really should be an xor, add another test that verifies that you
      ;; can't legally have both.
      ;; That very much flies in the face of the way specs were intended to work,
      ;; but this is an extremely special case.
      (is (not (s/explain-data ::server/pre-state-options (assoc base-options
                                                                 ::shared/keydir "somewhere"))))
      (let [pre-state-options (assoc base-options
                                     ;; The fact that keydir is stored here is worse than annoying.
                                     ;; It's wasteful and pointless.
                                     ;; Actually, both of these really point out the basic fact that
                                     ;; I should be smarter about this translation.
                                     ;; Pass these parameters into a function, get back the associated
                                     ;; long/short key-pair.
                                     ;; The shared ns has more comments about the problems involved
                                     ;; here.
                                     ;; One of the true ironies is that, if I'm using this approach,
                                     ;; the long/short key pairs are really what I want/need here.
                                     ;; And I don't needs the parts I've required.
                                     ;; FIXME: Switch to a smarter implementation.
                                     ::shared/my-keys {::shared/keydir "curve-test"
                                                       ::K/srvr-name factory/server-name})]
        (println "Checking pre-state spec")
        (is (not (s/explain-data ::server/pre-state-options pre-state-options)))
        (println "pre-state spec passed")
        (testing
            "Start/Stop"
            (let [pre-state (server/ctor pre-state-options)
                  state (server/start! pre-state)]
              (try
                (println "Server started. Looks like:  <------------")
                ;; Q: Do I want to do this dissoc?
                (pprint (dissoc state ::log/state))
                (is (not (s/explain-data ::srvr-state/checkable-state (dissoc state
                                                                              ::srvr-state/child-spawner
                                                                              ::srvr-state/event-loop-stopper!))))
                ;; Sending a SIGINT kills a thread that's blocking execution and
                ;; allows this line to print.
                (println "Spec checked")
                (finally (let [stopped (server/stop! state)]
                           ;; Not getting here, though
                           (println "Server stopped")
                           (is (not (s/explain-data ::server/post-state-options stopped)))
                           (println "pre-state checked"))))))))))

(deftest shake-hands
  ;; Note that this is really trying to simulate the network layer between the two
  (println "Top of shake-hands")
  (jio/delete-file "/tmp/shake-hands.server.log.edn" ::ignore-errors)
  (jio/delete-file "/tmp/shake-hands.client.log.edn" ::ignore-errors)
  ;; FIXME: Ditch the client agent.
  ;; Rewrite this entire thing as a pair of dfrd/chains.
  (let [srvr-logger (log/file-writer-factory "/tmp/shake-hands.server.log.edn")
        srvr-log-state (log/init ::shake-hands.server)
        initial-server (factory/build-server srvr-logger srvr-log-state)
        started (factory/start-server initial-server)
        srvr-log-state (log/flush-logs! srvr-logger (log/info srvr-log-state
                                                             ::shake-hands
                                                             "Server should be started now"))]
    ;; Time to start the client
    (try
      (let [client-host "cp-client.nowhere.org"
            ;; This is another example of java's unsigned integer stupidity.
            ;; This really should be a short, but can't without handling my own
            ;; 2s-complement bit twiddling.
            ;; Then again, the extra 2 bytes of memory involved here really
            ;; shouldn't matter.
            client-port 48816
            srvr-pk-long (.getPublicKey (get-in started [::factory/cp-server ::shared/my-keys ::shared/long-pair]))
            server-ip [127 0 0 1]
            server-port 65000
            clnt-log-state (log/init ::shake-hands.client)
            clnt-logger (log/file-writer-factory "/tmp/shake-hands.client.log.edn")
            internal-client-chan (strm/stream)
            client-agent (factory/raw-client "client-hand-shaker"
                                             (constantly clnt-logger)
                                             clnt-log-state
                                             server-ip
                                             server-port
                                             srvr-pk-long
                                             (partial handshake->client-child internal-client-chan)
                                             (partial handshake-client-child-spawner! internal-client-chan))]
        (println (str "shake-hands: Agent start triggered. Pulling HELLO from "
                      client-agent
                      ", a "
                      (class client-agent)))
        (try
          (let [client->server (::client-state/chan->server @client-agent)]
            (is client->server)
            (let [taken (strm/try-take! client->server ::drained 1000 ::timeout)
                  hello @taken]
              (println "server-test/handshake Hello from client:" hello)
              (when (or (= hello ::drained)
                        (= hello ::timeout))
                (throw (ex-info "Client took too long"
                                {::client-state/state @client-agent
                                 ::problem (agent-error client-agent)})))
              (let [host (:host hello)]
                (when-not host
                  (println "shake-hands: Something went wrong with" @client-agent)
                  (throw (ex-info "This layer doesn't know where to send anything"
                                  {::problem hello}))))
              (if (not (or (= hello ::drained)
                           (= hello ::timeout)))
                (let [->srvr (get-in started [::srvr-state/client-read-chan ::srvr-state/chan])
                      ;; Currently, this arrives as a ByteBuf.
                      ;; Anything that can be converted to a direct ByteBuf is legal.
                      ;; So this part is painfully implementation-dependent.
                      ;; Q: Is it worth generalizing?
                      ^ByteBuf hello-buffer (:message hello)
                      hello-length (.readableBytes hello-buffer)
                      hello-packet (byte-array hello-length)]
                  (.readBytes hello-buffer hello-packet)
                  (println (str "shake-hands: Trying to put hello packet\n"
                                (b-t/->string hello-packet)
                                "\nonto server channel "
                                ->srvr
                                " a "
                                (class ->srvr)))
                  (let [put-success (strm/try-put! ->srvr
                                                   (assoc hello
                                                          :message hello-packet)
                                                   1000
                                                   ::timed-out)
                        success (deref put-success
                                       1000
                                       ::deref-try-put!-timed-out)]
                    (println "shake-hands: Result of putting hello onto server channel:" success)
                    (if (and (not= ::timed-out success)
                             (not= ::deref-try-put!-timed-out success))
                      (let [srvr-> (get-in started [::srvr-state/client-write-chan ::srvr-state/chan])
                            ;; From the aleph docs:
                            ;; "The stream will accept any messages which can be coerced into
                            ;; a binary representation."
                            ;; It's perfectly legit for the Server to send either B] or
                            ;; ByteBuf instances here.
                            ;; (Whether socket instances emit ByteBuf or B] depends on a
                            ;; parameter to their ctor. The B] approach is slower due to
                            ;; copying, but recommended for any but advanced users,
                            ;; to avoid needing to cope with reference counts).
                            ;; TODO: See which format aleph works with natively to
                            ;; minimize copying for writes (this may or may not mean
                            ;; rewriting compose to return B] instead)
                            ;; Note that I didn't need to do this for the Hello packet.
                            packet-take (strm/try-take! srvr-> ::drained 1000 ::timeout)
                            packet (deref packet-take 1000 ::take-timeout)]
                        (println "server-test/shake-hands: Server response to hello:"
                                 packet)
                        (if (and (not= ::drained packet)
                                 (not= ::timeout packet)
                                 (not= ::take-timeout packet))
                          (if-let [client<-server (::client-state/chan<-server @client-agent)]
                            (let [cookie-buffer (:message packet)
                                  cookie (byte-array (.readableBytes cookie-buffer))]
                              (.readBytes cookie-buffer cookie)
                              (is (= server-ip (-> packet
                                                   :host
                                                   .getAddress
                                                   vec)))
                              (is (= server-port (:port packet))
                                  (str "Mismatched port in"
                                       packet
                                       "based on\n"
                                       (-> client-agent
                                           deref
                                           ::client-state/server-security)))
                              ;; Send the Cookie to the client
                              (println "server-test/handshake-test: Sending Cookie to"
                                       client<-server)
                              (let [put @(strm/try-put! client<-server
                                                        (assoc packet
                                                               :message cookie)
                                                        1000
                                                        ::timeout)]
                                (println "server-test/handshake-test: cookie->client result:" put)
                                (if (not= ::timeout put)
                                  ;; Get the Initiate from the client
                                  (let [possible-initiate (strm/try-take! client->server ::drained 1000 ::timeout)
                                        initiate-outcome (dfrd/deferred)]
                                    (dfrd/on-realized possible-initiate
                                                      (fn [initiate]
                                                        (println "server-test/handshake Initiate retrieved from client:"
                                                                 initiate
                                                                 "\nclient->server:"
                                                                 client->server)
                                                        ;; FIXME: Verify that this is a valid Initiate packet
                                                        (if-not (or (= initiate ::drained)
                                                                    (= initiate ::timeout))
                                                          (do
                                                            (is (= server-ip (-> initiate
                                                                                 :host
                                                                                 .getAddress
                                                                                 vec)))
                                                            (is (bytes? (:message initiate))
                                                                (str "Invalid byte in :message inside Initiate packet: " initiate))
                                                            (if-let [port (:port initiate)]
                                                              (is (= server-port port))
                                                              (is false (str "UDP packet missing port in " initiate)))
                                                            (let [put (strm/try-put! ->srvr initiate 1000 ::timeout)]
                                                              (if (not= ::timeout put)
                                                                (let [first-srvr-message @(strm/try-take! srvr-> ::drained 1000 ::timeout)]
                                                                  (if-not (or (= first-srvr-message ::drained)
                                                                              (= first-srvr-message ::timeout))
                                                                    (let [put @(strm/try-put! client<-server
                                                                                              first-srvr-message
                                                                                              1000
                                                                                              ::timeout)]
                                                                      (if (not= ::timeout put)
                                                                        (let [first-full-clnt-message @(strm/try-take! client->server ::drained 1000 ::timeout)]
                                                                          ;; As long as we got a message back, we should be able to call
                                                                          ;; this test done.
                                                                          (if (= ::timeout first-full-clnt-message)
                                                                            (do
                                                                              (dfrd/error! initiate-outcome
                                                                                           (ex-info "Timed out waiting for client response")))
                                                                            (dfrd/success! initiate-outcome first-full-clnt-message)))
                                                                        (do
                                                                          (dfrd/error! initiate-outcome
                                                                                       (ex-info "Timed out writing first server Message packet to client")))))
                                                                    (do
                                                                      (dfrd/error! initiate-outcome
                                                                                   (ex-info "Failed pulling first real Message packet from Server"
                                                                                            {::problem first-srvr-message})))))
                                                                (do
                                                                  (dfrd/error! initiate-outcome
                                                                               (ex-info "Timed out writing Initiate to Server"))))))
                                                          (do
                                                            (dfrd/error! initiate-outcome (ex-info "Failed to take Initiate/Vouch from Client"
                                                                                                   {::problem initiate})))))
                                                      identity)
                                    (let [initiate-outcome (deref initiate-outcome 2000 ::initiate-timeout)]
                                      (is (not= ::initiate-timeout initiate-outcome))
                                      (is (not (instance? Throwable initiate-outcome)))
                                      ;; Q: What are we dealing with here?
                                      (is (not initiate-outcome))))
                                  (throw (RuntimeException. "Timed out putting Cookie to Client")))))
                            (throw (ex-info "I know I have a mechanism for writing from server to client among"
                                            {::keys (keys @client-agent)
                                             ::grand-scheme @client-agent})))
                          (throw (RuntimeException. (str packet " reading Cookie from Server")))))
                      (throw (RuntimeException. "Timed out putting Hello to Server")))))
                (throw (RuntimeException. (str hello " taking Hello from Client"))))))
          (finally
            (let [client-state @client-agent
                  cleaned (if (map? client-state)
                            (dissoc client-state ::log/state)
                            {::agent-state client-state})]
              (println "Stopping client agent" cleaned))
            (try
              (client/stop! client-agent)
              (try
                (if-let [problem (agent-error client-agent)]
                  (println "Uh-oh. client-agent is in a failed state:\n"
                           problem)
                  (await client-agent))
                (catch Exception ex
                  ;; This should never happen.
                  ;; But I want to be certain that it doesn't escape to the
                  ;; outer try/catch
                  (println "Problem waiting for client-agent to finish\n"
                           (log/exception-details ex))))
              (catch Exception ex
                (println "stop! failed:\n" (log/exception-details ex))))
            (println "client-agent stopped")
            (if-let [problem (agent-error client-agent)]
              (println problem)
              (pprint (dissoc @client-agent
                              ::log/state))))))
      (finally
        (println "Triggering server event loop exit")
        (factory/stop-server started)))))
