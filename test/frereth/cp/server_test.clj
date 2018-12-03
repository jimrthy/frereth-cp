(ns frereth.cp.server-test
  (:require [byte-streams :as b-s]
            [clojure.java.io :as jio]
            [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [frereth.cp
             [client :as client]
             [message :as msg]
             [server :as server]
             [shared :as shared]
             [test-factory :as factory]
             [util :as utils]]
            [frereth.cp.client.state :as client-state]
            [frereth.cp.message.specs :as msg-specs]
            [frereth.cp.server.state :as srvr-state]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [serialization :as serial]
             [specs :as specs]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import io.netty.buffer.ByteBuf))

(defn build-hello
  [srvr-xtn
   {:keys [::specs/public-short]
    :as my-short-keys}]
  (throw (RuntimeException. "This is obsolete"))
  ;; frereth.cp.client.hello is really my model for setting
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

(defn handshake->child
  "Client-child callback for bytes arriving on the message stream"
  [ch
   ks-or-bs]
  (println "Incoming toward client-child:" ks-or-bs)
  ;; FIXME: This has to cope with buffering.
  ;; I really should use something like gloss again.
  (if (bytes? ks-or-bs)
    (strm/put! ch ks-or-bs)
    (strm/close! ch)))

(defn handshake-client-cb
  [io-handle ^bytes bs]
  ;; Since this is being called back via strm/consume,
  ;; the exception that's about to happen probably gets swallowed.
  (println "server-test/handshake-client-cb: bytes arrived. Should fail.")
  ;; It's tempting to write another interaction test, like
  ;; the one in message.handshake-test.
  ;; That would be a waste of time/energy.
  ;; This really is a straight request/response test.
  ;; As soon as the server sends back a message packet
  ;; response, the client quits caring.
  ;; Except that I also need to test the transition from
  ;; Initiate-sending mode to full-size Message packets.
  ;; So there has to be more than this.
  (throw (RuntimeException. "Need to send at least 1 more 'request'"))
  (msg/child-close! io-handle))

(s/fdef handshake-client-child-spawner!
        :args (s/cat :chan strm/source?
                     :io-handle ::msg-specs/io-handle)
        :ret ::weald/state)
(defn handshake-client-child-spawner!
  "Spawn the client-child for the handshake test and initiate the fun"
  [ch
   {log-state-atom ::weald/state-atom
    logger ::weald/logger
    :as io-handle}]
  {:pre [io-handle]}
  (when-not log-state-atom
    (throw (ex-info "Missing log-state-atom"
                    {::keys (keys io-handle)
                     ::io-handle io-handle})))
  (swap! log-state-atom #(log/debug %
                                    ::handshake-client-child-spawner!
                                    "Forking child process"))
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
                                  ::weald/state
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
          ;; FIXME: This is broken now.
          inited (factory/build-server logger
                                       log-state
                                       (fn [bs]
                                         (println "Message from client to server child")
                                         (println (b-t/->string bs))))
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
  ;; FIXME: This is broken now
  (testing "Does the spec really work as intended?"
    (let [base-options {::weald/logger (log/std-out-log-factory)
                        ::weald/state (log/init ::verify-ctor-spec)
                        ::shared/extension factory/server-extension
                        ::msg-specs/child-spawner! (fn [io-handle]
                                                     (println "Server child-spawner! called for side-effects"))
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
                (pprint (dissoc state ::weald/state))
                (is (not (s/explain-data ::srvr-state/checkable-state (dissoc state
                                                                              ::msg-specs/child-spawner
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
  (try
    (println "Top of shake-hands")
    (let [uncaught-ex-handler (Thread/getDefaultUncaughtExceptionHandler)
          overridden-handler (reify Thread$UncaughtExceptionHandler
                               (uncaughtException [this thread ex]
                                 (binding [*out* *err*]
                                   (println "Uncaught Exception on" (.getName thread)
                                            "\n" (log/exception-details ex)))))]
      (Thread/setDefaultUncaughtExceptionHandler overridden-handler)
      (try
        (jio/delete-file "/tmp/shake-hands.server.log.edn" ::ignore-errors)
        (jio/delete-file "/tmp/shake-hands.client.log.edn" ::ignore-errors)
        ;; TODO: Rewrite this entire thing as a pair of dfrd/chains.
        (let [srvr-logger (log/file-writer-factory "/tmp/shake-hands.server.log.edn")
              srvr-log-state (log/init ::shake-hands.server)
              srvr->child (strm/stream)
              initial-server (factory/build-server srvr-logger
                                                   srvr-log-state
                                                   (partial handshake->child srvr->child))
              named-server (assoc-in initial-server
                                     [::factory/cp-server ::msg-specs/message-loop-name-base]
                                     "server-hand-shaker")
              started (factory/start-server named-server)
              srvr-log-state (log/flush-logs! srvr-logger (log/info srvr-log-state
                                                                    ::shake-hands
                                                                    "Server should be started now"))]
          (is started)
          (try
            ;; Time to start the client
            (let [client-host "cp-client.nowhere.org"
                  ;; This is another example of java's unsigned integer stupidity.
                  ;; This really should be a short, but can't without handling my own
                  ;; 2s-complement bit twiddling.
                  ;; Then again, the extra 2 bytes of memory involved here really
                  ;; shouldn't matter.
                  client-port 48816
                  long-server-pair (get-in started [::factory/cp-server ::shared/my-keys ::shared/long-pair])
                  srvr-pk-long (.getPublicKey long-server-pair)
                  server-ip [127 0 0 1]
                  server-port 65000
                  clnt-log-state (log/init ::shake-hands.client)
                  clnt-logger (log/file-writer-factory "/tmp/shake-hands.client.log.edn")
                  internal-client-chan (strm/stream)
                  client (factory/raw-client (gensym "client-hand-shaker-")
                                             (constantly clnt-logger)
                                             clnt-log-state
                                             server-ip
                                             server-port
                                             srvr-pk-long
                                             (partial handshake->child internal-client-chan)
                                             (partial handshake-client-child-spawner! internal-client-chan))]
              (println (str "shake-hands: Client State start triggered. Pulling HELLO from "
                            client
                            ", a "
                            (class client)))
              (try
                (let [client->server (::client-state/chan->server client)]
                  (is client->server)
                  (let [taken (strm/try-take! client->server ::drained 1000 ::timeout)
                        hello @taken]
                    (println "server-test/handshake Hello from client:" hello)
                    (when (or (= hello ::drained)
                              (= hello ::timeout))
                      (throw (ex-info "Client didn't send Hello"
                                      {::received hello
                                       ;; Note that this state is going to
                                       ;; drift further and further from reality, now
                                       ;; that I've ditched the agent.
                                       ;; Q: Isn't it?
                                       ::client-state/state client})))
                    (let [host (:host hello)]
                      (when-not host
                        (println "shake-hands: Something went wrong with" client)
                        (throw (ex-info "This layer doesn't know where to send anything"
                                        {::problem hello}))))
                    (let [->srvr (get-in started [::srvr-state/client-read-chan ::srvr-state/chan])
                          ;; Currently, this arrives as a byte-array
                          ;; Anything that can be converted to a direct ByteBuf is legal.
                          ;; So this part is painfully implementation-dependent.
                          ;; Q: Is it worth generalizing?
                          hello-packet (bytes (:message hello))]
                      (println (str "shake-hands: Trying to put hello packet\n"
                                    (b-t/->string hello-packet)
                                    "\nonto server channel "
                                    ->srvr
                                    " a "
                                    (class ->srvr)))
                      ;; The timing on this test is extremely susceptible to variations in
                      ;; system performance.
                      ;; I don't want to let it run forever, but it would be nice to be able
                      ;; to set up some sort of system load check to get ideas about how
                      ;; long we expect things to take for any given test run.
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
                          (let [srvr->client (get-in started [::srvr-state/client-write-chan ::srvr-state/chan])
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
                                packet-take (strm/try-take! srvr->client
                                                            ::drained
                                                            1000
                                                            ::timeout)
                                packet (deref packet-take
                                              1000
                                              ::take-timeout)]
                            (println "server-test/shake-hands: Server response to hello:"
                                     packet)
                            (if (and (not= ::drained packet)
                                     (not= ::timeout packet)
                                     (not= ::take-timeout packet))
                              (if-let [client<-server (::client-state/chan<-server client)]
                                (let [cookie (:message packet)
                                      client-ip (:host packet)]
                                  ;; This is a byte array now, instead
                                  ;; of a message packet.
                                  ;; That isn't right.
                                  (is client-ip (str "Missing :host in "
                                                     packet
                                                     "\namong\n"
                                                     (keys packet)))
                                  (is (= server-ip (-> client-ip
                                                       .getAddress
                                                       vec)))
                                  (is (= server-port (:port packet))
                                      (str "Mismatched port in"
                                           packet
                                           "based on\n"
                                           (::client-state/server-security client)))
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
                                                              ;; This next step should be pretty pointless.
                                                              (let [initiate (update initiate :message
                                                                                     (fn [bs]
                                                                                       (b-s/convert bs (Class/forName "[B"))))]
                                                                (is (= server-ip
                                                                       (-> initiate
                                                                           :host
                                                                           .getAddress
                                                                           vec)))
                                                                (is (bytes? (:message initiate))
                                                                    (str "Invalid binary in :message inside Initiate packet: " initiate))
                                                                (if-let [port (:port initiate)]
                                                                  (is (= server-port port))
                                                                  (is false (str "UDP packet missing port in initiate\n" initiate)))
                                                                (println "Trying to send that initiate (?) packet to the server")
                                                                ;; This seems to think it's successful.
                                                                ;; server's initiate handler *is* calling do-fork-child!
                                                                (let [put (strm/try-put! ->srvr
                                                                                         initiate
                                                                                         1000
                                                                                         ::timeout)]
                                                                  (println "Initiate packet sent to the server:" put)
                                                                  (if (not= ::timeout @put)
                                                                    (let [first-srvr-message @(strm/try-take! srvr->client ::drained 1000 ::timeout)]
                                                                      (println "First message pulled back from server:" first-srvr-message)
                                                                      (if-not (or (= first-srvr-message ::drained)
                                                                                  (= first-srvr-message ::timeout))
                                                                        (let [put @(strm/try-put! client<-server
                                                                                                  (update first-srvr-message
                                                                                                          :message
                                                                                                          #(b-s/convert % specs/byte-array-type))
                                                                                                  1000
                                                                                                  ::timeout)]
                                                                          (if (not= ::timeout put)
                                                                            (let [first-full-client-message @(strm/try-take! client->server
                                                                                                                             ::drained
                                                                                                                             1000
                                                                                                                             ::timeout)]
                                                                              ;; As long as we got a message back, we should be able to call
                                                                              ;; this test done.
                                                                              (if (= ::timeout first-full-client-message)
                                                                                (do
                                                                                  (dfrd/error! initiate-outcome
                                                                                               (RuntimeException. "Timed out waiting for initial client message")))
                                                                                (dfrd/success! initiate-outcome first-full-client-message)))
                                                                            (do
                                                                              (dfrd/error! initiate-outcome
                                                                                           (RuntimeException. "Timed out writing first server Message packet to client")))))
                                                                        (do
                                                                          (dfrd/error! initiate-outcome
                                                                                       (ex-info "Failed pulling first real Message packet from Server"
                                                                                                {::problem first-srvr-message})))))
                                                                    (do
                                                                      (dfrd/error! initiate-outcome
                                                                                   (RuntimeException. "Timed out writing Initiate to Server"))))))
                                                              (do
                                                                (dfrd/error! initiate-outcome (ex-info "Failed to take Initiate/Vouch from Client"
                                                                                                       {::problem initiate})))))
                                                          identity)
                                        (try
                                          (let [actual-initiate-outcome (deref initiate-outcome 2000 ::initiate-timeout)]
                                            (is (not= ::initiate-timeout actual-initiate-outcome))
                                            ;; Q: What are we dealing with here?
                                            ;; It's a network packet.
                                            ;; So :host, :port, and a byte array in :message
                                            (is (not actual-initiate-outcome) (str "Message is a " (-> actual-initiate-outcome :message class))))
                                          (catch Exception ex
                                            ;; We get here on any of those dfrd/error! triggers above
                                            (is (not ex)))))
                                      (throw (RuntimeException. "Timed out putting Cookie to Client")))))
                                (throw (ex-info "I know I have a mechanism for writing from server to client among"
                                                {::keys (keys client)
                                                 ::grand-scheme client})))
                              (throw (RuntimeException. (str packet " reading Cookie from Server")))))
                          (throw (RuntimeException. "Timed out putting Hello to Server")))))))
                (finally
                  (let [cleaned (if (map? client)
                                  (dissoc client ::weald/state)
                                  {::client-state client})]
                    (try
                      (println "Stopping client agent" cleaned)
                      (catch StackOverflowError ex
                        (is (not ex))
                        (println "Failed to print the cleaned-up client agent state:"
                                 (log/exception-details ex))
                        (println "The unprintable state object that caused problems is a" (class client)))))
                  (try
                    (client/stop! client)
                    (catch Exception ex
                      (println "stop! failed:\n" (log/exception-details ex))))
                  (println "client stopped")
                  (try
                    (println "Trying to print out the client state")
                    (pprint (dissoc client
                                    ::weald/state))
                    (catch Exception ex
                      (is not ex)
                      (println "Something got terribly broken:"))))))
            (println "Made it to the bottom of the server handshake main try/catch")
            (catch Exception ex
              (is (not ex))
              (println "Unhandled exception in the main server handshake test try/catch")
              (println (log/exception-details ex)))
            (finally
              (println "Triggering server event loop exit")
              (factory/stop-server started)
              (println "Server stopped successfully"))))
        (finally
          (Thread/setDefaultUncaughtExceptionHandler uncaught-ex-handler))))
    (println "Got to the bottom of the server handshake test successfully")
    (catch Exception ex
      (is (not ex))
      (println "Unhandled exception at top-level of the server handshake test")
      (println ex)
      (println (log/exception-details ex)))))
