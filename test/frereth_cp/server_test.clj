(ns frereth-cp.server-test
  (:require [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [frereth-cp.client :as client]
            [frereth-cp.client.state :as client-state]
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(deftest start-stop
  (testing "That we can start and stop successfully"
    (let [inited (factory/build-server)
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
(comment
  (s/form ::srvr-state/state)
  (s/form ::shared/packet-management)
  )

(deftest shake-hands
  ;; Note that this is really trying to simulate the network layer between the two
  (let [srvr-logger (log/file-writer-factory "/tmp/shake-hands.server.log")
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
            ;; Then again, the extra 2 bytes of memory involved here really don't
            ;; matter.
            client-port 48816
            srvr-pk-long (.getPublicKey (get-in started [::factory/cp-server ::shared/my-keys ::shared/long-pair]))
            server-ip [127 0 0 1]
            server-port 65000
            clnt-log-state (log/init ::shake-hands.client)
            clnt-logger (log/file-writer-factory "/tmp/shake-hands.client.log")
            client-agent (factory/raw-client "client-hand-shaker"
                                             (constantly clnt-logger)
                                             clnt-log-state
                                             server-ip
                                             server-port
                                             srvr-pk-long)]
        (println "Sending HELLO")
        (try
          (let [client->server (::client-state/chan->server @client-agent)
                taken (strm/try-take! client->server ::drained 1000 ::timeout)
                hello @taken]
            (is (:host hello) "This layer doesn't know where to send anything")
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
                (println (str "Trying to put hello packet "
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
                  (println "Result of putting hello onto server channel:" success)
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
                      (println "Server response to hello:" packet)
                      (if (and (not= ::drained packet)
                               (not= ::timeout packet)
                               (not= ::take-timeout packet))
                        (if-let [client<-server (::client-state/chan<-server @client-agent)]
                          (let [cookie-buffer (:message packet)
                                cookie (byte-array (.readableBytes cookie-buffer))]
                            (.readBytes cookie-buffer cookie)
                            (is (= server-ip (:host packet)))
                            (is (= server-port (:port packet)))
                            (let [put @(strm/try-put! client<-server
                                                      (assoc packet
                                                             :message cookie)
                                                      1000
                                                      ::timeout)]
                              (if (not= ::timeout put)
                                (let [initiate @(strm/try-take! client->server ::drained 1000 ::timeout)]
                                  (if-not (or (= initiate ::drained)
                                              (= initiate ::timeout))
                                    (throw (ex-info "Don't stop here" initiate))
                                    (throw (ex-info "Failed to take Initiate/Vouch from Client"
                                                    {::problem initiate}))))
                                (throw (RuntimeException. "Timed out putting Cookie to Client")))))
                          (throw (ex-info "I know I have a mechanism for writing from server to client among"
                                          {::keys (keys @client-agent)
                                           ::grand-scheme @client-agent})))
                        (throw (RuntimeException. (str packet " reading Cookie from Server")))))
                    (throw (RuntimeException. "Timed out putting Hello to Server")))))
              (throw (RuntimeException. (str hello " taking Hello from Client")))))
          (finally
            (println "Stopping client")
            (client/stop! client-agent))))
      (finally
        (println "Triggering server event loop exit")
        (factory/stop-server started)))))
