(ns frereth-cp.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.client :as client]
            [frereth-cp.client.state :as client-state]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.test-factory :as factory]
            [manifold.stream :as strm]))

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

(deftest shake-hands
  ;; Note that this is really trying to simulate the network layer between the two
  (let [init (factory/build-server)
        started (factory/start-server init)]
    (println "Server should be started now")
    ;; Which means it's time to start the client
    (try
      (let [client-host "cp-client.nowhere.org"
            ;; This is another example of java's unsigned integer stupidity.
            ;; This really should be a short.
            ;; Then again, the extra 2 bytes of memory involved here really don't
            ;; matter.
            client-port 48816
            client-logger (log/std-out-log-factory)
            srvr-pk-long (.getPublicKey (get-in started [::factory/cp-server ::shared/my-keys ::shared/long-pair]))
            client-agent (factory/raw-client "client-hand-shaker" client-logger srvr-pk-long)]
        (try
          (println "Sending HELLO")
          (let [client->server (::client-state/chan->server @client-agent)
                taken (strm/try-take! client->server ::drained 1000 ::timeout)
                hello @taken]
            (is (:host hello) "This layer doesn't know where to send anything")
            (if (not (or (= hello ::drained)
                         (= hello ::timeout)))
              (let [->srvr (get-in started [::state/client-read-chan ::state/chan])
                    msg {:host client-host
                         :port client-port
                         :message hello}
                    success (deref (strm/try-put! ->srvr msg 1000 ::timed-out))]
                (if (not= ::timed-out success)
                  (let [srvr-> (get-in started [::state/client-write-chan ::state/chan])
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
                        cookie-buffer (:message @(strm/try-take! srvr-> ::drained 1000 ::timeout))]
                    (println "FIXME: Make packet sends more consistent")
                    (if (and (not= ::drained cookie-buffer)
                             (not= ::timeout cookie-buffer))
                      (let [cookie (byte-array (.readableBytes cookie-buffer))]
                        (.readBytes cookie-buffer cookie)
                        (.release cookie-buffer)
                        (if-let [client<-server (::client-state/chan<-server @client-agent)]
                          (let [server-name "server"
                                server-port 65000
                                ;; This is throwing a NPE.
                                ;; Almost definitely because I'm not setting up chan<-server
                                put @(strm/try-put! client<-server
                                                    {:host server-name
                                                     :message cookie
                                                     :port server-port}
                                                    1000
                                                    ::timeout)]
                            (if (not= ::timeout put)
                              (let [initiate @(strm/try-take! client->server ::drained 1000 ::timeout)]
                                (if-not (or (= initiate ::drained)
                                            (= initiate ::timeout))
                                  (throw (RuntimeException. "Don't stop here"))
                                  (throw (ex-info "Failed to take Initiate/Vouch from Client"
                                                  {::problem initiate}))))
                              (throw (RuntimeException. "Timed out putting Cookie to Client"))))
                          (throw (ex-info "I know I have a mechanism for writing from server to client among"
                                          {::keys (keys @client-agent)
                                           ::grand-scheme @client-agent}))))
                      (throw (RuntimeException. (str cookie-buffer " reading Cookie from Server")))))
                  (throw (RuntimeException. "Timed out putting Hello to Server"))))
              (throw (RuntimeException. (str hello " taking Hello from Client")))))
          (finally
            (println "Stopping client")
            (client/stop! client-agent))))
      (finally
        (println "Triggering server event loop exit")
        (factory/stop-server started)))))
