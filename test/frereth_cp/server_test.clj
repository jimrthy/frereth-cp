(ns frereth-cp.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.server :as server]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [manifold.stream :as strm]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helpers

(defn system-options
  []
  (let [server-name (shared/encode-server-name "test.frereth.com")]
    {::cp-server {::shared/extension (byte-array [0x01 0x02 0x03 0x04
                                                  0x05 0x06 0x07 0x08
                                                  0x09 0x0a 0x0b 0x0c
                                                  0x0d 0x0e 0x0f 0x10])
                  ::shared/my-keys #::shared{::K/server-name server-name
                                             :keydir "curve-test"}}}))

(defn build
  []
  {::cp-server (server/ctor (::cp-server (system-options)))
   ::state/client-read-chan {::state/chan (strm/stream)}
   ::state/client-write-chan {::state/chan (strm/stream)}})

(defn start
  [inited]
  (let [client-write-chan (::state/client-write-chan inited)
        client-read-chan (::state/client-read-chan inited)]
    {::cp-server (server/start! (assoc (::cp-server inited)
                                      ::state/client-read-chan client-read-chan
                                      ::state/client-write-chan client-write-chan))
     ::state/client-read-chan client-read-chan
     ::state/client-write-chan client-write-chan}))

(defn stop
  [started]
  (let [ch (get-in started [::state/client-read-chan ::state/chan])]
    (strm/close! ch))
  (let [ch (get-in started [::state/client-write-chan ::state/chan])]
    (strm/close! ch))
  {::cp-server (server/stop! (::cp-server started))
   ::state/client-read-chan {::state/chan nil}
   ::state/client-write-chan {::state/chan nil}})

(defn build-hello
  [srvr-xtn
   {:keys [::specs/public-short]
    :as my-short-keys}]
  ;; frereth-cp.client.hello is really my model for setting
  ;; this up.
  ;; I'm not overly fond of the current implementation.
  ;; Still, it's silly not to use whatever the client does.
  ;; TODO: Make what the client does less objectionable
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
    (let [inited (build)
          started (start inited)]
      (is started)
      (is (stop started)))))
(comment
  (def test-sys (build))
  (alter-var-root #'test-sys start)
  (-> test-sys :client-chan keys)
  (alter-var-root #'test-sys cpt/stop)
  )

(deftest shake-hands
  (let [init (build)
        started (start init)]
    (println "Server should be started now")
    (try
      (println "Sending bogus HELLO")
      (let [msg (build-hello)
            ->srvr (get-in started [::state/client-read-chan ::state/chan])
            success (deref (strm/try-put! ->srvr msg 1000 ::timed-out))]
        (println "put! success:" success)
        (is (not= ::timed-out success))
        (when (not= ::timed-out success)
          (let [srvr-> (get-in started [::state/client-write-chan ::state/chan])
                cookie @(strm/try-take! srvr-> ::drained 1000 ::timeout)]
            (is (not= ::drained cookie))
            (is (not= ::timeout cookie))
            (when (and (not= ::drained cookie)
                       (not= ::timeout cookie))
              ;; A: Decrypt the cookie and send an Initiate to get the server
              ;; to fork a child to handle messages with this client
              (throw (RuntimeException. "Q: What next?"))))))
      (finally
        (println "Triggering event loop exit")
        (stop started)))))
