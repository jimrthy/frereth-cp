(ns frereth-cp.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.server :as server]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [manifold.stream :as strm]))

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
      (let [msg "Howdy!"
            client (get-in started [::state/client-write-chan ::state/chan])
            recvd (strm/try-take! client ::drained 500 ::timed-out)
            success (deref (strm/try-put! client msg 1000 ::timed-out))]
        (println "put! success:" success)
        (is (not= ::timed-out success))
        (is (= @recvd msg)))
      (finally
        (println "Triggering event loop exit")
        (stop started)))))
