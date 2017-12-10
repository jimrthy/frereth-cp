(ns frereth-cp.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth-cp.server :as server]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [manifold.stream :as strm])
  (:import io.netty.buffer.Unpooled))

(defn system-options
  []
  (let [server-name (shared/encode-server-name "test.frereth.com")]
    {:cp-server {::shared/extension (byte-array [0x01 0x02 0x03 0x04
                                                 0x05 0x06 0x07 0x08
                                                 0x09 0x0a 0x0b 0x0c
                                                 0x0d 0x0e 0x0f 0x10])
                 ::shared/my-keys #::shared{::K/server-name server-name
                                           :keydir "curve-test"}}}))

(defn build
  []
  {:cp-server (server/ctor (:cp-server (system-options)))
   :client-read-chan {:chan (strm/stream)}
   :client-write-chan {:chan (strm/stream)}})

(defn start
  [inited]
  (let [client-write-chan (:client-write-chan inited)
        client-read-chan (:client-read-chan inited)]
    {:cp-server (server/start! (assoc (:cp-server inited)
                                      ::state/client-read-chan client-read-chan
                                      ::state/client-write-chan client-write-chan))
     :client-read-chan client-read-chan
     :client-write-chan client-write-chan}))

(defn stop
  [started]
  (let [ch (get-in started [:client-read-chan :chan])]
    (strm/close! ch))
  (let [ch (get-in started [:client-write-chan :chan])]
    (strm/close! ch))
  {:cp-server (server/stop! (:cp-server started))
   :client-read-chan {:chan nil}
   :client-write-chan {:chan nil}})

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
            client (get-in started [:client-write-chan :chan])
            recvd (strm/try-take! client ::drained 500 ::timed-out)
            ;; Currently, this fails silently (from our perspective).
            ;; Which, really, is a fine thing.
            ;; Although the log message should be improved (since this could
            ;; very well indicate a hacking attempt).
            ;; Still, the current behavior is good enough for now.
            ;; I need to build packets to send to do the real work.
            ;; That will be easier/simpler to do in shared when I'm
            ;; interacting with a real client.
            ;; (The alternative is to either capture that exchange so
            ;; I can send it manually or reinvent the client's packet
            ;; buildig code)
            success (deref (strm/try-put! client msg 1000 ::timed-out))]
        (println "put! success:" success)
        ;; This is failing.
        ;; Probably because I'm not really creating a Client.
        ;; Q: Is that worth actually doing?
        (is (not= ::timed-out success))
        (is (= @recvd msg)))
      (finally
        (println "Triggering event loop exit")
        (stop started)))))

(deftest test-cookie-composition
  (let [client-extension (byte-array (take 16 (repeat 0)))
        server-extension (byte-array (take 16 (range)))
        working-nonce (byte-array (take 24 (drop 40 (range))))
        boxed (byte-array 200)
        dst (Unpooled/buffer 400)
        to-encode {::K/header K/cookie-header
                   ::K/client-extension client-extension
                   ::K/server-extension server-extension
                   ::K/client-nonce-suffix (Unpooled/wrappedBuffer working-nonce
                                                                   K/server-nonce-prefix-length
                                                                   K/server-nonce-suffix-length)
                   ;; This is also a great big FAIL:
                   ;; Have to drop the first 16 bytes
                   ;; Q: Have I fixed that yet?
                   ::K/cookie (Unpooled/wrappedBuffer boxed
                                                      K/box-zero-bytes
                                                      144)}]
    (try
      ;; FIXME: This fails because we can't cast a ByteBuf to a B]
      (let [composed (shared/compose K/cookie-frame to-encode dst)]
        (is composed))
      (catch clojure.lang.ExceptionInfo ex
        (is (not (.getData ex)))))))

(deftest vouch-extraction
  ;; TODO:
  ;; Use client/build-vouch to generate a vouch wrapper.
  ;; Then call server/decrypt-initiate-vouch to verify that
  ;; it extracted correctly.
  (throw (RuntimeException. "Not Implemented")))
