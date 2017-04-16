(ns com.frereth.common.curve.server-test
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.curve.server :as server]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.constants :as K]
            ;; TODO: This also needs to go away
            [com.stuartsierra.component :as cpt]
            [component-dsl.system :as cpt-dsl]
            [manifold.stream :as strm])
  (:import io.netty.buffer.Unpooled))

(defrecord StreamOwner [chan]
  ;; TODO: Make this just totally go away
  cpt/Lifecycle
  (start
    [this]
    (assoc this :chan (or chan (strm/stream))))
  (stop
    [this]
    (println "Stopping StreamOwner")
    (when chan
      (strm/close! chan))
    (assoc this :chan nil)))
(defn chan-ctor
  [_]
  (->StreamOwner (strm/stream)))

(def options {:cp-server {:security {:keydir "curve-test"
                                     ;; Note that name really isn't legal.
                                     ;; It needs to be something we can pass
                                     ;; along to DNS, padded to 255 bytes.
                                     ;; This bug really should show up in
                                     ;; a test.
                                     :name "local.test"}
                          :extension (byte-array [0x01 0x02 0x03 0x04
                                                  0x05 0x06 0x07 0x08
                                                  0x09 0x0a 0x0b 0x0c
                                                  0x0d 0x0e 0x0f 0x10])}})
(def sys-struct {:cp-server 'com.frereth.common.curve.server/ctor
                 :client-chan 'com.frereth.common.curve.server-test/chan-ctor})

(defn build
  []
  (cpt-dsl/build #:component-dsl.system {:structure sys-struct
                                         :dependencies {:cp-server [:client-chan]}}
                 options))

(deftest start-stop
  (testing "That we can start and stop successfully"
    (let [init (build)
          started (cpt/start init)]
      (is started)
      (is (cpt/stop started)))))
(comment
  (def test-sys (build))
  (alter-var-root #'test-sys cpt/start)
  (-> test-sys :client-chan keys)
  (alter-var-root #'test-sys cpt/stop)
  )

(deftest shake-hands
  (let [init (build)
        started (cpt/start init)]
    (println "Server should be started now")
    (try
      (println "Sending bogus HELLO")
      (let [client (get-in started [:client-chan :chan])
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
            success (deref (strm/try-put! client "Howdy!" 1000 ::timed-out))]
        (println "put! success:" success)
        (is (not= ::timed-out success)))
      (finally
        (println "Triggering event loop exit")
        (cpt/stop started)))))

(deftest test-cookie-composition
  (let [client-extension (byte-array (take 16 (repeat 0)))
        server-extension (byte-array (take 16 (range)))
        working-nonce (byte-array (take 24 (drop 40 (range))))
        boxed (byte-array 200)
        dst (Unpooled/buffer 400)
        to-encode {::K/header K/cookie-header
                   ::K/client-extension client-extension
                   ::K/server-extension server-extension
                   ::K/nonce (Unpooled/wrappedBuffer working-nonce
                                                     shared/server-nonce-prefix-length
                                                     K/server-nonce-suffix-length)
                   ;; This is also a great big FAIL:
                   ;; Have to drop the first 16 bytes
                   ;; Q: Have I fixed that yet?
                   ::K/cookie (Unpooled/wrappedBuffer boxed
                                                      K/box-zero-bytes
                                                      144)}]
    (try
      (let [composed (shared/compose K/cookie-frame to-encode dst)]
        (is composed))
      (catch clojure.lang.ExceptionInfo ex
        (is (not (.getData ex)))))))

(deftest vouch-extraction
  ;; TODO:
  ;; Use client/build-vouch to generate a vouch wrapper.
  ;; Then call server/decrypt-initiate-vouch to verify that
  ;; it extracted correctly.
  (throw RuntimeException. "Not Implemented"))
