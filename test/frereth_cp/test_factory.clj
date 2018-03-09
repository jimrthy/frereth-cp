(ns frereth-cp.test-factory
  "Build common pieces that the tests share"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.client :as clnt]
            [frereth-cp.client.state :as client-state]
            [frereth-cp.server :as server]
            [frereth-cp.server.state :as srvr-state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.specs :as shared-specs]
            [manifold.stream :as strm]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(def server-extension (byte-array [0x01 0x02 0x03 0x04
                                   0x05 0x06 0x07 0x08
                                   0x09 0x0a 0x0b 0x0c
                                   0x0d 0x0e 0x0f 0x10]))

(def server-name (shared/encode-server-name "test.frereth.com"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helpers

(defn server-options
  []
  {::cp-server {::shared/extension server-extension
                ::shared/my-keys #::shared{::K/server-name server-name
                                           :keydir "curve-test"}}})

(defn build-server
  []
  {::cp-server (server/ctor (::cp-server (server-options)))
   ::srvr-state/client-read-chan {::srvr-state/chan (strm/stream)}
   ::srvr-state/client-write-chan {::srvr-state/chan (strm/stream)}})

(defn start-server
  [inited]
  (let [client-write-chan (::srvr-state/client-write-chan inited)
        client-read-chan (::srvr-state/client-read-chan inited)]
    {::cp-server (server/start! (assoc (::cp-server inited)
                                       ::srvr-state/client-read-chan client-read-chan
                                       ::srvr-state/client-write-chan client-write-chan))
     ::srvr-state/client-read-chan client-read-chan
     ::srvr-state/client-write-chan client-write-chan}))

(defn stop-server
  [started]
  (let [ch (get-in started [::srvr-state/client-read-chan ::srvr-state/chan])]
    (strm/close! ch))
  (let [ch (get-in started [::srvr-state/client-write-chan ::srvr-state/chan])]
    (strm/close! ch))
  {::cp-server (server/stop! (::cp-server started))
   ::srvr-state/client-read-chan {::srvr-state/chan nil}
   ::srvr-state/client-write-chan {::srvr-state/chan nil}})

(s/fdef raw-client
        :args (s/cat :child-spawner ::clnt/child-spawner
                     :server-keys ::shared-specs/peer-keys))
(defn raw-client
  [child-spawner]
  (let [long-srvr-keys (crypto/random-keys ::crypto/long)
        pk-long (::shared-specs/my-long-public long-srvr-keys)
        shrt-srvr-keys (crypto/random-keys ::crypto/short)
        pk-shrt (::shared-specs/my-short-public shrt-srvr-keys)
        server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                      0x0d 0x0e 0x0f 0x10])
        server-name (shared/encode-server-name "hypothet.i.cal")
        long-pair (crypto/random-key-pair)
        result (clnt/ctor {;; Aleph supplies a single bi-directional channel.
                           ;; My tests break trying to use that here.
                           ;; For now, take a step back and get them working
                           ::client-state/chan<-server (strm/stream)
                           ::client-state/chan->server (strm/stream)
                           ::shared/my-keys {::shared/keydir "client-test"
                                             ::shared/long-pair long-pair
                                             ::K/server-name server-name}
                           ::clnt/child-spawner child-spawner
                           ::client-state/server-extension server-extension
                           ::client-state/server-security {::K/server-name server-name
                                                           ::shared-specs/public-long pk-long
                                                           ::client-state/public-short pk-shrt}})]
    (clnt/start! result)
    {::client-agent result
     ::long-srvr-keys long-srvr-keys
     ::shrt-srvr-keys shrt-srvr-keys}))
