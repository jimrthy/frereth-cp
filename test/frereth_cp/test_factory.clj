(ns frereth-cp.test-factory
  "Build common pieces that the tests share"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.client :as clnt]
            [frereth-cp.client.state :as client-state]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.server :as server]
            [frereth-cp.server.state :as srvr-state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log]
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
        :args (s/cat :message-loop-name ::msg-specs/message-loop-name
                     :child-spawner ::clnt/child-spawner
                     :srvr-pk-long ::shared-specs/public-long
                     :srvr-xtn-vec (s/and vector?
                                          #(= (count %) K/extension-length)))
        :ret ::client-state/state-agent)
(defn raw-client
  ([message-loop-name logger srvr-pk-long]
   (raw-client message-loop-name
               logger
               srvr-pk-long
               [0x01 0x02 0x03 0x04
                0x05 0x06 0x07 0x08
                0x09 0x0a 0x0b 0x0c
                0x0d 0x0e 0x0f 0x10]))
  ([message-loop-name logger srvr-pk-long srvr-xtn-vec]
   (let [server-extension (byte-array srvr-xtn-vec)
         server-name (shared/encode-server-name "hypothet.i.cal")
         long-pair (crypto/random-key-pair)
         log-state (log/init message-loop-name)
         result (clnt/ctor {::msg-specs/->child (strm/stream)
                            ::client-state/chan->server (strm/stream)
                            ::log/logger logger
                            ::msg-specs/message-loop-name message-loop-name
                            ::shared/my-keys {::shared/keydir "client-test"
                                              ::shared/long-pair long-pair
                                              ::K/server-name server-name}
                            ::client-state/server-extension server-extension
                            ::client-state/server-security {::K/server-name server-name
                                                            ::shared-specs/public-long srvr-pk-long}
                            ::log/state log-state})]
     (clnt/start! result)
     result)))
