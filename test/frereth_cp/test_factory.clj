(ns frereth-cp.test-factory
  "Build common pieces that the tests share"
  (:require [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
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
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo))

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
  [logger log-state]
  (let [client-write-chan (strm/stream)
        client-read-chan (strm/stream)]
    {::cp-server {::log/logger logger
                  ::log/state log-state
                  ::shared/extension server-extension
                  ::shared/my-keys #::shared{::K/srvr-name server-name
                                             :keydir "curve-test"}
                  ::srvr-state/client-read-chan client-read-chan
                  ::srvr-state/client-write-chan client-write-chan
                  ::srvr-state/child-spawner (fn []
                                               ;; This needs to do something
                                               ;; Then again, that "something" very much depends
                                               ;; on the changes I'm currently making to the client
                                               ;; child fork mechanism.
                                               ;; FIXME: Get back to this once that is done.
                                               (throw (RuntimeException. "Not Implemented")))}}))

(defn build-server
  [logger log-state]
  (try
    (let [server (server/ctor (::cp-server (server-options logger log-state)))]
      {::cp-server server
       ::srvr-state/client-read-chan {::srvr-state/chan (::srvr-state/client-read-chan server)}
       ::srvr-state/client-write-chan {::srvr-state/chan (::srvr-state/client-write-chan server)}})
    (catch ExceptionInfo ex
      (log/flush-logs! logger (log/exception log-state
                                             ex
                                             ::build-server
                                             ""))
      (throw ex))))

(defn start-server
  [inited]
  (update inited ::cp-server server/start!))

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
  ([message-loop-name logger-init log-state srvr-ip srvr-port srvr-pk-long]
   (raw-client message-loop-name
               logger-init
               log-state
               srvr-ip
               srvr-port
               srvr-pk-long
               [0x01 0x02 0x03 0x04
                0x05 0x06 0x07 0x08
                0x09 0x0a 0x0b 0x0c
                0x0d 0x0e 0x0f 0x10]))
  ([message-loop-name logger-init log-state srvr-ip srvr-port srvr-pk-long srvr-xtn-vec]
   (let [key-dir "client-test"
         nonce-key-resource (io/resource (str key-dir
                                              "/.expertsonly/noncekey"))]
     (when-not nonce-key-resource
       (println "Building a new nonce-key")
       (crypto/new-nonce-key! key-dir))

     (let [server-extension (byte-array srvr-xtn-vec)
           ;; FIXME: Honestly, we need to cope with multiple servers.
           ;; Each could be listening on a different port with a different
           ;; long-term-pk
           srvr-name (shared/encode-server-name "hypothet.i.cal")
           long-pair (crypto/random-key-pair)
           result (clnt/ctor {::msg-specs/->child (strm/stream)  ; This seems wrong. Q: Is it?
                              ::client-state/chan<-server (strm/stream)
                              ::log/state log-state
                              ::msg-specs/message-loop-name message-loop-name
                              ::shared/my-keys {::shared/keydir key-dir
                                                ::shared/long-pair long-pair
                                                ::K/server-name server-name}
                              ::client-state/server-extension server-extension
                              ::client-state/server-security {::K/server-name srvr-name
                                                              ::K/server-ip srvr-ip
                                                              ::K/server-port srvr-port
                                                              ::shared-specs/public-long srvr-pk-long}}
                             logger-init)]
       (clnt/start! result)
       result))))
