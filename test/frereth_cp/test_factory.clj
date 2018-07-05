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
            [manifold.executor :as exec]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           java.net.InetAddress))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(def server-extension (byte-array [0x01 0x02 0x03 0x04
                                   0x05 0x06 0x07 0x08
                                   0x09 0x0a 0x0b 0x0c
                                   0x0d 0x0e 0x0f 0x10]))

(def server-name (shared/encode-server-name "test.frereth.com"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helpers

(defn server-options
  [logger log-state]
  (let [client-write-chan (strm/stream)
        client-read-chan (strm/stream)
        child-id-atom (atom 0)
        executor (exec/fixed-thread-executor 4)]
    {::cp-server {::log/logger logger
                  ::log/state log-state
                  ::shared/extension server-extension
                  ::shared/my-keys #::shared{::shared-specs/srvr-name server-name
                                             :keydir "curve-test"}
                  ::srvr-state/client-read-chan {::srvr-state/chan client-read-chan}
                  ::srvr-state/client-write-chan {::srvr-state/chan client-write-chan}
                  ::srvr-state/child-spawner! (fn []
                                                (println "FIXME: Server child state spawned")
                                                ;; This needs to do something
                                                ;; Then again, that "something" very much depends
                                                ;; on the changes I'm currently making to the client
                                                ;; child fork mechanism.
                                                ;; FIXME: Get back to this once that is done.
                                                {::srvr-state/child-id (swap! child-id-atom inc)
                                                 ::srvr-state/read<-child (strm/stream 2 nil executor)
                                                 ::srvr-state/write->child (strm/stream 2 nil executor)})}}))

(defn build-server
  [logger log-state]
  (try
    (let [server (server/ctor (::cp-server (server-options logger log-state)))]
      {::cp-server server
       ::srvr-state/client-read-chan (::srvr-state/client-read-chan server)
       ::srvr-state/client-write-chan (::srvr-state/client-write-chan server)})
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
    (println "Closing" ch)
    (strm/close! ch))
  (let [ch (get-in started [::srvr-state/client-write-chan ::srvr-state/chan])]
    (strm/close! ch))
  {::cp-server (server/stop! (::cp-server started))
   ::srvr-state/client-read-chan {::srvr-state/chan nil}
   ::srvr-state/client-write-chan {::srvr-state/chan nil}})

;; FIXME: This spec still doesn't match the function signature at all
(s/fdef raw-client
        :args (s/or :sans-xtn (s/cat :message-loop-name ::msg-specs/message-loop-name
                                     :logger-init (s/fspec :args nil :ret ::log/logger)
                                     :log-state ::log/state
                                     :server-ip (s/tuple int? int? int? int?)
                                     :srvr-port ::shared-specs/port
                                     :srvr-pk-long ::shared-specs/public-long
                                     :->child ::msg-specs/->child
                                     :child-spawner! ::msg-specs/child-spawner!)
                    :with-xtn (s/cat :message-loop-name ::msg-specs/message-loop-name
                                     :logger-init (s/fspec :args nil :ret ::log/logger)
                                     :log-state ::log/state
                                     :server-ip (s/tuple int? int? int? int?)
                                     :srvr-port ::shared-specs/port
                                     :srvr-pk-long ::shared-specs/public-long
                                     :srvr-xtn-vec (s/and vector?
                                                          #(= (count %) K/extension-length))
                                     :->child ::msg-specs/->child
                                     :child-spawner! ::msg-specs/child-spawner!))
        :ret ::client-state/state)
(defn raw-client
  ([message-loop-name logger-init log-state srvr-ip srvr-port srvr-pk-long ->child child-spawner!]
   (raw-client message-loop-name
               logger-init
               log-state
               srvr-ip
               srvr-port
               srvr-pk-long
               [0x01 0x02 0x03 0x04
                0x05 0x06 0x07 0x08
                0x09 0x0a 0x0b 0x0c
                0x0d 0x0e 0x0f 0x10]
               ->child
               child-spawner!))
  ([message-loop-name logger-init log-state srvr-ip srvr-port srvr-pk-long srvr-xtn-vec ->child child-spawner!]
   (let [key-dir "client-test"
         nonce-key-resource (io/resource (str key-dir
                                              "/.expertsonly/noncekey"))]
     (when-not nonce-key-resource
       (println "Building a new nonce-key")
       (crypto/new-nonce-key! key-dir))

     (let [server-extension (byte-array srvr-xtn-vec)
           ;; FIXME: Honestly, we need to cope with multiple servers.
           ;; Each could be listening on a different port with a different
           ;; long-term-pk.
           ;; For starters, I should just add a test that tries, for example,
           ;; 3 different addresses before it finds one that responds.
           ;; Then again, that test should run in the background behind others,
           ;; since it's basically just waiting for timeouts.
           ;; Better choice: make the timeout customizable
           srvr-name (shared/encode-server-name "hypothet.i.cal")
           long-pair (crypto/random-key-pair)
           result (clnt/ctor {::client-state/chan<-server (strm/stream)
                              ::log/state log-state
                              ::msg-specs/->child ->child
                              ::msg-specs/child-spawner! child-spawner!
                              ::msg-specs/message-loop-name message-loop-name
                              ::shared/my-keys {::shared/keydir key-dir
                                                ::shared/long-pair long-pair
                                                ::shared-specs/srvr-name server-name}
                              ::client-state/server-extension server-extension
                              ::client-state/server-ips [(InetAddress/getByAddress (byte-array srvr-ip))]
                              ::client-state/server-security {::shared-specs/srvr-name srvr-name
                                                              ::shared-specs/srvr-port srvr-port
                                                              ::shared-specs/public-long srvr-pk-long}}
                             logger-init)]
       ;; Starting in a future like this is nerve-racking.
       ;; If nothing else, the callers don't have any way to check what happened, unless I add this
       ;; to the response.
       ;; Or possible just return this. Maybe as a deferred running on an executor? Or, really,
       ;; just used dfrd/future.
       ;; Those options fail because start! will block until something pulls the Hello packet
       ;; from the to-server channel.
       (future
         (clnt/start! result))
       result))))
