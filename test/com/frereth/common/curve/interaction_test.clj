(ns com.frereth.common.curve.interaction-test
  (:require [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is)]
            [com.frereth.common.curve.client :as clnt]
            [com.frereth.common.curve.server :as srvr]
            [com.frereth.common.curve.server-test :as server-test]
            [com.frereth.common.curve.shared :as shared]
            [manifold.deferred :as deferred]
            [manifold.stream :as strm])
  (:import [clojure.lang ExceptionInfo]))

(defn retrieve-hello
  [client-chan hello]
  (println "Pulled HELLO from client")
  (println "Have" (count hello) "bytes to write to " client-chan)
  (if (= 224 (count hello))
    (strm/put! (:chan client-chan) hello)
    (throw (RuntimeException. "Bad Hello"))))

(defn wrote-hello
  [client-chan success]
  (is success "Failed to write hello to server")
  ;; TODO: I'm pretty sure I need to split
  ;; this into 2 channels so I don't pull back
  ;; the hello that I just put on there
  (strm/try-take! client-chan ::drained 500 ::timeout))

(defn forward-cookie
  [client<-server cookie]
  (when-not (keyword? cookie)
    (is (= 200 (count cookie)))
    (strm/try-put! client<-server cookie 500 ::timeout)))

(defn wrote-cookie
  [clnt->srvr success]
  (println "D")
  (is success)
  (is (not= success ::timeout))
  (strm/try-take! clnt->srvr ::drained 500 ::timeout))

(defn vouch->server
  [client-chan vouch]
  (if (and (not= vouch ::drained)
           (not= vouch ::timeout))
    (strm/try-put! client-chan vouch 500 ::timeout)
    (throw (ex-info "Retrieving Vouch from client failed"
                    {:failure vouch}))))

(defn wrote-vouch
  [client-chan success]
  (if success
    (strm/try-take! client-chan ::drained 500 ::timeout)
    (throw (RuntimeException. "Failed writing Vouch to client"))))

(defn finalize
  [client<-server response]
  (is response "Handshake should be complete")
  (strm/try-put! client<-server response 500 ::timeout))

(defn client-child-spawner
  [client-agent]
  (comment (spit "/home/james/hey-you.txt" "Spawning child"))
  (println "Top of client-child-spawner")
  ;; Q: What should this really do?
  (let [result (strm/stream)
        child (future
                (println "Client child sending bytes to server via client")
                (let [written (strm/try-put! result
                                             "Hello, out there!"
                                             2500
                                             ::timedout)]
                  (println "Client-child send result:" @written)))]
    {::clnt/child child
     ::clnt/reader result
     ::clnt/writer strm/stream}))

(deftest handshake
  (let [server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                      0x0d 0x0e 0x0f 0x10])
        server-long-pk (byte-array [37 108 -55 -28 25 -45 24 93
                                    51 -105 -107 -125 -120 -41 83 -46
                                    -23 -72 109 -58 -100 87 115 95
                                    89 -74 -21 -33 20 21 110 95])
        server-name (shared/encode-server-name "test.frereth.com")
        options {::server #::shared{:extension server-extension
                                    :my-keys #::shared{:server-name server-name
                                                       :keydir "curve-test"}}
                 ::client {::shared/extension (byte-array [0x10 0x0f 0x0e 0x0d
                                                           0x0c 0x0b 0x0a 0x09
                                                           0x08 0x07 0x06 0x05
                                                           0x04 0x03 0x02 0x01])
                           ::clnt/child-spawner client-child-spawner
                           ::clnt/server-extension server-extension
                           ;; Q: Where do I get the server's public key?
                           ;; A: Right now, I just have the secret key's 32 bytes encoded as
                           ;; the alphabet.
                           ;; TODO: Really need to mirror what the code does to load the
                           ;; secret key from a file.
                           ;; Then I can just generate a random key pair for the server.
                           ;; Use the key-put functionality to store the secret, then
                           ;; hard-code the public key here.
                           ::clnt/server-security {::clnt/server-long-term-pk server-long-pk
                                                   ::shared/server-name server-name}}}
        chan->server (strm/stream)
        chan<-server (strm/stream)
        ;; TODO: This seems like it would be a great place to try switching to integrant
        client (clnt/ctor (assoc (::client options)
                                 ::clnt/chan<-server chan<-server
                                 ::clnt/chan->server chan->server))
        unstarted-server (srvr/ctor (::server options))
        ;; Flip the meaning of these channel names,
        ;; because we're looking at things inside out.
        ;; From the perspective of the client, this is
        ;; the stream it uses to communicate with the
        ;; server.
        ;; But it's the one we use to communicate with
        ;; the client.
        unstarted-client-chan (server-test/chan-ctor nil)
        client-chan (.start unstarted-client-chan)]
    (try
      (println "Starting server based on\n"
               #_(with-out-str (pprint (srvr/hide-long-arrays unstarted-server)))
               "...stuff...")
      (try
        (let [server (srvr/start! (assoc unstarted-server ::srvr/client-chan client-chan))]
          (try
            ;; Currently just called for side-effects.
            ;; TODO: Seems like I really should hide that little detail
            ;; by having it return this.
            ;; Except that that "little detail" really sets off the handshake
            ;; Q: Is there anything interesting about the deferred that it
            ;; currently returns?
            (let [eventually-started (clnt/start! client)
                  clnt->srvr (::clnt/chan->server @client)]
              (when-not (= chan->server clnt->srvr)
                (assert false (str "Client channels don't match.\n"
                                   "Expected:" chan->server
                                   "\nHave:" clnt->srvr)))
              (let [_ (assert clnt->srvr)
                    write-hello (partial retrieve-hello client-chan)
                    get-cookie (partial wrote-hello client-chan)
                    write-cookie (partial forward-cookie chan<-server)
                    get-cookie (partial wrote-cookie clnt->srvr)
                    write-vouch (partial vouch->server client-chan)
                    get-server-response (partial wrote-vouch client-chan)
                    write-server-response (partial finalize chan<-server)
                    _ (println "interaction-test: Starting the stream "
                               clnt->srvr)
                    fut (deferred/chain (strm/take! clnt->srvr)
                          write-hello
                          get-cookie
                          write-cookie
                          get-cookie
                          write-vouch
                          get-server-response
                          write-server-response
                          (fn [wrote]
                            (is (not= wrote ::timeout))))]
                (println "Dereferencing the deferreds set up by handshake")
                (let [outcome (deref fut 5000 ::timeout)]
                  (when (instance? Exception outcome)
                    (if (instance? RuntimeException outcome)
                      (if (instance? ExceptionInfo outcome)
                        (do
                          (println "FAIL:" outcome)
                          (pprint (.getData outcome)))
                        (do
                          (println "Ugly failure:" outcome)))
                      (println "Low Level Failure:" outcome))
                    (.printStackTrace outcome)
                    (throw outcome))
                  (is (not= outcome ::timeout)))
                ;; This really should have been completed as soon as
                ;; I read from chan->server2 the first time
                ;; Q: Right?
                (is (not= (deref eventually-started 500 ::timeout)
                          ::timeout))))
            (catch Exception ex
              (println "Unhandled exception escaped!")
              (.printStackTrace ex)
              (is (not ex)))
            (finally
              (println "Test done. Stopping server.")
              (srvr/stop! server))))
        (catch clojure.lang.ExceptionInfo ex
          (is (not (.getData ex)))))
      (finally (.stop client-chan)))))
