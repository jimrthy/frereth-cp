(ns frereth-cp.message.handshake-test
  (:require [clojure.edn :as edn]
            [clojure.test :refer (are deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.message-test :as m-t]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import io.netty.buffer.Unpooled))

;;;; TODO: Consolidate these next 2 to eliminate duplication
(defn srvr->client-consumer
  [client-io time-out succeeded? bs]
  (let [prelog (utils/pre-log "server->client consumer")]
    (log/info prelog "Message from server to client")
    (let [client-state (message/get-state client-io time-out ::timed-out)]
      (if (or (= ::timed-out client-state)
              (instance? Throwable client-state)
              (nil? client-state))
        (let [problem (if (instance? Throwable client-state)
                        client-state
                        (ex-info "Non-exception in server->client consumer"
                                 {::problem client-state}))]
          (log/error problem prelog "Client failed!")
          (dfrd/error! succeeded? problem))
        (message/parent->! client-io bs)))))

(defn client->srvr-consumer
  [server-io time-out succeeded? bs]
  ;; Note that, at this point, we're blocking the
  ;; server's I/O loop.
  ;; Whatever happens here must return control
  ;; quickly.
  (let [prelog (utils/pre-log "client->server")]
    (log/info prelog "Incoming")
    ;; Checking for the server state is wasteful here.
    ;; And very dubious...depending on implementation details,
    ;; it wouldn't take much to shift this over to triggering
    ;; a deadlock (since we're really running on the event loop
    ;; thread).
    ;; Actually, I'm a little surprised that this works at all.
    ;; And it definitely *has* had issues.
    ;; Q: But is it worth it for the test's sake?
    (let [srvr-state (message/get-state server-io time-out ::timed-out)]
      (if (or (= ::timed-out srvr-state)
              (instance? Throwable srvr-state)
              (nil? srvr-state))
        (let [problem (if (instance? Throwable srvr-state)
                        srvr-state
                        (ex-info "Non-exception in client->server consumer"
                                 {::problem srvr-state}))]
          (do
            (log/error problem prelog "Server failed!")
            (dfrd/error! succeeded? problem)))
        (message/parent->! server-io bs)))))

(deftest handshake
  (let [prelog (utils/pre-log "Handshake test")]
    (log/info prelog
              "Top")
    (let [client->server (strm/stream)
          server->client (strm/stream)
          succeeded? (dfrd/deferred)
          ;; Simulate a very stupid FSM
          client-state (atom 0)
          client-atom (atom nil)
          time-out 500
          client-parent-cb (fn [^bytes bs]
                             (log/info (utils/pre-log "Client parent callback")
                                       "Sending a" (count bs)
                                       "byte array to client's parent")
                             (let [sent (strm/try-put! client->server bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          ;; Something that spans multiple packets would be better, but
          ;; that seems like a variation on this test.
          ;; Although this *does* take me back to the beginning, where
          ;; I was trying to figure out ways to gen the tests based upon
          ;; a protocol defined by something like spec.
          cheezburgr-length 182
          client-child-cb (fn [bs]
                            (is bs)
                            (let [s (String. bs)
                                  ;; This approach was wishful thinking. I've been getting
                                  ;; lucky up to now, because it happened to work.
                                  ;; Now that I'm getting close to a working implementation,
                                  ;; I'm receiving a real stream of bytes instead of the distinct
                                  ;; messages that I was receiving initially.
                                  ;; That is what I want, but it complicates this test.
                                  ;; TODO: Need to cope with this.
                                  incoming (edn/read-string s)
                                  prelog (utils/pre-log "Handshake Client: child callback")]
                              (is (< 0 (count s)))
                              (is incoming)
                              (log/info prelog
                                        (str "Client State: "
                                             @client-state
                                             "\nreceived: "
                                             incoming ", a " (class incoming)))
                              (let [next-message
                                    (condp = @client-state
                                      0 (do
                                          (is (= incoming ::orly?))
                                          ::yarly)
                                      1 (do
                                          (is (= incoming ::kk))
                                          ::icanhazchzbrgr?)
                                      2 (do
                                          (is (= incoming ::kk))
                                          ;; This is the protocol-level ACK
                                          ;; (which is different than the CurveCP
                                          ;; ACK message) associated
                                          ;; with the chzbrgr request
                                          ;; No response to send for this
                                          nil)
                                      3 (do
                                          ;; This is based around an implementation
                                          ;; detail that the message stream really consists
                                          ;; of either
                                          ;; a) the same byte array sent by the other side
                                          ;; b) several of those byte arrays, if the block
                                          ;; is too big to send all at once.
                                          ;; TODO: don't rely on that.
                                          ;; It really would be more efficient for the other
                                          ;; side to batch up the ACK and this response
                                          (is (b-t/bytes= incoming (byte-array (range cheezburgr-length))))
                                          ::kthxbai)
                                      4 (do
                                          (is (= incoming ::kk))
                                          (log/info "Client child callback is done")
                                          (dfrd/success! succeeded? ::kthxbai)
                                          (try
                                            (message/close! @client-atom)
                                            (catch RuntimeException ex
                                              ;; CIDER doesn't realize that this is a failure.
                                              ;; I blame something screwy in the testing
                                              ;; harness. I *do* see this error message
                                              ;; and the stack trace.
                                              (log/error ex "This really shouldn't pass")
                                              (is (not ex))))
                                          nil))]
                                (swap! client-state inc)
                                ;; Hmm...I've wound up with a circular dependency
                                ;; on the io-handle again.
                                ;; Q: Is this a problem with my architecture, or just
                                ;; a testing artifact?
                                (when next-message
                                  (let [actual (.getBytes (pr-str next-message))]
                                    (m-t/try-multiple-sends message/child->!
                                                            prelog
                                                            5
                                                            @client-atom
                                                            actual
                                                            (str "Buffered bytes from child")
                                                            "Giving up on sending message from child"
                                                            {}))))))

          server-atom (atom nil)
          server-parent-cb (fn [bs]
                             (log/info (utils/pre-log "Server's parent callback")
                                       "Sending a" (class bs) "to server's parent")
                             (let [sent (strm/try-put! server->client bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          server-child-cb (fn [bs]
                            (let [prelog (utils/pre-log "Server's child callback")
                                  incoming (edn/read-string (String. bs))
                                  _ (log/debug prelog
                                               (str "Matching '" incoming
                                                    "', a " (class incoming)) )
                                  rsp (condp = incoming
                                        ::ohai! ::orly?
                                        ::yarly ::kk
                                        ::icanhazchzbrgr? ::kk
                                        ::kthxbai ::kk
                                        ::specs/normal ::specs/normal)]
                              (log/info prelog
                                        "Server received"
                                        incoming
                                        "\nwhich triggers"
                                        rsp)
                              (if (not= rsp ::specs/normal)
                                (let [actual (.getBytes (pr-str rsp))]
                                  (m-t/try-multiple-sends message/child->!
                                                          prelog
                                                          5
                                                          @server-atom
                                                          actual
                                                          "Message buffered to child"
                                                          "Giving up on forwarding to child"
                                                          {::response rsp
                                                           ::request incoming}))
                                (message/close! @server-atom))
                              (when (= incoming ::icanhazchzbrgr?)
                                ;; One of the main points is that this doesn't need to be a lock-step
                                ;; request/response.
                                (log/info prelog "Client requested chzbrgr. Send out of lock-step")
                                (let [chzbrgr (byte-array (range cheezburgr-length))]
                                  (m-t/try-multiple-sends message/child->!
                                                          prelog
                                                          5
                                                          @server-atom
                                                          chzbrgr
                                                          "Buffered chzbrgr to child"
                                                          "Giving up on sending chzbrgr"
                                                          {})))))]
      (dfrd/on-realized succeeded?
                        (fn [good]
                          (log/info "----------> Test should have passed <-----------"))
                        (fn [bad]
                          (log/error bad "High-level test failure")
                          (is (not bad))))

      (let [client-init (message/initial-state "Client" {} false)
            client-io (message/start! client-init client-parent-cb client-child-cb)
            server-init (message/initial-state "Server" {} true)
            ;; It seems like this next part really shouldn't happen until the initial message arrives
            ;; from the client.
            ;; Actually, it starts when the Initiate(?) packet arrives as part of the handshake. So
            ;; that isn't quite true
            server-io (message/start! server-init server-parent-cb server-child-cb)]
        (reset! client-atom client-io)
        (reset! server-atom server-io)

        (try
          (strm/consume (partial client->srvr-consumer server-io time-out succeeded?)
                        client->server)
          (strm/consume (partial srvr->client-consumer client-io time-out succeeded?)
                        server->client)

          (let [initial-message (Unpooled/buffer K/k-1)
                helo (.getBytes (pr-str ::ohai!))]
            ;; Kick off the exchange
            (m-t/try-multiple-sends message/child->!
                                    prelog
                                    5
                                    client-io
                                    helo
                                    "HELO sent"
                                    "Sending HELO failed"
                                    {})
            ;; TODO: Find a reasonable value for this timeout
            (let [really-succeeded? (deref succeeded? 10000 ::timed-out)]
              (log/info "handshake-test run through. Need to see what happened")
              (let [client-state (message/get-state client-io time-out ::timed-out)]
                (when (or (= client-state ::timed-out)
                          (instance? Throwable client-state)
                          (nil? client-state))
                  (is not client-state))
                (when (= really-succeeded? ::timed-out)
                  (let [{:keys [::specs/flow-control]} client-state]
                    ;; I'm mostly interested in the next-action inside flow-control
                    ;; Down-side to switching to manifold for scheduling:
                    ;; I don't really have any insight into what's going on
                    ;; here.
                    ;; Q: Is that true? Or have I just not studied its
                    ;; docs thoroughly enough?
                    (is (not flow-control) "Client flow-control"))))
              (let [{:keys [::specs/flow-control]
                     :as srvr-state} (message/get-state server-io time-out ::timed-out)]
                (when (or (= srvr-state ::timed-out)
                          (instance? Throwable srvr-state)
                          (nil? srvr-state))
                  (is (not srvr-state)))
                (comment (is (not flow-control) "Server flow-control")))
              (is (= ::kthxbai really-succeeded?))
              (is (= 5 @client-state))))
          (finally
            (log/info "Cleaning up")
            (try
              (message/halt! client-io)
              (catch Exception ex
                (log/error ex "Trying to halt client")))
            (try
              (message/halt! server-io)
              (catch Exception ex
                (log/error ex "Trying to halt server")))))))))
(comment
  (handshake)
  (count (str ::kk))
  (String. (byte-array [0 1 2]))
  )
