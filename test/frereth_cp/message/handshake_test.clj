(ns frereth-cp.message.handshake-test
  (:require [clojure.edn :as edn]
            [clojure.spec.alpha :as s]
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Helper functions

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

(defn buffer-response!
  [io-handle
   prelog
   response
   success-message
   error-message
   error-details]
  ;; This actually sends a stream of data.
  ;; So prepend with the byte count
  (let [printed (pr-str response)
        payload (.getBytes printed)
        response-length (count payload)
        ;; 2 bytes for length encoding
        buffer (+ 2 response-length)]
    (b-t/uint16-pack! buffer 0 response-length)
    (b-t/byte-copy! buffer 2 response-length payload)
    (m-t/try-multiple-sends message/child->!
                            prelog
                            5
                            io-handle
                            buffer
                            success-message
                            error-message
                            error-details)))

(s/def ::prefix (s/nilable bytes?))
(s/def ::count nat-int?)
(s/def ::state (s/keys :req [::count
                             ::prefix]))
(s/def ::next-object any?)
(s/fdef extract-next-object-from-stream
        :args (s/cat :state ::state
                     :bs bytes?)
        :ret (s/keys :req [::state
                           ::next-object]))
(defn extract-next-object-from-stream
  "This is probably generally applicable"
  [{:keys [::prefix]
    :as state} bs]
  ;; Q: How much easier would using ByteBuf make this?
  ;; As it is, I feel like this needs its own unit test.
  (log/debug "Trying to extract object number"
             (inc (::count state))
             "from stream based upon"
             prefix "and" bs)
  (if-not (keyword? bs)
    (let [prefix-count (count prefix)
          buffer-size (+ prefix-count
                         (count bs))
          actual (if prefix
                   (let [buffer (byte-array buffer-size)]
                     (b-t/byte-copy! buffer prefix)
                     (b-t/byte-copy! buffer prefix-count bs)
                     buffer)
                   bs)
          object-length (b-t/uint16-unpack actual)]
      (let [next-object
            (if (<= object-length (+ 2 buffer-size))
              (let [next-object-bytes (b-t/sub-byte-array actual 2 (+ 2 object-length))]
                (edn/read-string (b-t/->string next-object-bytes)))
              nil)]
        (let [slice-of-bs (if next-object
                            (b-t/sub-byte-array actual (+ 2 object-length))
                            actual)]
          {::next-object next-object
           ::state (-> state
                       (assoc ::prefix slice-of-bs)
                       (update ::count inc))})))
    ;; Getting an EOF in the middle of the stream shouldn't
    ;; really be possible, but it would be annoying.
    ;; (i.e. if ::state has a ::prefix)
    ;; TODO: Warn about that scenario
    {::next-object bs
     ::state state}))

(defn server-mock-child
  [server-atom state-atom chzbrgr-length bs]
  (let [prelog (utils/pre-log "Server's child callback")
        _ (log/debug prelog "Message arrived at server's child")
        {:keys [::state]
         incoming ::next-object} (extract-next-object-from-stream @state-atom bs)]
    (reset! state-atom state)
    (when incoming
      (log/debug prelog
                 (str "Matching '" incoming
                      "', a " (class incoming)))
      (let [rsp (condp = incoming
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
          (buffer-response! @server-atom
                            prelog
                            rsp
                            "Message buffered to child"
                            "Giving up on forwarding to child"
                            {::response rsp
                             ::request incoming})
          (message/child-close! @server-atom))
        (when (= incoming ::icanhazchzbrgr?)
          ;; One of the main points is that this doesn't need to be a lock-step
          ;; request/response.
          (log/info prelog "Client requested chzbrgr. Send out of lock-step")
          (let [chzbrgr (byte-array (range chzbrgr-length))]
            (buffer-response! @server-atom
                              prelog
                              chzbrgr
                              "Buffered chzbrgr to child"
                              "Giving up on sending chzbrgr"
                              {})))))))

(defn mock-client-child
  [client-atom client-state succeeded? chzbrgr-length bs]
  (let [prelog (utils/pre-log "Handshake Client: child callback")
        _ (log/debug prelog "Message arrived at client's child")
        {incoming ::next-object
         :keys [::state]} (extract-next-object-from-stream @client-state bs)]
    (is bs)
    (is (< 0 (count bs)))
    (log/info prelog
              (str "Client State: "
                   @client-state
                   "\nreceived: "
                   incoming ", a " (class incoming)))
    (reset! client-state state)
    (when incoming
      (let [{:keys [::count]} state
            next-message
            (condp = (dec count)
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
                  (is (b-t/bytes= incoming (byte-array (range chzbrgr-length))))
                  ::kthxbai)
              4 (do
                  (is (= incoming ::kk))
                  (log/info "Client child callback is done")
                  (dfrd/success! succeeded? ::kthxbai)
                  (try
                    (message/child-close! @client-atom)
                    (catch RuntimeException ex
                      ;; CIDER doesn't realize that this is a failure.
                      ;; I blame something screwy in the testing
                      ;; harness. I *do* see this error message
                      ;; and the stack trace.
                      (log/error ex "This really shouldn't pass")
                      (is (not ex))))
                  nil))]
        ;; Hmm...I've wound up with a circular dependency
        ;; on the io-handle again.
        ;; Q: Is this a problem with my architecture, or just
        ;; a testing artifact?
        (when next-message
          (buffer-response! @client-atom
                            prelog
                            next-message
                            "Buffered bytes from child"
                            "Giving up on sending message from child"))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests functions

(deftest handshake
  (let [prelog (utils/pre-log "Handshake test")]
    (log/info prelog
              "Top")
    (let [client->server (strm/stream)
          server->client (strm/stream)
          succeeded? (dfrd/deferred)
          ;; Simulate a very stupid FSM
          client-state (atom {::count 0
                              ::prefix nil})
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
          chzbrgr-length 182
          client-child-cb (partial mock-client-child
                                   client-atom
                                   client-state
                                   succeeded?
                                   chzbrgr-length)

          server-atom (atom nil)
          server-state-atom (atom {::prefix nil
                                   ::count 0})
          server-parent-cb (fn [bs]
                             (log/info (utils/pre-log "Server's parent callback")
                                       "Sending a" (class bs) "to server's parent")
                             (let [sent (strm/try-put! server->client bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          server-child-cb (partial server-mock-child
                                   server-atom
                                   server-state-atom
                                   chzbrgr-length)]
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
              (let [client-message-state (message/get-state client-io time-out ::timed-out)]
                (when (or (= client-message-state ::timed-out)
                          (instance? Throwable client-state)
                          (nil? client-message-state))
                  (is not client-message-state))
                (when (= really-succeeded? ::timed-out)
                  (let [{:keys [::specs/flow-control]} client-state]
                    ;; I'm mostly interested in the next-action inside flow-control
                    ;; Down-side to switching to manifold for scheduling:
                    ;; I don't really have any insight into what's going on
                    ;; here.
                    ;; Q: Is that true? Or have I just not studied its
                    ;; docs thoroughly enough?
                    (is (not flow-control) "Client flow-control behind a timeout"))))
              (let [{:keys [::specs/flow-control]
                     :as srvr-state} (message/get-state server-io time-out ::timed-out)]
                (when (or (= srvr-state ::timed-out)
                          (instance? Throwable srvr-state)
                          (nil? srvr-state))
                  (is (not srvr-state)))
                (comment (is (not flow-control) "Server flow-control")))
              (is (= ::kthxbai really-succeeded?))
              (is (= 5 (-> client-state
                           deref
                           ::count)))))
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
