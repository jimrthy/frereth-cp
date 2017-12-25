(ns frereth-cp.message.handshake-test
  (:require [clojure.edn :as edn]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (are deftest is testing)]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.message-test :as m-t]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.util :as utils]
            [gloss.core :as gloss]
            [gloss.io :as io]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::prefix (s/nilable bytes?))
(s/def ::count nat-int?)
(s/def ::state (s/keys :req [::count
                             ::prefix]))
(s/def ::next-object any?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def protocol
  (gloss/compile-frame
   (gloss/finite-frame :uint16
                       (gloss/string :utf-8))
   pr-str
   edn/read-string))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Helper functions

(defn consumer
  [{:keys [::specs/message-loop-name]
    :as io-handle}
   log-atom
   log-ctx
   time-out
   succeeded?
   bs]
  ;; Note that, at this point, we're blocking the
  ;; I/O loop.
  ;; Whatever happens here must return control
  ;; quickly.
  ;; Note also that this really isn't something
  ;; that clients should be writing.
  ;; This is really just mocking out all the pieces
  ;; that the parent handles (like encryption
  ;; and network writes) to transmit to its peer.
  ;; Then again, you *could* do something like
  ;; this, to experiment with the unencrypted
  ;; networking protocol.
  (swap! log-atom log/info log-ctx "Message over network")

  (let [prelog (utils/pre-log message-loop-name)
        consumption (dfrd/future
                      ;; Checking for the server state is wasteful here.
                      ;; And very dubious...depending on implementation details,
                      ;; it wouldn't take much to shift this over to triggering
                      ;; a deadlock (since we're really running on the event loop
                      ;; thread).
                      ;; Actually, I'm a little surprised that this works at all.
                      ;; And it definitely *has* had issues.
                      ;; Q: But is it worth it for the test's sake?
                      ;; Better Q: Is this the sort of thing that will trip
                      ;; us up with surprising behavior if it doesn't work?
                      (let [state (message/get-state io-handle time-out ::timed-out)]
                        (swap! log-atom
                               log/debug
                               log-ctx
                               "Got state"
                               {::state state
                                ::parent-context prelog})
                        (if (or (= ::timed-out state)
                                (instance? Throwable state)
                                (nil? state))
                          (let [problem (if (instance? Throwable state)
                                          state
                                          (ex-info "Non-exception"
                                                   {::problem state}))]
                            (is (not problem))
                            (swap! log-atom
                                   log/exception
                                   problem
                                   log-ctx
                                   "Failed!"
                                   {::triggered-from prelog})
                            (if (realized? succeeded?)
                              (swap! log-atom
                                     log/warn
                                     log-ctx
                                     "Caller already thinks we succeeded"
                                     {::triggered-by prelog})
                              (dfrd/error! succeeded? problem)))
                          (message/parent->! io-handle bs))))]
    (dfrd/on-realized consumption
                      (fn [success]
                        (swap! log-atom
                               log/debug
                               log-ctx
                               "Message successfully consumed"
                               {::outcome success
                                ::triggered-from prelog}))
                      (fn [failure]
                        (swap! log-atom
                               log/error
                               log-ctx
                               "Failed to consume message"
                               {::problem failure
                                ::triggered-from prelog})))))

(defn srvr->client-consumer
  "This processes bytes that are headed from the server to the client"
  [client-io log-atom time-out succeeded? bs]
  (consumer client-io
            log-atom
            ::srvr->client-consumer
            time-out
            succeeded?
            bs))

(defn client->srvr-consumer
  [server-io log-atom time-out succeeded? bs]
  (let [prelog (utils/pre-log "client->server consumer")]
    (consumer server-io
              log-atom
              ::client->srvr-consumer
              time-out
              succeeded?
              bs)))

(defn buffer-response!
  "Serialize and send a message from the child"
  [io-handle
   message-loop-name
   log-atom
   message
   success-message
   error-message
   error-details]
  (let [frames (io/encode protocol message)
        prelog (utils/pre-log message-loop-name)]
    (swap! log-atom
           log/debug
           ::buffer-response!
           "Ready to send message frames"
           {::frame-count (count frames)})
    (doseq [frame frames]
      (let [array (if (.hasArray frame)
                    (.array frame)
                    (let [result (byte-array (.readableBytes frame))]
                      (.readBytes frame result)))]
        ;; This is actually a java.nio.HeapByteBuffer.
        ;; Which is a totally different animal from a reference-counted ByteBuf
        ;; from netty.
        (comment (.release frame))
        (if-not (message/child->! io-handle array)
          (throw (ex-info "Sending failed"
                          {::failed-on frame
                           ::context prelog}))
          (swap! log-atom
                 log/debug
                 ::buffer-response!
                 "frame sent"
                 {::frame-size (count array)}))))))
(comment
  ;; Inline test for test-helper.
  ;; This seems like a bad sign.
  ;; It's tempting to expand this to its own unit test
  ;; It seems like doing that would just formalize the complexity.
  ;; Q: Is this incidental or inherent?
  (io/encode protocol ::test)
  (let [chzbrgr-length 182
        frames (io/encode protocol (range chzbrgr-length))
        [length payload] frames
        chzbrgr (byte-array (.getShort length))]
    (.get payload chzbrgr)
    (String. chzbrgr))
  )

(defn decoder
  [src]
  (io/decode-stream src protocol))

(defn decode-bytes->child
  [decode-src decode-sink log-atom bs]
  (comment) (swap! log-atom
                   log/debug
                   ::decode-bytes->child
                   "Trying to decode"
                   (if-not (keyword? bs)
                     {::message-size (count bs)}
                     {::eof-flag bs}) bs)
  (if-not (keyword? bs)
    (do
      (when (= 2 (count bs))
        (swap! log-atom
               log/debug
               ::decode-bytes->child
               (str "This is probably a prefix expecting "
                    (b-t/uint16-unpack bs)
                    " bytes")))
      (let [decoded (strm/try-take! decode-sink ::drained 10 false)]
        (strm/put! decode-src bs)
        (deref decoded 10 false)))
    bs))

(defn server-child-processor
  [server-atom state-atom log-atom chzbrgr-length incoming]
  (is incoming)
  (is (or (keyword? incoming)
          (and (bytes? incoming)
               (< 0 (count incoming)))))
  (swap! log-atom
         log/debug
         ::server-child-processor
         (str "Matching '" incoming
              "', a " (class incoming))
         {::server-state @server-atom
          ::other-state @state-atom})
  (let [rsp (condp = incoming
              ::ohai! ::orly?
              ::yarly ::kk
              ::icanhazchzbrgr? ::kk
              ::kthxbai ::kk
              ::specs/normal ::specs/normal)]
    (swap! log-atom
           log/info
           ::server-child-processor
           "Incoming triggered"
           {::incoming incoming
            ::response rsp})
    (if (not= rsp ::specs/normal)
      ;; Happy path
      (buffer-response! @server-atom
                        "server"
                        log-atom
                        rsp
                        "Message buffered to child"
                        "Giving up on forwarding to child"
                        {::response rsp
                         ::request incoming})
      (message/child-close! @server-atom))
    (when (= incoming ::icanhazchzbrgr?)
      ;; One of the main points is that this doesn't need to be a lock-step
      ;; request/response.
      (swap! log-atom log/info ::server-child-processor
             "Client requested chzbrgr. Send out of lock-step")
      ;; Only 3 messages are arriving at the client.
      ;; This almost definitely means that the chzbrgr is the problem.
      ;; Trying to send a raw byte-array here definitely does not work.
      ;; Sending the lazy seq that range produces seems like a bad idea.
      ;; Sending a vec like this doesn't help.
      ;; Note that, whatever I *do* send here, the client needs to
      ;; be updated to expect that type.
      (let [chzbrgr (vec (range chzbrgr-length))]
        ;; This is buffering far more bytes than expected.
        ;; That's because it's encoding an EDN string instead of
        ;; the raw byte-array with which I started.
        ;; (Can't just supply a byte-array because the other
        ;; side doesn't have a reader override to decode that.
        ;; And it wouldn't gain anything to add it, since it would
        ;; still be the string representation of the numbers.
        ;; That's annoying, but it should be good enough for
        ;; purposes of this test.
        (buffer-response! @server-atom
                          "client"
                          log-atom
                          chzbrgr
                          "Buffered chzbrgr to child"
                          "Giving up on sending chzbrgr"
                          {})))))

(defn client-child-processor
  "Process the messages queued by mock-client-child"
  [client-atom client-state-atom log-atom succeeded? chzbrgr-length incoming]
  (is (or (keyword? incoming)
          ;; Implementation detail:
          ;; incoming is deserialized EDN.
          ;; Which means it's either a keyword for the handshake
          ;; or the chzbrgr.
          (seq incoming))
      (str "Incoming: "
           (if (keyword? incoming)
             incoming
             (str incoming ", a" (class incoming)))))
  (let [client-state @client-state-atom]
    (swap! log-atom log/info ::client-child-processor "incoming"
           {::client-state client-state
            ::received incoming})
    (if incoming
      (let [{n ::count} client-state
            next-message
            (condp = n
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
                  ;; This should be the chzbrgr
                  (is (= incoming (range chzbrgr-length)))
                  ::kthxbai)
              4 (do
                  (is (= incoming ::kk))
                  (swap! log-atom
                         log/info
                         ::client-child-processor
                         "Client child callback is done")
                  (try
                    (message/child-close! @client-atom)
                    (catch RuntimeException ex
                      ;; CIDER doesn't realize that this is a failure.
                      ;; I blame something screwy in the testing
                      ;; harness. I *do* see this error message
                      ;; and the stack trace.
                      (log/error ex "This really shouldn't pass")
                      (is (not ex))))
                  nil)
              5 (do
                  (is (= incoming ::specs/normal))
                  (swap! log-atom
                         log/info
                         ::client-child-processor
                         "Received server EOF")
                  (dfrd/success! succeeded? ::kthxbai)
                  ;; At this point, we signalled the end of the transaction.
                  ;; We closed our outbound pipe in the previous step,
                  ;; which is what closed this.
                  ;; It might be useful to deliver some sort of promise
                  ;; here to make the test more obvious.
                  ;; But, honestly, winding up at state
                  ;; 6 after this pretty much says it all.
                  nil))]
        (swap! log-atom
               log/info
               "response triggered"
               ;; This approach hides the context that set this
               ;; up.
               ;; Then again, that's just the unit test, so it
               ;; really isn't very interesting
               {::incoming incoming
                ::next-message next-message})
        (swap! client-state-atom update ::count inc)
        ;; Hmm...I've wound up with a circular dependency
        ;; on the io-handle again.
        ;; Q: Is this a problem with my architecture, or just
        ;; a testing artifact?
        (when next-message
          (buffer-response! @client-atom
                            "from-client"
                            log-atom
                            next-message
                            "Buffered bytes from child"
                            "Giving up on sending message from child"
                            {}))
        (let [result (> 6 n)]
          (swap! log-atom log/debug ::client-child-processor "returning" result)
          result))
      (swap! log-atom
             log/error
             ::client-child-processor
             "No bytes decoded. Shouldn't have gotten here"))))

(defn child-mocker
  "Functionality shared between client and server"
  [logger log-atom log-ctx arrival-msg decode-src bs-or-kw]
  (swap! log-atom
         log/debug
         log-ctx
         (if (keyword? bs-or-kw)
           (str bs-or-kw)
           (str (count bs-or-kw) "-byte"))
         arrival-msg)
  (if-not (keyword? bs-or-kw)
    (strm/put! decode-src bs-or-kw)
    (doseq [frame (io/encode protocol bs-or-kw)]
      (strm/put! decode-src frame)))
  (swap! log-atom
         log/debug
         log-ctx
         "Messages forwarded to decoder")
  (swap! log-atom #(log/flush-logs! logger %)))

(defn mock-server-child
  "Callback for messages that arrived from client"
  [decode-src logger log-atom bs]
  (let [prelog (utils/pre-log "Handshake Server: child callback")]
    (child-mocker logger
                  log-atom
                  ::server-child
                  "message arrived at server's child"
                  decode-src
                  bs)))

(defn mock-client-child
  "This is the callback for messages arriving from server"
  [decode-src logger log-atom bs]
  (let [prelog (utils/pre-log "Handshake Client: child callback")]
    (child-mocker logger
                  log-atom
                  ::client-child
                  "message arrived at client's child"
                  decode-src
                  bs)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest check-decoder
  ;; Tests for checking my testing code seems like a really bad sign.
  ;; Then again, this really is an integration test. It's covering
  ;; a *lot* of functionality.
  ;; And I've made it extra-complicated by refusing to consider
  ;; adding serialization by default.
  (try "Fundamental idea"
    (let [s (strm/stream)
          xfrm-node (decoder s)
          msg ::message
          msg-frames (io/encode protocol msg)]
      (try
        (is (= 2 (count msg-frames)))
        (doseq [frame msg-frames]
          (strm/put! s frame))
        (let [outcome (strm/try-take! xfrm-node ::drained 40 ::timed-out)]
          (is (= msg (deref outcome 10 ::time-out-2))))
        (finally
          (strm/close! s)))))
  (testing "Wrappers"
    (let [decode-src (strm/stream)
          decode-sink (decoder decode-src)
          msg {::a 1
               ::b 2
               ::c #{3 4 5}}
          frames (io/encode protocol msg)
          binary-frames (reduce (fn [acc frame]
                                  (let [n (- (.limit frame)
                                             (.position frame))
                                        result (byte-array n)]
                                    (.get frame result)
                                    (conj acc result)))
                                []
                                frames)
          log-atom (log/init)
          decoded (map (partial decode-bytes->child
                                decode-src
                                decode-sink
                                log-atom)
                       binary-frames)]
      (try
        (dorun decoded)
        (is (= 2 (count frames)))
        (is (= 2 (count binary-frames)))
        (is (= 2 (count decoded)))
        (is (not (first decoded)))
        ;; Current test implementation hinges on this.
        ;; It doesn't work.
        ;; Just glancing at the gloss source code,
        ;; based on what I know about it, really
        ;; seems as though this should work.
        ;; TODO: Try just using the ByteBuffer.
        ;; Or maybe a ByteBuf?
        (is (= msg (second decoded)))
        (finally
          (strm/close! decode-src)
          (let [logger (log/std-out-log-factory)]
            (log/flush-logs! logger @log-atom)))))))
(comment (check-decoder)
         )

(deftest handshake
  (let [logger (log/std-out-log-factory)
        prelog (utils/pre-log "Handshake test")
        ;; Sticking the logs into an atom like this is tempting
        ;; and convenient.
        ;; But it really misses the point.
        ;; I don't terribly mind doing this for something like a
        ;; unit test. But you very definitely don't want multiple
        ;; threads trying to update a single atom in the middle
        ;; of a tight inner loop.
        ;; (of course, time will tell whether it's wise to do *any*
        ;; logging under those circumstances)
        log-atom (atom (log/info (log/init) ::top-level "Top"))]
    (let [client->server (strm/stream)
          server->client (strm/stream)
          succeeded? (dfrd/deferred)
          ;; Simulate a very stupid FSM
          client-state (atom {::count 0
                              ::prefix nil})
          client-atom (atom nil)
          time-out 500
          client-parent-cb (fn [^bytes bs]
                             (swap! log-atom
                                    log/info
                                    ::client-parent-callback
                                    (str "Sending a " (count bs)
                                         " byte array to client's parent"))
                             ;; With the current implementation, there is no good way
                             ;; to coordinate our lamport clock with the ioloop's.
                             ;; Well, we get the ioloop's when we call get-state.
                             ;; And that clock will pretty much always be ahead
                             ;; of ours.
                             ;; But there's no good way [currently] to go the other
                             ;; direction, if we want to keep everything synchronized.
                             ;; After all, get-state will actually return a clock tick
                             ;; that's quite a bit behind the caller's.
                             (let [sent (strm/try-put! client->server bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          ;; Something that spans multiple packets would be better, but
          ;; that seems like a variation on this test.
          ;; Although this *does* take me back to the beginning, where
          ;; I was trying to figure out ways to gen the tests based upon
          ;; a protocol defined by something like spec.
          ;; Note that doubling this would expand to at least 2 packets,
          ;; since sending a raw byte-buffer really isn't an option.
          ;; And it's silly to pretend that this is a unit test.
          chzbrgr-length 182
          ;; For this implementation, it would make more sense to use
          ;; strm/onto to put this onto an executor. I'm not doing so
          ;; because tracking all the different threads that are involved
          ;; is already annoying, and this test isn't about trying to
          ;; maximize throughput/bandwidth/responsiveness.
          ;; (My first run after switching to this approach stretches
          ;; the callback out to around 23 ms, which is completely unacceptable)
          clnt-decode-src (strm/stream)
          clnt-decode-sink (decoder clnt-decode-src)
          client-child-cb (partial mock-client-child
                                   clnt-decode-src
                                   logger
                                   log-atom)
          server-atom (atom nil)
          server-state-atom (atom {::prefix nil
                                   ::count 0})
          ;; Note that any realistic server would actually need 1
          ;; decoder per connected client.
          ;; Then again, the server really should wind up with 1 messaging
          ;; ioloop per client, so this is more realistic than it might
          ;; seem at first.
          ;; At least, that's really the reference implementation's design.
          srvr-decode-src (strm/stream)
          srvr-decode-sink (decoder srvr-decode-src)
          ;; Important note: In general, clients will not write these.
          ;; These are really hooks for sending the bytes to the encryption
          ;; layer.
          server-parent-cb (fn [bs]
                             (swap! log-atom
                                    log/info
                                    ::server-parent-cb
                                    (str "Sending a " (class bs) " to server's parent"))
                             (let [sent (strm/try-put! server->client bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          server-child-cb (partial mock-server-child
                                   srvr-decode-src
                                   logger
                                   log-atom)]
      (dfrd/on-realized succeeded?
                        (fn [good]
                          (swap! log-atom
                                 log/info
                                 ::child-succeeded
                                 "----------> Test should have passed <-----------"))
                        (fn [bad]
                          (swap! log-atom
                                 log/error
                                 ::child-failed
                                 "High-level test failure"
                                 {::problem bad})
                          (is (not bad))))

      ;; If we use consume-async (which seems preferable), we risk
      ;; race conditions.
      ;; In this particular test, we get the :kk ACK for the chzbrgr
      ;; request and the chzbrgr as a single message block.
      ;; They do get processed separately, but the :kk doesn't have
      ;; time to update the state before the chzbrgr derefs it.
      (strm/consume (partial client-child-processor
                             client-atom
                             client-state
                             log-atom
                             succeeded?
                             chzbrgr-length)
                    clnt-decode-sink)
      (strm/consume (partial server-child-processor
                             server-atom
                             server-state-atom
                             log-atom
                             chzbrgr-length)
                    srvr-decode-sink)

      (let [client-init (message/initial-state "Client" false {} logger)
            client-io (message/start! client-init logger client-parent-cb client-child-cb)
            server-init (message/initial-state "Server" true {} logger)
            ;; It seems like this next part really shouldn't happen until the initial message arrives
            ;; from the client.
            ;; Actually, it starts when the Initiate(?) packet arrives as part of the handshake. So
            ;; that isn't quite true
            server-io (message/start! server-init logger server-parent-cb server-child-cb)]
        (reset! client-atom client-io)
        (reset! server-atom server-io)

        (try
          (strm/consume (partial client->srvr-consumer
                                 server-io
                                 log-atom
                                 time-out
                                 succeeded?)
                        client->server)
          (strm/consume (partial srvr->client-consumer
                                 client-io
                                 log-atom
                                 time-out
                                 succeeded?)
                        server->client)

          (let [initial-message (Unpooled/buffer K/k-1)]
            ;; Kick off the exchange
            (buffer-response! client-io
                              "faux-client"
                              log-atom
                              ::ohai!
                              "Sequence Initiated"
                              "Handshake initiation failed"
                              {})
            ;; TODO: Find a reasonable value for this timeout
            (let [really-succeeded? (deref succeeded? 10000 ::timed-out)]
              (swap! log-atom
                     log/info
                     ::handshake-status-check
                     (str "=====================================================\n"
                          "handshake-test run through. Need to see what happened\n"
                          "====================================================="))
              (let [client-message-state (message/get-state client-io time-out ::timed-out)]
                ;; This seems inside-out.
                ;; TODO: Check really-succeeded? first.
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
              ;; FIXME: This next step is evil, but we deliberately don't have access to the
              ;; details at this level.
              ;; Digging in to get them would be worse.
              ;; Add some sort of hooks (promise/deferred seems like the most
              ;; appropriate choice) to let the io-loop broadcast when a particular
              ;; state has finished.
              ;; Or maybe this is already there.
              ;; TODO: Clean this mess up.
              (Thread/sleep 25)   ; Give the server side a chance to flush
              (let [{:keys [::specs/flow-control]
                     :as srvr-state} (message/get-state server-io time-out ::timed-out)]
                (when (or (= srvr-state ::timed-out)
                          (instance? Throwable srvr-state)
                          (nil? srvr-state))
                  (is (not srvr-state)))
                ;; Keep this around as a reminder to look carefully at it in
                ;; case of wonkiness
                (comment (is (not flow-control) "Server flow-control")))
              (is (= ::kthxbai really-succeeded?))
              (is (= 6 (-> client-state
                           deref
                           ::count)))))
          (finally
            (swap! log-atom
                   log/info
                   ::handshake-status-check
                   "Cleaning up")
            (strm/close! clnt-decode-src)
            (strm/close! srvr-decode-src)
            (try
              (message/halt! client-io)
              (catch Exception ex
                (swap! log-atom
                       log/exception
                       ex
                       ::handshake-status-check
                       "Trying to halt client")))
            (try
              (message/halt! server-io)
              (catch Exception ex
                (swap! log-atom
                       log/exception
                       ex
                       ::handshake-status-check
                       "Trying to halt server")))
            (log/flush-logs! logger @log-atom)))))))
(comment
  (handshake)
  (count (str ::kk))
  (String. (byte-array [0 1 2]))
  )
