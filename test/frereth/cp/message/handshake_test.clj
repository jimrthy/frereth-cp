(ns frereth.cp.message.handshake-test
  "Test basic message exchanges"
  (:require [clojure.edn :as edn]
            [clojure.java.io :as jio]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (are deftest is testing)]
            [frereth.cp.message :as message]
            [frereth.cp.message
             [constants :as K]
             [message-test :as m-t]
             [specs :as specs]]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [util :as utils]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [gloss
             [core :as gloss]
             [io :as io]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import clojure.lang.ExceptionInfo
           io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::count nat-int?)
(s/def ::state (s/keys :req [::count]))
(s/def ::next-object any?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic constants

(def protocol
  (gloss/compile-frame
   (gloss/finite-frame :uint16
                       (gloss/string :utf-8))
   pr-str
   edn/read-string))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helper functions

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
  (swap! log-atom #(log/info % log-ctx "Message over network" {::weald/ctx message-loop-name}))
  (println "DEBUG:" message-loop-name "consumer:" log-ctx)

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
                               #(log/debug %
                                           log-ctx
                                           "Got state"
                                           {::state state
                                            ::parent-context prelog
                                            ::specs/message-loop-name message-loop-name}))
                        (if (or (= ::timed-out state)
                                (instance? Throwable state)
                                (nil? state))
                          (let [problem (if (instance? Throwable state)
                                          state
                                          (ex-info "Non-exception querying for state"
                                                   {::problem state
                                                    ::specs/message-loop-name message-loop-name}))]
                            (is (not problem))
                            (swap! log-atom
                                   #(log/exception %
                                                   problem
                                                   log-ctx
                                                   "Failed!"
                                                   {::triggered-from prelog
                                                    ::specs/message-loop-name message-loop-name}))
                            (if (realized? succeeded?)
                              (swap! log-atom
                                     #(log/warn %
                                                log-ctx
                                                "Caller already thinks we succeeded"
                                                {::triggered-by prelog
                                                 ::specs/message-loop-name message-loop-name}))
                              (dfrd/error! succeeded? problem)))
                          (message/parent->! io-handle bs))))]
    (dfrd/on-realized consumption
                      (fn [success]
                        (swap! log-atom
                               #(log/debug %
                                           log-ctx
                                           "Message successfully consumed"
                                           {::specs/message-loop-name message-loop-name
                                            ::outcome success
                                            ::triggered-from prelog})))
                      (fn [failure]
                        (swap! log-atom
                               #(log/error %
                                           log-ctx
                                           "Failed to consume message"
                                           {::specs/message-loop-name message-loop-name
                                            ::problem failure
                                            ::triggered-from prelog}))))))

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
  (consumer server-io
            log-atom
            ::client->srvr-consumer
            time-out
            succeeded?
            bs))

(defn buffer-response!
  "Serialize and send a message from the child"
  [io-handle
   message-loop-name
   log-atom
   message
   success-message
   error-message
   error-details]
  (println "DEBUG: Serializing and sending a message from" message-loop-name "child")
  (let [frames (io/encode protocol message)
        prelog (utils/pre-log message-loop-name)]
    (swap! log-atom
           #(log/debug %
                       ::buffer-response!
                       "Ready to send message frames"
                       {::weald/ctx message-loop-name
                        ::frame-count (count frames)}))
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
                 #(log/debug %
                             ::buffer-response!
                             "frame sent"
                             {::weald/ctx message-loop-name
                              ::frame-size (count array)})))))))
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
                   (assoc
                    (if-not (keyword? bs)
                      {::message-size (count bs)}
                      {::eof-flag bs})
                    ::weald/ctx "TODO: Which child?"
                    ::specs/bs-or-eof bs))
  (if-not (keyword? bs)
    (do
      (when (= 2 (count bs))
        (swap! log-atom
               log/debug
               ::decode-bytes->child
               (str "This is probably a prefix expecting "
                    (b-t/uint16-unpack bs)
                    " bytes")
               {::weald/ctx "TODO: Which child?"}))
      (let [decoded (strm/try-take! decode-sink ::drained 10 false)]
        (strm/put! decode-src bs)
        (deref decoded 10 false)))
    bs))

(defn server-child-processor
  "Need an extra layer of indirection away from the first-level child mocker"
  ;; Because of the way gloss handles deserialization.
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
         {::weald/ctx "server"
          ::server-state @server-atom
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
           {::weald/ctx "server"
            ::incoming incoming
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
      (swap! log-atom
             log/info
             ::server-child-processor
             "Client requested chzbrgr. Send out of lock-step"
             {::weald/ctx "server"})
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
    (swap! log-atom
           #(log/info %
                      ::client-child-processor
                      "incoming"
                      {::weald/ctx "client"
                       ::client-state client-state
                       ::received incoming}))
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
                         #(log/info %
                                    ::client-child-processor
                                    "Client child callback is drained (but still need server's EOF)"
                                    {::weald/ctx "client"}))
                  (try
                    (message/child-close! @client-atom)
                    (catch RuntimeException ex
                      ;; CIDER doesn't realize that this is a failure.
                      ;; I blame something screwy in the testing
                      ;; harness. I *do* see this error message
                      ;; and the stack trace.
                      (swap! log-atom
                             #(log/exception %
                                             ex
                                             ::client-child-processor
                                             "This really shouldn't pass"
                                             {::weald/ctx "client"}))
                      (is (not ex))))
                  nil)
              5 (do
                  (is (= incoming ::specs/normal))
                  (swap! log-atom
                         #(log/info %
                                    ::client-child-processor
                                    "Received server EOF"
                                    {::weald/ctx "client"}))
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
               #(log/info %
                          ::client-child-processor
                          "response triggered"
                          ;; This approach hides the context that set this
                          ;; up.
                          ;; Then again, that's just the unit test, so it
                          ;; really isn't very interesting
                          {::weald/ctx "client"
                           ::incoming incoming
                           ::next-message next-message}))
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
          (swap! log-atom
                 #(log/debug %
                             ::client-child-processor
                             "returning"
                             {::too-many-attempts? (not result)
                              ::weald/ctx "client"}))
          result))
      (swap! log-atom
             #(log/error %
                         ::client-child-processor
                         "No bytes decoded. Shouldn't have gotten here")))))

(defn child-mocker
  "Functionality shared between client and server"
  [logger log-atom log-ctx arrival-msg decode-src bs-or-kw]
  (swap! log-atom
         #(log/debug %
                     log-ctx
                     (if (keyword? bs-or-kw)
                       (str bs-or-kw)
                       (str (count bs-or-kw) "-byte"))
                     {::message arrival-msg}))
  (if-not (keyword? bs-or-kw)
    (strm/put! decode-src bs-or-kw)
    (doseq [frame (io/encode protocol bs-or-kw)]
      (strm/put! decode-src frame)))
  (swap! log-atom
         #(log/debug %
                     log-ctx
                     "Messages forwarded to decoder"))
  (swap! log-atom #(log/flush-logs! logger %)))

(defn mock-server-child
  "Callback for messages that arrived from client"
  [decode-src logger log-atom bs]
  (child-mocker logger
                log-atom
                ::server-child
                "message arrived at server's child"
                decode-src
                bs))

(defn mock-client-child
  "This is the callback for messages arriving from server"
  [decode-src logger log-atom bs]
  (child-mocker logger
                log-atom
                ::client-child
                "message arrived at client's child"
                ;; This is a strm/source that streams binary
                ;; through the decoder into the real callback
                decode-src
                bs))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(deftest check-decoder
  ;; Tests for checking my testing code seems like a really bad sign.
  ;; Then again, this really is an integration test. It's covering
  ;; a *lot* of functionality.
  ;; And I've made it extra-complicated by refusing to consider
  ;; anything like a default serialization implementation.
  ;; There are plenty of other libraries around for that side
  ;; of things. Using gloss for the test was bad enough.
  ;; Pick your own poison.
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
          log-atom (log/init "Decoder Check" 0)
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
        (is (= msg (second decoded)))
        (finally
          (strm/close! decode-src)
          (let [logger (log/std-out-log-factory)]
            (log/flush-logs! logger @log-atom)))))))
(comment (check-decoder)
         )

(deftest handshake
  (jio/delete-file "/tmp/client.clj" true)
  (jio/delete-file "/tmp/server.clj" true)
  (let [client-logger (log/file-writer-factory "/tmp/client.clj")
        server-logger (log/file-writer-factory "/tmp/server.clj")
        ;; Sticking the logs into an atom like this is tempting
        ;; and convenient.
        ;; But it really misses the point.
        ;; I don't terribly mind doing this for something like a
        ;; unit test. But you very definitely don't want multiple
        ;; threads trying to update a single atom in the middle
        ;; of a tight inner loop.
        ;; (of course, time will tell whether it's wise to do *any*
        ;; logging under those circumstances)
        client-log-atom (atom (log/info (log/init ::client 0) ::top-level "Top"))
        server-log-atom (atom (log/info (log/init ::server 0) ::top-level "Top"))]
    (let [client->server (strm/stream)
          server->client (strm/stream)
          succeeded? (dfrd/deferred)
          ;; Simulate a very stupid FSM
          client-state (atom {::count 0})
          client-atom (atom nil)
          time-out 500
          client-parent-cb (fn [^bytes bs]
                             (swap! client-log-atom
                                    #(log/info %
                                               ::client-parent-callback
                                               (str "Sending a " (count bs)
                                                    " byte array to client's parent")))
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
                                   client-logger
                                   client-log-atom)
          server-atom (atom nil)
          server-state-atom (atom {::count 0})
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
                             (swap! server-log-atom
                                    #(log/info %
                                               ::server-parent-cb
                                               (str "Sending a " (class bs) " to server's parent")))
                             (let [sent (strm/try-put! server->client bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          server-child-cb (partial mock-server-child
                                   srvr-decode-src
                                   server-logger
                                   server-log-atom)]
      (dfrd/on-realized succeeded?
                        (fn [good]
                          (swap! client-log-atom
                                 #(log/info %
                                            ::child-succeeded
                                            "----------> Test should have passed <-----------")))
                        (fn [bad]
                          (swap! client-log-atom
                                 #(log/error %
                                             ::child-failed
                                             "High-level test failure"
                                             {::problem bad}))
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
                             client-log-atom
                             succeeded?
                             chzbrgr-length)
                    clnt-decode-sink)
      (strm/consume (partial server-child-processor
                             server-atom
                             server-state-atom
                             server-log-atom
                             chzbrgr-length)
                    srvr-decode-sink)

      (let [client-init (message/initial-state "Client" false {::weald/state @client-log-atom} client-logger)
            {client-io ::specs/io-handle}  (message/do-start client-init client-logger client-parent-cb client-child-cb)
            server-init (message/initial-state "Server" true {::weald/state @server-log-atom} server-logger)
            ;; It seems like this next part really shouldn't happen until the initial message arrives
            ;; from the client.
            ;; Actually, it starts when the Initiate(?) packet arrives as part of the handshake. So
            ;; that isn't quite true
            {server-io ::specs/io-handle} (message/do-start server-init server-logger server-parent-cb server-child-cb)]
        (reset! client-atom client-io)
        (reset! server-atom server-io)

        (try
          (strm/consume (partial client->srvr-consumer
                                 server-io
                                 server-log-atom
                                 time-out
                                 succeeded?)
                        client->server)
          (strm/consume (partial srvr->client-consumer
                                 client-io
                                 client-log-atom
                                 time-out
                                 succeeded?)
                        server->client)

          (let [initial-message (Unpooled/buffer K/k-1)]
            ;; Kick off the exchange
            (buffer-response! client-io
                              "faux-client"
                              client-log-atom
                              ::ohai!
                              "Sequence Initiated"
                              "Handshake initiation failed"
                              {})
            ;; TODO: Find a reasonable value for this timeout
            (let [really-succeeded? (deref succeeded? 10000 ::timed-out)]
              ;; FIXME: Don't make this ad-hoc. It should be part of the
              ;; public API.
              ;; Just add a notification system so i/o loop creators
              ;; can tell when
              ;; a) their child has sent an EOF and that message has
              ;;    been ACK'd
              ;; b) EOF from the other side reaches our child
              ;; Then again, neither of those seems all that useful.
              ;; The callback handler *knows* when EOF arrives, and
              ;; it can send out any notifications its creator cares
              ;; about, using whichever messaging methodology the
              ;; creator chooses.
              ;; Q: And why do we care when the ACK to our EOF was
              ;; received?
              ;; A: That seems like a pretty important clean-up signal
              (is (not= really-succeeded? ::timed-out))
              (swap! client-log-atom
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
            (swap! client-log-atom
                   log/info
                   ::handshake-status-check
                   "Cleaning up")
            (strm/close! clnt-decode-src)
            (strm/close! srvr-decode-src)
            (try
              (message/halt! client-io)
              (catch Exception ex
                (swap! client-log-atom
                       log/exception
                       ex
                       ::handshake-status-check
                       "Trying to halt client")))
            (try
              (message/halt! server-io)
              (catch Exception ex
                (swap! server-log-atom
                       log/exception
                       ex
                       ::handshake-status-check
                       "Trying to halt server")))
            (log/flush-logs! client-logger @client-log-atom)
            (log/flush-logs! server-logger @server-log-atom)))))))
(comment
  (handshake)
  (count (str ::kk))
  (String. (byte-array [0 1 2]))
  )
