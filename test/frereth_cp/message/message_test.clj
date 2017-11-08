(ns frereth-cp.message.message-test
  (:require [clojure.data]
            [clojure.edn :as edn]
            [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (are deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.from-child :as from-child]
            [frereth-cp.message.from-parent :as from-parent]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-utilities :as test-helpers]
            [frereth-cp.message.to-child :as to-child]
            [frereth-cp.message.to-parent :as to-parent]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import [clojure.lang
            ExceptionInfo
            PersistentQueue]
           [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Helper functions

(defn try-multiple-sends
  [f  ;; Honestly, this is just child->!
   n
   io-handle
   payload
   success-message
   failure-message
   failure-body]
  (loop [m n]
    (if (f io-handle payload)
      (do
        (log/info success-message)
        (log/debug "Took" (- (inc n) m) "attempt(s)"))
      (if (> 0 m)
        (let [failure (ex-info failure-message
                               failure-body)]
          ;; Just make double-extra certain that
          ;; this exception doesn't just disappear
          (log/error failure)
          (throw failure))
        (recur (dec m))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Actual tests
;;; handshake, at least, is bordering on an integration test.
;;; It should probably move somewhere along those lines

(deftest basic-echo
  (let [loop-name "Echo Test"
        src (Unpooled/buffer K/k-1)  ; w/ header, this takes it to the 1088 limit
        msg-len (- K/max-msg-len K/header-length K/min-padding-length)
        ;; Note that this is what the child sender should be supplying
        message-body (byte-array (range msg-len))
        ;; Might as well start with 1, since we're at stream address 0.
        ;; Important note: message-id 0 is reserved for pure ACKs!
        ;; TODO: Play with this and come up with test states that simulate
        ;; dropping into the middle of a conversation
        message-id 1]
    (is (= msg-len K/k-1))
    (.writeBytes src message-body)
    (let [incoming (to-parent/build-message-block-description loop-name
                    {::specs/buf src
                     ::specs/length msg-len
                     ::specs/message-id message-id
                     ::specs/send-eof ::specs/false
                     ::specs/start-pos 0})]
      (is (= K/max-msg-len (count incoming)))
      (let [response (dfrd/deferred)
            parent-state (atom 0)
            parent-cb (fn [buf]
                        (is (s/valid? bytes? buf))
                        (let [response-state @parent-state]
                          (log/debug (utils/pre-log "parent-cb")
                                     "Current response-state: "
                                     response-state
                                     "\nCalled from:\n"
                                     (utils/get-stack-trace (Exception.)))
                          (let [new-state
                                (swap! parent-state inc)]
                            (when (= 2 new-state)
                              (deliver response buf)))))
            ;; I have a circular dependency between
            ;; child-cb and initialized.
            ;; child-cb is getting called inside an
            ;; agent send handler,
            ;; which means I have the agent state
            ;; directly available, but not the actual
            ;; agent.
            ;; That's what it needs, because child->!
            ;; is going to trigger another send.
            ;; Wrapping it inside an atom is obnoxious, but
            ;; it works.
            ;; Don't do anything like this for anything real.
            io-handle-atom (atom nil)
            child-message-counter (atom 0)
            strm-address (atom 0)
            child-cb (fn [array-o-bytes]
                       ;; TODO: Add another similar test that throws an
                       ;; exception here, for the sake of hardening the
                       ;; caller
                       (let [prelog (utils/pre-log "child-cb")]
                         ;; We aren't getting here
                         (log/info prelog "Incoming to child")
                         (is (bytes? array-o-bytes)
                             (str "child-cb Expected a byte-array. Got a "
                                  (class array-o-bytes)))
                         (when array-o-bytes
                           (let [msg-len (count array-o-bytes)
                                 locator (Exception.)]
                             (if (not= 0 msg-len)
                               (do
                                 (log/debug prelog
                                            "Echoing back an incoming message:"
                                            msg-len
                                            "bytes\n"
                                            "Called from:\n"
                                            (utils/get-stack-trace (Exception.)))
                                 (when (not= K/k-1 msg-len)
                                   (log/warn prelog
                                             "Incoming message doesn't match length we sent"
                                             {::expected K/k-1
                                              ::actual msg-len
                                              ::details (vec array-o-bytes)}))
                                 ;; Just echo it directly back.
                                 (let [io-handle @io-handle-atom]
                                   (is io-handle)
                                   (swap! child-message-counter inc)
                                   (swap! strm-address + msg-len)
                                   (try-multiple-sends message/child->!
                                                       5
                                                       io-handle
                                                       array-o-bytes
                                                       (str "Buffered bytes from child")
                                                       "Giving up on buffering bytes from child"
                                                       {})))
                               (log/warn prelog "Empty incoming message. Highly suspicious"))))))
            ;; It's tempting to treat this test as a server.
            ;; Since that's the way it acts: request packets come in and
            ;; trigger responses.
            ;; But the setup is wrong:
            ;; The server shouldn't start until after the first client
            ;; message arrives.
            ;; Maybe it doesn't matter, since I'm trying to send the initial
            ;; message quickly, but the behavior seems suspicious.
            initialized (message/initial-state loop-name {} true)
            io-handle (message/start! initialized  parent-cb child-cb)]
        (try
          (let [state (message/get-state io-handle 500 ::timed-out)]
            (is (not= state ::timed-out))
            (when (not= state ::timed-out)
              (reset! io-handle-atom io-handle)
              (is (not
                   (s/explain-data ::specs/state state)))

              ;; TODO: Add similar tests that send a variety of
              ;; gibberish messages
              (let [wrote (dfrd/future
                            (log/debug loop-name "Writing message from parent")
                            (message/parent->! io-handle incoming)
                            (log/debug "Message should be headed to child"))
                    outcome (deref response 1000 ::timeout)]
                (if (= outcome ::timeout)
                  (do
                    (log/warn "Parent never got message from child")
                    (is (not= outcome ::timeout)))
                  (do
                    (is (= 2 @parent-state))
                    ;; I'm getting the response message header here, which is
                    ;; correct, even though it seems wrong.
                    ;; In the real thing, these are the bytes I'm getting ready
                    ;; to send over the wire
                    (is (= (count outcome) (+ msg-len K/header-length K/min-padding-length)))
                    (let [without-header (byte-array (drop (+ K/header-length K/min-padding-length)
                                                           (vec outcome)))]
                      (is (= (count message-body) (count without-header)))
                      (is (b-t/bytes= message-body without-header)))))
                (is (realized? wrote) "Initial write from parent hasn't returned yet.")
                (let [state (message/get-state io-handle 500 ::time-out)]
                  (is (not= state ::timeout))
                  (when (not= state ::timeout)
                    (is (not
                         (s/explain-data ::specs/state state)))
                    (log/info "Checking test outcome")

                    (let [{:keys [::specs/incoming
                                  ::specs/outgoing]} state]
                      (is incoming)
                      (is (= msg-len (inc (::specs/strm-hwm incoming))))
                      (is (= msg-len (::specs/contiguous-stream-count incoming)))
                      (is (= (inc (::specs/strm-hwm incoming))
                             (::specs/contiguous-stream-count incoming)))
                      (is (= 2 (::specs/next-message-id outgoing)))
                      ;; Still have the message buffered.
                      (is (= msg-len (from-child/buffer-size outgoing)))
                      (is (= 0 (count (::specs/un-sent-blocks outgoing))))
                      (is (= 1 (count (::specs/un-ackd-blocks outgoing))))
                      (is (= ::specs/false (::specs/send-eof outgoing)))
                      (is (= msg-len (::specs/strm-hwm outgoing)))
                      ;; Keeping around as a reminder for when the implementation changes
                      ;; and I need to see what's really going on again
                      (comment (is (not outcome) "What should we have here?"))))))))
          (catch ExceptionInfo ex
            (log/error loop-name ex "Starting the event loop"))
          (finally
            (message/halt! io-handle)))))))
(comment (basic-echo))

(deftest check-eof
  ;; TODO: Add a close! method to the message ns that triggers this
  (throw (RuntimeException. "Need to decide how this should work")))

(deftest send-error-code
  (throw (RuntimeException. "Need to decide how this should work")))

(deftest verify-empty-message-arrives
  ;; If other side deliberately sends an empty message block, we
  ;; *want* the child to be notified about that.
  ;; It seems nonsensical, since it doesn't update the stream address.
  ;; But this is one complaint I've read about the reference implementation:
  ;; Some protocols are simple enough that they rely on empty messages
  ;; for heartbeats.
  (throw (RuntimeException. "Write this")))

(deftest wrap-chzbrgr
  ;; handshake test fails due to problems in this vicinity when it tries to
  #_(message/child->! @server-atom (byte-array (range cheezburgr-length)))
  (let [message-loop-name "Building chzbrgr"
        start-state {::specs/message-loop-name message-loop-name
                     ::specs/outgoing {::specs/max-block-length K/standard-max-block-length
                                       ::specs/ackd-addr 0
                                       ::specs/strm-hwm 0
                                       ::specs/un-sent-blocks PersistentQueue/EMPTY}
                     ::specs/recent (System/nanoTime)}
        ;; TODO: Keep this magic number in sync
        ;; And verify the action with sizes that cross packet boundaries
        chzbrgr-lngth 182
        chzbrgr (byte-array (range chzbrgr-lngth))
        _ (log/info "Reading chzbrgr from child")
        ;; This is much slower than I'd like
        {:keys [::specs/outgoing
                ::specs/recent]
         :as state'} (time (from-child/consume-from-child start-state chzbrgr))]
    (is (= 1 (count (::specs/un-sent-blocks outgoing))))
    (is (= chzbrgr-lngth (::specs/strm-hwm outgoing)))
    (let [current-message  (-> outgoing
                      ::specs/un-sent-blocks
                      first)
          out-buf (::specs/buf current-message)]
      (is (b-t/bytes= (.array out-buf) chzbrgr))
      (let [read-index (.readerIndex out-buf)
            write-index (.writerIndex out-buf)
            current-message-id 1
            updated-message (-> current-message
                                (update ::specs/transmissions inc)
                                (assoc ::specs/time recent)
                                (assoc ::specs/message-id current-message-id))
            _ (log/info "Building message block to send to parent")
            buf (time (to-parent/build-message-block-description message-loop-name
                                                                 updated-message))]
        ;;; Start with the very basics
        ;; Q: Did that return what we expected?
        (is (s/valid? bytes? buf))
        (is (= 320 (count buf)))
        ;; Q: Did it mutate the its argument?
        (is (b-t/bytes= (.array out-buf) chzbrgr))
        (is (= read-index (.readerIndex out-buf)))
        (is (= write-index (.writerIndex out-buf)))
        ;; Now, what does the decoded version look like?
        ;; TODO: This is another piece that's just
        ;; screaming for generative testing
        (log/info "Deserializing message from parent")
        (let [{:keys [::specs/acked-message
                      ::specs/ack-length-1
                      ::specs/ack-length-2
                      ::specs/ack-length-3
                      ::specs/ack-length-4
                      ::specs/ack-length-5
                      ::specs/ack-length-6
                      ::specs/ack-gap-1->2
                      ::specs/ack-gap-2->3
                      ::specs/ack-gap-3->4
                      ::specs/ack-gap-4->5
                      ::specs/ack-gap-5->6
                      ::specs/buf
                      ::specs/message-id
                      ::specs/size-and-flags]
               :as packet} (time (from-parent/deserialize message-loop-name buf))]
          (comment (is (not packet)))
          (is (= chzbrgr-lngth size-and-flags))
          (are [expected actual] (= expected actual)
            0 acked-message
            0 ack-length-1
            0 ack-length-2
            0 ack-length-3
            0 ack-length-4
            0 ack-length-5
            0 ack-length-6
            0 ack-gap-1->2
            0 ack-gap-2->3
            0 ack-gap-3->4
            0 ack-gap-4->5
            0 ack-gap-5->6)
          (is (= message-id current-message-id))
          (let [bytes-rcvd (.readableBytes buf)
                dst (byte-array bytes-rcvd)]
            (is (= chzbrgr-lngth bytes-rcvd))
            (.readBytes buf dst)
            (log/info "Comparing byte arrays")
            (is (time (b-t/bytes= chzbrgr dst)))))))))

(deftest handshake
  ;; The stop values going back to to-child/consolidate-message-block
  ;; are gibberish. This probably ties in with my failures to cope with
  ;; ::ackd-addr.
  ;; This definitely seems to tie in with message.helpers, when it receives
  ;; ACKs in gap buffers
  ;; TODO: Need to address that.
  (log/info (utils/pre-log "Handshake test")
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
                                incoming (edn/read-string s)]
                            (is (< 0 (count s)))
                            (is incoming)
                            ;; We're receiving the initial ::orly? response in State 0.
                            ;; The ::yarly disappears
                            ;; FIXME: Where?
                            (log/info (str "Client (state "
                                           @client-state
                                           ") received: "
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
                                        ;; This is the ACK associated
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
                                          ;; This fails because I haven't really
                                          ;; decided how I want to handle EOF.
                                          (message/close! @client-atom)
                                          (catch RuntimeException ex
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
                                  (try-multiple-sends message/child->!
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
                                        ::kthxbai ::kk)]
                            (log/info prelog
                                      "Server received"
                                      incoming
                                      "\nwhich triggers"
                                      rsp)
                            (let [actual (.getBytes (pr-str rsp))]
                              (try-multiple-sends message/child->!
                                                  5
                                                  @server-atom
                                                  actual
                                                  "Message buffered to child"
                                                  "Giving up on forwarding to child"
                                                  {::response rsp
                                                   ::request incoming}))
                            (when (= incoming ::icanhazchzbrgr?)
                              ;; One of the main points is that this doesn't need to be a lock-step
                              ;; request/response.
                              (log/info prelog "Client requested chzbrgr. Send out of lock-step")
                              (let [chzbrgr (byte-array (range cheezburgr-length))]
                                (try-multiple-sends message/child->!
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
        (strm/consume (fn [bs]
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
                          ;; Q: But is it worth it for the test's sake?
                          ;; A: Well, now that the RTT adjustments are taking effect,
                          ;; I'm hitting the deadlocks I expected.
                          ;; I *think* the problem is this sequence:
                          ;; 1. the event loop triggers this
                          ;; 2. this sends a get-state request
                          ;; 3. that request can never succeed, because it's waiting
                          ;; for this thread to return to start handling those sorts
                          ;; of requests again.
                          ;; It seems a little strange that adding RTT adjustments would
                          ;; bring this problem to light.
                          ;; But, honestly, it seems more strange that it ever worked.

                          ;; The obvious solution starts with what the library client
                          ;; should do here: get the callback and push the incoming
                          ;; message onto another queue to deal with later.

                          ;; But, honestly, it would be easier for the library to
                          ;; do that.
                          ;; Not necessarily better, since callers *could* handle
                          ;; things more directly here. But it's very tempting.

                          ;; And yet...how did this approach ever work?

                          ;; Actually, it's probably worth keeping in mind that
                          ;; *this* approach never did.

                          ;; An approach with the same basic code, built around agents,
                          ;; never did either. It just failed in different ways that
                          ;; drove me to switch to this Actor-based approach.
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
                      client->server)
        (strm/consume (fn [bs]
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
                      server->client)

        (let [initial-message (Unpooled/buffer K/k-1)
              helo (.getBytes (pr-str ::ohai!))]
          ;; Kick off the exchange
          (try-multiple-sends message/child->!
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
              (log/error ex "Trying to halt server"))))))))
(comment (handshake))

(deftest check-initial-state-override
  (let [opts {::specs/outgoing {::specs/pipe-from-child-size K/k-1}
              ::specs/incoming {::specs/pipe-to-child-size K/k-4}}
        start-state (message/initial-state "Overflowing Test" true opts)]
    (is (= K/k-1 (get-in start-state [::specs/outgoing ::specs/pipe-from-child-size])))
    (is (= K/k-4 (get-in start-state [::specs/incoming ::specs/pipe-to-child-size])))))

(deftest overflow-from-child
  ;; If the child sends bytes faster than we can
  ;; buffer/send, we need a way to signal back-pressure.
  (let [opts {::specs/outgoing {::specs/pipe-from-child-size K/k-1}}
        start-state (message/initial-state "Overflowing Test" true opts)
        parent-cb (fn [out]
                    (log/warn "parent-cb called with"
                              (count out) bytes)
                    (is (not out) "Should never get called"))
        rcvd (atom [])
        child-cb (fn [in]
                   (log/info "child-cb received" in)
                   (swap! rcvd conj in))
        event-loop (message/start! start-state
                                   parent-cb
                                   child-cb)]
    (is (= K/k-1 (get-in start-state [::specs/outgoing ::specs/pipe-from-child-size])))
    (is (= K/k-1 (::specs/pipe-from-child-size event-loop)))
    (is (= 0 (.available (::specs/child-out event-loop))))
    (try
      ;; Start by trying to send a buffer that's just flat-out too big
      (is (not (message/child->! event-loop (byte-array K/k-4))))
      ;; TODO: Send messages that are just long enough as fast as possible
      ;; until one fails because it would have blocked.
      ;; Then wait a bit and try again, with smaller block sizes
      ;; Actually, don't do that here. The test is probably interesting
      ;; for metrics, but it really needs a pair of i/o loops.
      ;; And, really, it gets much more interesting when you add
      ;; crypto to the mix.
      (finally
        ;; This is premature. Honestly, I need to call close! first,
        ;; give the loop a chance to send out its EOF signal, and then
        ;; kill it.
        ;; It doesn't matter as much here as it does for the handshake
        ;; test (since there's no "other side" loop to ACK the EOF, but
        ;; it's worth doing if only to demonstrate the basic
        ;; point.
        (message/halt! event-loop)))))

(deftest bigger-outbound
  ;; Flip-side of echo: I want to see what happens
  ;; when the child sends bytes that don't fit into
  ;; a single message packet.
  (let [test-run (gensym)
        prelog (utils/pre-log test-run)]
    (log/info prelog "Start testing writing big chunk of outbound data")
    ;; TODO: split this into 2 tests
    ;; 1 should stall out like the current implementation,
    ;; waiting for ACKs (maybe drop every other packet?
    ;; maybe send ACKs out of order?)
    ;; The other should just send ACKs to get this working
    ;; the way it did originally again
    ;; TODO: Figure out a nice way to streamline the
    ;; component setup without bringing in another 3rd
    ;; party library
    (let [start-time (System/nanoTime)
          packet-count 9  ; trying to make life interesting
          ;; Add an extra quarter-K just for giggles
          msg-len (+ (* (dec packet-count) K/k-div2) K/k-div4)
          response (promise)
          srvr-child-state (atom {:count 0
                                  :buffer []})
          ;; I have a circular dependency between
          ;; the client's child-cb, server-parent-cb,
          ;; and initialized.
          ;; The callbacks get called inside an
          ;; agent send handler,
          ;; which means I have the agent state
          ;; directly available, but not the actual
          ;; agent.
          ;; That's what it needs, because child->!
          ;; is going to trigger another send.
          ;; Wrapping it inside an atom is obnoxious, but
          ;; it works.
          ;; Don't do anything like this for anything real.
          client-io-atom (atom nil)
          server-parent-cb (fn [bs]
                             ;; TODO: Add a test that buffers these
                             ;; up and then sends them
                             ;; all at once
                             (log/info (utils/pre-log test-run)
                                       "Message from server to client."
                                       "\nThis really should just be an ACK")
                             (message/parent->! @client-io-atom bs))
          server-child-cb (fn [incoming]
                            (let [prelog (utils/pre-log test-run)]
                              (log/info prelog "Incoming to server's child")

                              ;; Q: Which version better depicts how the reference implementation works?
                              ;; Better Q: Which approach makes more sense?
                              ;; (Seems obvious...don't want to waste bandwidth if it's just going
                              ;; to a broken router that will never deliver. But there's a lot of
                              ;; experience behind this sort of thing, and it would be a terrible
                              ;; mistake to ignore that accumulated wisdom)

                              ;; That comment above is fairly rotten.
                              ;; I think it stemmed from my scheduling algorithm
                              ;; going off the rails and trying to send messages as fast as possible,
                              ;; under some circumstances.
                              ;; TODO: Check out the history, make sure this comment is
                              ;; in the correct vicinity, and then hopefully delete them both.

                              (let [response-state @srvr-child-state]
                                (if (keyword? incoming)
                                  (do
                                    (is (s/valid? ::specs/eof-flag incoming))
                                    (message/close! nil))
                                  (log/debug (str test-run
                                                  "::server-child-cb ("
                                                  (count incoming)
                                                  " bytes): "
                                                  (-> response-state
                                                      (dissoc :buffer)
                                                      (assoc :buffer-size (count (:buffer response-state)))))))
                                ;; The first few blocks should max out the message size.
                                ;; The way the test is set up, the last will be
                                ;; (+ 512 64).
                                ;; It doesn't seem worth the hoops it would take to validate that.
                                (swap! srvr-child-state
                                       (fn [cur]
                                         (log/info prelog "Incrementing state count")
                                         (-> cur
                                             (update :count inc)
                                             ;; Seems a little silly to include the ACKs.
                                             ;; Should probably think this through more thoroughly
                                             (update :buffer conj (vec incoming)))))
                                ;; I would like to get 8 callbacks here:
                                ;; 1 for each message packet the child tries to send.
                                ;; I'm actually receiving 6:
                                ;; 4 1K blocks, 256 bytes, and an EOF indicator.
                                ;; It seems like this almost definitely involves
                                ;; PipedStream buffering.
                                ;; TODO: Need to double-check that and consider
                                ;; very diligently what I think about it.
                                ;; (At first glance, it seems totally incorrect).
                                (when (= packet-count (:count @srvr-child-state))
                                  (log/info prelog
                                            "::srvr-child-cb Received all expected packets")
                                  (deliver response @srvr-child-state)))))
          srvr-initialized (message/initial-state (str "(test " test-run ") Server w/ Big Inbound")
                                                  true
                                                  {})
          srvr-io-handle (message/start! srvr-initialized server-parent-cb server-child-cb)

          parent-cb (fn [bs]
                      (log/info (utils/pre-log test-run) "Forwarding buffer to server")
                      ;; This approach is over-simplified for the sake
                      ;; of testing.
                      ;; In reality, we need to pull off this queue as
                      ;; fast as possible.
                      ;; And, realistically, push the message onto another
                      ;; queue that handles all the details like encrypting
                      ;; and actually writing bytes to the wire.
                      (message/parent->! srvr-io-handle bs))
          child-message-counter (atom 0)
          strm-address (atom 0)
          child-cb (fn [bs]
                     ;; This is for messages from elsewhere to the child.
                     ;; This test is all about the child spewing "lots" of data
                     ;; TODO: Honestly, need a test that really does just start off by
                     ;; sending megabytes (or gigabytes) of data as soon as the connection
                     ;; is warmed up.
                     ;; Library should be robust enough to handle that failure.
                     ;; Q: (which failure? feature?)
                     (is (not bs) "This should never get called"))
          client-initialized (message/initial-state (str "(test " test-run ") Client w/ Big Outbound")
                                                    false
                                                    {})
          client-io-handle (message/start! client-initialized parent-cb child-cb)]
      (reset! client-io-atom client-io-handle)
      (try
        (let [;; Note that this is what the child sender should be supplying
              message-body (byte-array (range msg-len))]
          (log/debug prelog "Replicating child-send to " client-io-handle)
          (try-multiple-sends message/child->!
                              5
                              client-io-handle
                              message-body
                              (str "Buffered "
                                   msg-len
                                   " bytes to child")
                              "Buffering big message from child failed"
                              {::buffer-size msg-len})
          (message/close! client-io-handle ::indicate-child-done)
          (let [outcome (deref response 10000 ::timeout)
                end-time (System/nanoTime)]
            (log/info prelog
                      "Verifying that state hasn't errored out after"
                      (float (utils/nanos->millis (- end-time start-time))) "milliseconds")
            ;; Q: Can I do anything better in terms of checking for errors?
            (let [client-state (message/get-state client-io-handle 500 ::timeout)]
              (is outcome)
              (is (not= ::timeout outcome))
              (when (not= ::timeout outcome)
                (is (not (instance? Exception outcome)))
                (when-not (= outcome ::timeout)
                  (let [result-buffer (:buffer outcome)]
                    (is (= packet-count (count result-buffer)))
                    (is (= K/initial-max-block-length (count (first result-buffer))))
                    (doseq [packet (butlast result-buffer)]
                      (is (= (count packet) K/k-div2)))
                    (let [final (last result-buffer)]
                      (is (= (count final) K/k-div4)))
                    (let [rcvd-strm
                          (reduce (fn [acc block]
                                    (conj acc block))
                                  []
                                  result-buffer)]
                      (is (b-t/bytes= (->> rcvd-strm
                                           first
                                           byte-array)
                                      (->> message-body
                                           vec
                                           (take K/initial-max-block-length)
                                           byte-array))))))))))
        (let [{:keys [::specs/incoming
                      ::specs/outgoing]
               :as outcome} (message/get-state client-io-handle 500 ::time-out)]
          (is (not= outcome ::time-out))
          (when (not= outcome ::time-out)
            (is outgoing)
            (is (= msg-len (::specs/ackd-addr outgoing)))
            (let [n-m-id (::specs/next-message-id outgoing)]
              (is (= (inc packet-count) n-m-id)))
            (is (= 0 (from-child/buffer-size outcome)))
            ;; TODO: I do need a test that triggers EOF
            (is (= ::specs/false (::specs/send-eof outgoing)))
            ;; Keeping around as a reminder for when the implementation changes
            ;; and I need to see what's really going on again
            (comment (is (not outcome) "What should we have here?"))))
      (finally
          (log/info "Ending test" prelog)
          (try
            (message/halt! client-io-handle)
            (catch RuntimeException ex
              (is not ex)))
          (try
            (message/halt! srvr-io-handle)
            (catch RuntimeException ex
              (is not ex))))))))
(comment (bigger-echo))

(deftest smarter-overflowing
  ;; Should be a smarter version of bigger-echo
  ;; I want to try keeping the child's outbound pipe
  ;; saturated.
  ;; To do this well, I really need it to provide status
  ;; notifications when write space becomes available.
  ;; Or just take the easy approach (which would generally
  ;; perform better for most use cases) and provide an
  ;; optional parameter to child-> to allow the write to
  ;; block.
  ;; Both options are better than what I have now, which
  ;; amounts to polling for the state until some space
  ;; opens up, then hoping some other thread doesn't
  ;; write that first.
  ;; Another option comes to mind:
  ;; Switch to returning the available buffer size on
  ;; failure, and false on success
  (throw (RuntimeException. "Implement this")))

(comment
  (deftest parallel-parent-test
    (testing "parent->! should be thread-safe"
      ;; This seems dubious.
      ;; Q: What's the real use case?
      ;; A: Well, we certainly could have multiple
      ;; socket listening threads that get a bunch
      ;; of message packets from the client at the
      ;; same time.
      ;; Q: Can we?
      ;; TODO: this needs more investigation.
      (is false "Write this")))

  (deftest parallel-child-test
    (testing "child->! should be thread-safe"
      ;; It seems scary, but it's actually an important
      ;; part of allowing the child to buffer up bytes
      ;; bigger than we can handle all at once.
      ;; Maybe 1 thread sends a big EDN structure, while
      ;; another sends a big chunk of transit, and a
      ;; third starts uploading chunks of images.
      ;; The other side will have to sort out the
      ;; stream on its own, but we have to maintain
      ;; the byte ordering
      (is false "Write this")))

  (deftest simulate-dropped-acks
    ;; When other side fails to respond "quickly enough",
    ;; should re-send message blocks
    ;; This adds an entirely new wrinkle (event scheduling)
    ;; to the mix
    (is false "Write this")))

(comment
  (deftest piping-io
    ;; This was an experiment that failed.
    ;; Keeping it around as a reminder of why it didn't work.
    (let [in-pipe (java.io.PipedInputStream. K/send-byte-buf-size)
          out-pipe (java.io.PipedOutputStream. in-pipe)]
      (testing "Overflow"
        (let [too-big (+ K/k-128 K/k-8)
              src (byte-array (range too-big))
              dst (byte-array (range too-big))]
          (is (= 0 (.available in-pipe)))
          (let [fut (future (.write out-pipe src)
                            (println "Bytes written")
                            ::written)]
            (is (= K/k-128 (.available in-pipe)))
            (is (= K/k-8 (.read in-pipe dst 0 K/k-8)))
            (is (= (- K/k-128 K/k-8) (.available in-pipe)))
            (is (= (- K/k-128 K/k-8) (.read in-pipe dst 0 K/k-128)))
            (println "Read 128K")
            ;; It looks like these extra 8K bytes just silently disappear.
            ;; That's no good.
            (Thread/sleep 0.5)
            ;; Actually, they didn't disappear.
            ;; I just don't have any good way to tell that they're
            ;; available.
            (is (not= K/k-8 (.available in-pipe)))
            ;; Q: Is this a deal-killer?
            ;; A: Yes.
            (println "Trying to read 1K more")
            (let [remaining-read (.read in-pipe dst 0 K/k-1)]
              (println "Read" remaining-read "bytes")
              (is (= K/k-1 remaining-read)))
            (is (= (* 7 K/k-1) (.available in-pipe)))
            (is (= (* 7 K/k-1) (.read in-pipe dst 0 K/k-16)))
            (is (realized? fut))
            (is (= ::written (deref fut 500 ::timed-out)))))))))
