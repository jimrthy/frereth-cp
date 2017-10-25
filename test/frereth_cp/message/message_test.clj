(ns frereth-cp.message.message-test
  (:require [clojure.data]
            [clojure.edn :as edn]
            [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.from-child :as from-child]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-utilities :as test-helpers]
            [frereth-cp.message.to-parent :as to-parent]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           [io.netty.buffer ByteBuf Unpooled]))

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
                    message-id
                    {::specs/buf src
                     ::specs/length msg-len
                     ::specs/send-eof ::specs/false
                     ::specs/start-pos 0})]
      (is (= K/max-msg-len (count incoming)))
      (let [response (promise)
            parent-state (atom 0)
            parent-cb (fn [buf]
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
                       (is (bytes? array-o-bytes)
                           (str "child-cb Expected a byte-array. Got a "
                                (class array-o-bytes)))
                       (when array-o-bytes
                         (let [msg-len (count array-o-bytes)
                               prelog (utils/pre-log "child-cb")
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
                                 (message/child->! io-handle array-o-bytes)))
                             (log/warn prelog "Empty incoming message. Highly suspicious")))))
            ;; It's tempting to treat this test as a server.
            ;; Since that's the way it acts: request packets come in and
            ;; trigger responses.
            ;; But the setup is wrong:
            ;; The server shouldn't start until after the first client
            ;; message arrives.
            ;; Maybe it doesn't matter, since I'm trying to send the initial
            ;; message quickly, but the behavior seems suspicious.
            initialized (message/initial-state loop-name true)
            io-handle (message/start! initialized  parent-cb child-cb)]
        (try
          (let [state (message/get-state io-handle)]
            (is (not= state ::timed-out))
            (when (not= state ::timed-out)
              (reset! io-handle-atom io-handle)
              (is (not
                   (s/explain-data ::specs/state state)))

              ;; TODO: Add similar tests that send a variety of
              ;; gibberish messages
              (let [wrote (dfrd/future (message/parent->! io-handle incoming))
                    outcome (deref response 1000 ::timeout)]
                (is (not= outcome ::timeout))
                (when-not (= outcome ::timeout)
                  (is (= 2 @parent-state))
                  ;; I'm getting the response message header here, which is
                  ;; correct, even though it seems wrong.
                  ;; In the real thing, these are the bytes I'm getting ready
                  ;; to send over the wire
                  (is (= (count outcome) (+ msg-len K/header-length K/min-padding-length)))
                  (let [without-header (byte-array (drop (+ K/header-length K/min-padding-length)
                                                         (vec outcome)))]
                    (is (= (count message-body) (count without-header)))
                    (is (b-t/bytes= message-body without-header))))
                (is (realized? wrote) "Initial write from parent hasn't returned yet.")
                (let [state (message/get-state io-handle ::time-out)]
                  (is (not= state ::timeout))
                  (when (not= state ::timeout)
                    ;; This test fails because
                    ;; (get-in state [::specs/outgoing ::specs/send-buf])
                    ;; is either a byte-array (seems likely) or a vector.
                    ;; According to spec, it must be a ByteBuf.
                    ;; Honestly, I'm mixing 2 different abstraction layers,
                    ;; because they happen to represent the same thing.
                    ;; FIXME: Start back here.
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

(deftest handshake
  (let [client->server (strm/stream)
        server->client (strm/stream)
        succeeded? (dfrd/deferred)
        ;; Simulate a very stupid FSM
        client-state (atom 0)
        client-atom (atom nil)
        client-parent-cb (fn [bs]
                           (log/info "Sending a" (class bs) "to client's parent")
                           (let [sent (strm/try-put! client->server bs 500 ::timed-out)]
                             (is (not= @sent ::timed-out))))
        ;; Something that spans multiple packets would be better, but
        ;; that seems like a variation on this test.
        ;; Although this *does* take me back to the beginning, where
        ;; I was trying to figure out ways to gen the tests via spec.
        cheezburgr-length 182
        client-child-cb (fn [bs]
                          (is bs)
                          (let [s (String. bs)
                                incoming (edn/read-string s)]
                            (is (< 0 (count s)))
                            (is incoming)
                            ;; We're receiving the initial ::orly? response in State 0.
                            ;; The ::yarly disappears
                            ;; FIXME: Where
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
                                        ::icanhazchbrgr?)
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
                                        ;; Time to signal EOF.
                                        (message/close! @client-atom)
                                        (dfrd/success! succeeded? ::kthxbai)
                                        nil))]
                              (swap! client-state inc)
                              ;; Hmm...I've wound up with a circular dependency again.
                              ;; Q: Is this a problem with my architecture, or just
                              ;; a testing artifact?
                              (when next-message
                                (message/child->! @client-atom (.getBytes (pr-str next-message)))))))

        server-atom (atom nil)
        server-parent-cb (fn [bs]
                           (log/info "Sending a" (class bs) "to server's parent")
                           (let [sent (strm/try-put! server->client bs 500 ::timed-out)]
                             (is (not= @sent ::timed-out))))
        server-child-cb (fn [bs]
                          (let [incoming (edn/read-string (String. bs))
                                ;; Latest test is failing here, on ::yarly.
                                ;; Wut?
                                ;; I'm receiving
                                ;; "frereth-cp.message.message-test/yarly"
                                ;; rather than
                                ;; ":frereth-cp.message.message-test/yarly"
                                ;; due to an off-by-1 error.
                                #_(comment (throw (RuntimeException. "Start back here")))
                                _ (log/debug (str "Matching '" incoming
                                                  "', a " (class incoming)) )
                                rsp (condp = incoming
                                        ::ohai! ::orly?
                                        ::yarly ::kk
                                        ::icanhazchbrgr? ::kk
                                        ::kthxbai ::kk)]
                            (log/info "Server received"
                                      incoming
                                      "\nwhich triggers"
                                      rsp)
                            (message/child->! @server-atom (.getBytes (pr-str rsp)))
                            (when (= incoming ::icanhazchzbrgr?)
                              ;; One of the main points is that this doesn't need to be a lock-step
                              ;; request/response.
                              (message/child->! @server-atom (byte-array (range cheezburgr-length))))))]
    (dfrd/on-realized succeeded?
                      (fn [good]
                        (log/info "Success!"))
                      (fn [bad] (is (not bad))))

    (reset! client-atom (message/initial-state "Client" client-parent-cb client-child-cb false))
    (message/start! @client-atom)

    ;; It seems like this next part really shouldn't happen until the initial message arrives
    ;; from the client.
    ;; Actually, it starts when the Initiate(?) packet arrives as part of the handshake. So
    ;; that isn't quite true
    (reset! server-atom (message/initial-state "Server" server-parent-cb server-child-cb true))
    (message/start! @server-atom)

    (try
      (strm/consume (fn [bs]
                      (log/info "Message from client to server")
                      (let [srvr-agent @server-atom]
                        (if-let [err (agent-error srvr-agent)]
                          (do
                            (log/error "Server failed!")
                            (dfrd/error! succeeded? err))
                          (message/parent->! srvr-agent bs))))
                    client->server)
      (strm/consume (fn [bs]
                      (log/info "Message from server to client")
                      (let [client-agent @client-atom]
                        (if-let [err (agent-error client-agent)]
                          (do
                            (log/error "Client failed!")
                            (dfrd/error! succeeded? err))
                          (message/parent->! client-agent bs))))
                    server->client)

      (let [initial-message (Unpooled/buffer K/k-1)
            helo (.getBytes (pr-str ::ohai!))]
        ;; Kick off the exchange
        (message/child->! @client-atom helo)
        ;; TODO: Find a reasonable value for this timeout
        (let [really-succeeded? (deref succeeded? 10000 ::timed-out)]
          (log/info "Bottom of message-test")
          (is (not (agent-error @client-atom)))
          (is (not (agent-error @server-atom)))
          (when (= really-succeeded? ::timed-out)
            ;; Double deref to get to the agent state.
            (let [{:keys [::specs/flow-control]
                   :as client-state} @(deref client-atom)]
              ;; I'm mostly interested in the next-action inside flow-control
              ;; Down-side to switching to manifold for scheduling:
              ;; I don't really have any insight into what's going on
              ;; here.
              ;; Q: Is that true? Or have I just not studied its
              ;; docs thoroughly enough?
              (is (not flow-control))))
          (is (= ::kthxbai really-succeeded?))
          (is (= 5 @client-state))))
      (finally
        (log/info "Cleaning up")
        (message/halt! @client-atom)
        (message/halt! @server-atom)))))
(comment (handshake))

(deftest overflow-from-child
  ;; If the child sends bytes faster than we can
  ;; buffer/send, we need a way to signal back-pressure.
  (throw (RuntimeException. "Not Implemented")))

(deftest bigger-outbound
  ;; Flip-side of echo: I want to see what happens
  ;; when the child sends bytes that don't fit into
  ;; a single message packet.
  (let [test-run (gensym)]
    (log/info test-run "Start testing writing big chunk of outbound data")
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
          state-agent-atom (atom nil)
          server-parent-cb (fn [bs]
                             ;; TODO: Add a test that buffers these
                             ;; up and then sends them
                             ;; all at once
                             (log/info test-run
                                       "Message from server to client."
                                       "\nThis really should just be an ACK")
                             (message/parent->! @state-agent-atom bs))
          server-child-cb (fn [incoming]
                            (log/info test-run "Incoming to server's child")

                            ;; Q: Which version better depicts how the reference implementation works?
                            ;; Better Q: Which approach makes more sense?
                            ;; (Seems obvious...don't want to waste bandwidth if it's just going
                            ;; to a broken router that will never deliver. But there's a lot of
                            ;; experience behind this sort of thing, and it would be a terrible
                            ;; mistake to ignore that accumulated wisdom)


                            (let [response-state @srvr-child-state]
                              (log/debug (str test-run
                                              "::server-child-cb ("
                                              (count incoming)
                                              " bytes): "
                                              (-> response-state
                                                  (dissoc :buffer)
                                                  (assoc :buffer-size (count (:buffer response-state))))))
                              ;; The first few blocks should max out the message size.
                              ;; The way the test is set up, the last will be
                              ;; (+ 512 64).
                              ;; It doesn't seem worth the hoops it would take to validate that.
                              (swap! srvr-child-state
                                     (fn [cur]
                                       (log/info test-run "Incrementing state count")
                                       (-> cur
                                           (update :count inc)
                                           ;; Seems a little silly to include the ACKs.
                                           ;; Should probably think this through more thoroughly
                                           (update :buffer conj (vec incoming)))))
                              ;; I would like to get 8 callbacks here:
                              ;; 1 for each kilobyte of message the child tries to send.
                              (when (= packet-count (:count @srvr-child-state))
                                (log/info (str test-run "::srvr-child-cb Received all expected packets"))
                                (deliver response @srvr-child-state))))
          srvr-initialized (message/initial-state (str "(test " test-run ") Server w/ Big Inbound")
                                                  server-parent-cb
                                                  server-child-cb
                                                  true)
          srvr-state (message/start! srvr-initialized)

          parent-cb (fn [bs]
                      (log/info test-run "Forwarding buffer to server")
                      ;; This approach is over-simplified for the sake
                      ;; of testing.
                      ;; In reality, we need to pull off this queue as
                      ;; fast as possible.
                      ;; And, realistically, push the message onto another
                      ;; queue that handles all the details like encrypting
                      ;; and actually writing bytes to the wire.
                      (message/parent->! srvr-state bs))
          child-message-counter (atom 0)
          strm-address (atom 0)
          child-cb (fn [_]
                     ;; This is for messages from elsewhere to the child.
                     ;; This test is all about the child spewing "lots" of data
                     ;; TODO: Honestly, need a test that really does just start off by
                     ;; sending megabytes (or gigabytes) of data as soon as the connection
                     ;; is warmed up.
                     ;; Library should be robust enough to handle that failure.
                     ;; Q: (which failure? feature?)
                     (is false "This should never get called"))
          client-initialized (message/initial-state (str "(test " test-run ") Client w/ Big Outbound")
                                                    parent-cb child-cb false)
          client-state (message/start! client-initialized)]
      (reset! state-agent-atom client-state)
      (try
        (let [;; Note that this is what the child sender should be supplying
              message-body (byte-array (range msg-len))]
          (log/debug test-run "Replicating child-send to " client-state)
          (message/child->! client-state message-body)
          (let [outcome (deref response 10000 ::timeout)
                end-time (System/nanoTime)]
            (log/info test-run
                      "Verifying that state hasn't errored out after"
                      (float (utils/nanos->millis (- end-time start-time))) "milliseconds")
            (if-let [err (agent-error client-state)]
              (is (not err))
              (do
                (is (not= outcome ::timeout))
                (when-not (= outcome ::timeout)
                  ;; TODO: What do I need to set up a full-blown i/o
                  ;; loop to make this accurate?
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
        (finally
          (log/info "Ending test" test-run)
          (try
            (message/halt! client-state)
            (catch RuntimeException ex
              (is not ex)))
          (try
            (message/halt! srvr-state)
            (catch RuntimeException ex
              (is not ex)))))
      (let [state-agent @state-agent-atom]
        (await state-agent)
        (await srvr-state)
        (log/info test-run "Deref'ing the state-agent")
        (let [{:keys [::specs/incoming
                      ::specs/outgoing]
               :as outcome} @state-agent]
          (is (= msg-len (::specs/ackd-addr outgoing)))
          (let [n-m-id (::specs/next-message-id outgoing)]
            ;; There's a timing issue with the next check.
            ;; There's a good chance we'll get here before
            ;; the agent is through updating its state due
            ;; to the last message we fed from the child.
            ;; So it might be one or the other
            (is (or (= (inc packet-count) n-m-id)
                    (= packet-count n-m-id)))
            ;; Either way, this relationship won't be impacted
            ;; by timing issues.
            ;; Except that it totally is.
            ;; We need to do an await on the client/server
            ;; agents for this kind of approach to make
            ;; any sense at all.
            (is (= (- n-m-id packet-count)
                   (count (::specs/un-ackd-blocks outgoing)))))
          (is (= 0 (from-child/buffer-size outcome)))
          ;; TODO: I do need a test that triggers EOF
          (is (not (::specs/send-eof outgoing)))
          ;; Keeping around as a reminder for when the implementation changes
          ;; and I need to see what's really going on again
          (comment (is (not outcome) "What should we have here?")))))))
(comment (bigger-echo))

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
