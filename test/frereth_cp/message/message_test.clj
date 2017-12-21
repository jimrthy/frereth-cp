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
            [frereth-cp.shared.logging :as log2]
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
  ;; Q: Does this make any sense at all?
  ;; A: Well, a little. If the put! would
  ;; have blocked, this call just fails.
  ;; Without a good explanation about what
  ;; to try differently.
  ;; So the problem is really a bad API.
  ;; TODO: Convert child->! to return nil
  ;; on success and the number of bytes that
  ;; *are* available on failure.

  ;; TODO: Refactor to take advantage of
  ;; from-child/try-multiple-sends
  [f  ;; Honestly, this is just child->!
   logger
   n
   io-handle
   payload
   success-message
   failure-message
   failure-body]
  (let [logs (log2/init)]
    (loop [m n]
      (if (f io-handle payload)
        (let [logs (log2/info logs ::try-multiple-sends success-message)
              logs (log2/debug logs
                               ::try-multiple-sends
                               (str "Sending took" (- (inc n) m) "attempt(s)"))]
          (log2/flush-logs! logger logs))
        (if (> 0 m)
          (let [failure (ex-info failure-message
                                 failure-body)
                logs (log2/exception logs
                                     failure
                                     ::try-multiple-sends
                                     failure-message)]
            (log2/flush-logs! logger logs)
            ;; Need to make double-extra certain that
            ;; this exception doesn't just disappear
            (throw failure))
          (recur (dec m)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Actual tests

(deftest basic-echo
  ;; There's some ugliness baked into here for the sake of
  ;; simplicity.
  ;; Or maybe it was just easier to write it this way at first.
  ;; Messages don't propagate correctly until we at least
  ;; start getting back ACKs.
  ;; I really don't want to fake that.
  ;; Initial implementations worked with just a sender.
  ;; Now that I'm getting closer to having the full protocol
  ;; implemented, this is getting messier.
  ;; TODO: Revisit this decision. See whether it's uglier
  ;; with 2 sides to "communicate"
  (let [loop-name "Echo Test"
        logs (log2/init)
        logger (log2/std-out-log-factory)
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
            ;; I have circular dependencies among
            ;; the io-handle, child-cb, and parent-cb.
            ;; The callbacks both need access to the
            ;; io-handle. But I can't create the io-handle
            ;; without them.
            ;; Hopefully this is just an artifact of the
            ;; way I wrote this test and not a fundamental
            ;; design flaw.
            io-handle-atom (atom nil)
            parent-state (atom 0)
            parent-cb (fn [buf]
                        ;; This is really a mock-up of the entire
                        ;; encryption/networking stack.
                        ;; In a lot of ways, this mimics what a
                        ;; really simplistic child on the "other side"
                        ;; might do.
                        (is (s/valid? bytes? buf))
                        (let [response-state @parent-state
                              logs (log2/debug logs
                                               ::echo-parent-cb
                                               "Top of callback"
                                               {::response-state response-state
                                                ::called-from (utils/get-stack-trace (Exception.))})
                              new-state (swap! parent-state inc)
                              ;; I'd like to get 3 message packets here:
                              ;; 1. ACK
                              ;; 2. message being echoed
                              ;; 3. EOF
                              ;; What I'm getting instead is:
                              ;; 1. ACK
                              ;; 2. message being echoed
                              ;; 3. message being echoed because I haven't responded with an ACK
                              ;; There may be ways around this, but none of the ones that come
                              ;; to mind just now seem worth the time/effort.
                              ;; This test pretty obviously isn't about a
                              ;; realistic message exchange. It's really
                              ;; just about verifying that I got the echo.
                              ;; Everything else going on in here is really just
                              ;; a distraction from that fundamental point.
                              ;; They're good distractions, and the system's gotten
                              ;; much more robust because of them.
                              ;; FIXME: Revisit this soon.
                              logs (if (= 3 new-state)
                                     (let [logs (log2/info logs
                                                           ::echo-parent-cb
                                                           "Echo sent. Pretending other child triggers done")
                                           ;; This seems like a good time for the parent
                                           ;; to send EOF
                                           {:keys [::specs/from-parent-trigger]
                                            :as io-handle} @io-handle-atom]
                                       ;; This part of the circular dependency
                                       ;; is absolutely not realistic.
                                       ;; The real message code that receives
                                       ;; the EOF signal needs to do this.
                                       ;; It only makes sense in this test because
                                       ;; I'm totally mocking out any sort of real
                                       ;; interaction.
                                       (strm/close! from-parent-trigger)
                                       (deliver response buf)
                                       logs)
                                     logs)]
                          (log2/flush-logs! logger logs)))
            child-message-counter (atom 0)
            strm-address (atom 0)
            child-finished (dfrd/deferred)
            ;; The actual problem with this test is the missing
            ;; logs parameter.
            ;; The bigger-picture problem is that the problem wasn't
            ;; immediately obvious
            ;; FIXME: Start back with the caller to fix that.
            child-cb (fn [logs array-o-bytes]
                       (println "Top of child-cb")
                       ;; TODO: Add another similar test that throws an
                       ;; exception here, for the sake of hardening the
                       ;; caller
                       (let [logs (log2/info logs
                                             ::echo-child-cb
                                             "Incoming to child"
                                             {::rcvd array-o-bytes
                                              ::type (class array-o-bytes)})]
                         (is array-o-bytes "Falsey reached callback")
                         (println "Checked for truthy incoming")
                         (try
                           (let [logs
                                 (if (bytes? array-o-bytes)
                                   (let [msg-len (count array-o-bytes)
                                         locator (Exception.)
                                         logs (if (not= 0 msg-len)
                                                (let [logs (log2/debug logs
                                                                       ::echo-child-cb
                                                                       "Echoing back an incoming message"
                                                                       {::msg-len msg-len
                                                                        ::called-from (utils/get-stack-trace (Exception.))})
                                                      logs (if (not= K/k-1 msg-len)
                                                             (log2/warn logs
                                                                        ::echo-child-cb
                                                                        "Incoming message doesn't match length we sent"
                                                                        {::expected K/k-1
                                                                         ::actual msg-len
                                                                         ::details (vec array-o-bytes)})
                                                             logs)
                                                      ;; Just echo it directly back.
                                                      io-handle @io-handle-atom]
                                                  (println "")
                                                  (is io-handle)
                                                  (swap! child-message-counter inc)
                                                  (swap! strm-address + msg-len)
                                                  (try
                                                    (try-multiple-sends message/child->!
                                                                        logger
                                                                        5
                                                                        io-handle
                                                                        array-o-bytes
                                                                        (str "Buffered bytes from child")
                                                                        "Giving up on buffering bytes from child"
                                                                        {})
                                                    (finally
                                                      (message/child-close! @io-handle-atom)
                                                      ;; This is called purely for side-effects.
                                                      ;; The return value does not matter.
                                                      (let [inner-logs (log2/init (inc (::log2/lamport logs)))
                                                            inner-logs (log2/info inner-logs
                                                                                  ::echo-child-cb
                                                                                  "Sent EOF after the message block")]
                                                        (log2/flush-logs! logger inner-logs))))
                                                  logs))]
                                     (log2/warn logs :echo-child-cb "Empty incoming message. Highly suspicious"))
                                   (let [{:keys [::specs/from-child]
                                            :as io-handle} @io-handle-atom
                                           logs (log2/warn logs
                                                           ::echo-child-cb
                                                           "Child received what should be EOF. Mark done.")]
                                       (message/child-close! io-handle)
                                       (is (s/valid? ::specs/eof-flag array-o-bytes))
                                       (deliver child-finished array-o-bytes)
                                       logs))]
                             (log2/flush-logs! logger logs))
                           (catch Exception ex
                             (println "child-cb Failed:" ex)
                             ;; Throw as much sand as possible into the gears
                             nil))))
            ;; It's tempting to treat this test as a server.
            ;; Since that's the way it acts: request packets come in and
            ;; trigger responses.
            ;; But the setup is wrong:
            ;; The server shouldn't start until after the first client
            ;; message arrives.
            ;; Maybe it doesn't matter, since I'm trying to send the initial
            ;; message quickly, but the behavior seems suspicious.
            initialized (message/initial-state loop-name true {} logger)
            io-handle (message/start! initialized logger parent-cb child-cb)]
        (dfrd/on-realized child-finished
                          (fn [success]
                            (let [logs (log2/info logs
                                                  ::child-finished
                                                  "Child just signalled EOF")]
                              (log2/flush-logs! logger logs))
                            (is (= ::specs/normal success)))
                          (fn [failure]
                            (is (not failure) "Child echoer failed")))
        (try
          (let [state (message/get-state io-handle 500 ::timed-out)]
            (is (not= state ::timed-out) "Querying for initial state timed out")
            (when (not= state ::timed-out)
              (reset! io-handle-atom io-handle)
              (is (not
                   (s/explain-data ::specs/state state)))

              ;; TODO: Add similar tests that send a variety of
              ;; gibberish messages
              (let [wrote (dfrd/future
                            (let [logs (log2/init)
                                  logs (log2/debug logs
                                                   ::echo-initial-write
                                                   "Writing message from parent")]
                              (message/parent->! io-handle incoming)
                              (let [logs (log2/debug logs
                                                     ::echo-initial-write
                                                     "Message should be headed to child")]
                                (log2/flush-logs! logger logs))))
                    ;; The time delay here is pretty crazy.
                    ;; It seems as though it should never take human-noticeable time.
                    ;; And yet I've seen this test fail on my desktop
                    ;; because it took > 2 seconds.
                    ;; (Most of that is because I don't have another side to send
                    ;; an ACK
                    outcome (deref response 5000 ::timeout)]
                (if (= outcome ::timeout)
                  (do
                    (is (not= outcome ::timeout) "Parent didn't get complete message from child"))
                  (do
                    (is (= 3 @parent-state))
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
                (let [state (message/get-state io-handle 500 ::time-out)
                      logs (log2/info logs
                                      ::echo-examination
                                      "Final state query returned")]
                  (is (not= state ::timeout))
                  (when (not= state ::timeout)
                    (is (not
                         (s/explain-data ::specs/state state)))
                    (let [logs (log2/info logs
                                          ::echo-examination
                                          "Checking test outcome")]
                      (let [child-completion (deref child-finished 500 ::child-timed-out)]
                        (is (= ::specs/normal child-completion)))

                      (let [{:keys [::specs/incoming
                                    ::specs/outgoing]} state]
                        (is incoming)
                        (is (= msg-len (inc (::specs/strm-hwm incoming))))
                        (is (= msg-len (::specs/contiguous-stream-count incoming)))
                        (is (= (inc (::specs/strm-hwm incoming))
                               (::specs/contiguous-stream-count incoming)))
                        (is (= 3 (::specs/next-message-id outgoing)))
                        ;; There's nothing on the other side to send back
                        ;; an ACK. But it should have been sent.
                        (is (= msg-len (from-child/buffer-size outgoing)))
                        ;; This includes both the packet we're echoing back
                        ;; and the EOF signal.
                        ;; Because of the way the initial scheduling algorithm works
                        ;; (it wants an ACK from the first block before sending the
                        ;; second), we're winding up with 1 message in both
                        ;; queues. That's an implementation detail that really doesn't
                        ;; matter for our purposes, and it might change.
                        ;; The important point is that we still have both
                        ;; the echo and the EOF.
                        (is (= 2 (+ (count (::specs/un-sent-blocks outgoing))
                                    (count (::specs/un-ackd-blocks outgoing)))))
                        (is (= ::specs/normal (::specs/send-eof outgoing)))
                        (is (= msg-len (::specs/strm-hwm outgoing)))
                        ;; Keeping around as a reminder for when the implementation changes
                        ;; and I need to see what's really going on again
                        (comment (is (not outcome) "What should we have here?")))
                      (log2/flush-logs! logger logs)))))))
          (catch ExceptionInfo ex
            (let [logs (log2/exception (log2/init)
                                       ex
                                       ::echo-failure
                                       "Starting the event loop")]
              (log2/flush-logs! logger logs)))
          (finally
            (let [logs (log2/warn (log2/init)
                                  ::echo-clean-up
                                  "Signalling I/O loop halt")]
              (log2/flush-logs! logger logs)
              (message/halt! io-handle))))))))
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
        consumer (from-child/build-byte-consumer message-loop-name chzbrgr)
        _ (log/info "Reading chzbrgr from child")
        ;; This is much slower than I'd like
        {:keys [::specs/outgoing
                ::specs/recent]
         :as state'} (time (consumer start-state))]
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
    (log/info prelog "Start test writing big chunk of outbound data")
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
          msg-len (+ (* (dec packet-count) K/k-1) K/k-div4)
          response (promise)
          srvr-child-state (atom {:address 0
                                  :buffer []
                                  :count 0})
          srvr-io-atom (atom nil)
          ;; I have a circular dependency between
          ;; the client's child-cb, server-parent-cb,
          ;; and initialized.
          ;; The callbacks have access to the state
          ;; value, but not the io-loop handle.
          ;; They need that, because child->!
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
                             ;; This is simulating the network
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

                              (let [packet-size (if (keyword? incoming)
                                                  0
                                                  (count incoming))
                                    response-state @srvr-child-state]
                                (if (keyword? incoming)
                                  (do
                                    (log/warn prelog "Server child received EOF" incoming)
                                    (is (s/valid? ::specs/eof-flag incoming))
                                    (message/child-close! @client-io-atom))
                                  (log/debug prelog
                                             (str "::server-child-cb ("
                                                  packet-size
                                                  " bytes): "
                                                  (-> response-state
                                                      (dissoc :buffer)
                                                      (assoc :buffer-size (count (:buffer response-state)))))))
                                (swap! srvr-child-state
                                       (fn [cur]
                                         (log/info prelog "Incrementing state count")
                                         (let [incoming (if (keyword? incoming)
                                                          [incoming]
                                                          incoming)]
                                           (-> cur
                                               (update :count inc)
                                               ;; Seems a little silly to include the ACKs.
                                               ;; Should probably think this through more thoroughly
                                               ;; ACKs shouldn't get here.
                                               ;; TODO: Verify that.
                                               (update :buffer conj (vec incoming))
                                               (update :address + packet-size)))))
                                (when (= msg-len (:address @srvr-child-state))
                                  (log/info prelog
                                            "::srvr-child-cb Received all expected bytes")
                                  (deliver response @srvr-child-state)
                                  (message/child-close! @srvr-io-atom)))))
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
          child-cb (fn [eof]
                     ;; This is for messages from elsewhere to the child.
                     ;; This test is all about the *child* spewing "lots" of data.
                     ;; So I don't expect it to ever receive anything except the EOF
                     ;; marker.

                     ;; TODO: Honestly, need a test that really does just start off by
                     ;; sending megabytes (or gigabytes) of data as soon as the connection
                     ;; is warmed up.
                     ;; Library should be robust enough to handle that.
                     (is (s/valid? ::specs/eof-flag eof) "This should only get called for EOF"))
          client-initialized (message/initial-state (str "(test " test-run ") Client w/ Big Outbound")
                                                    false
                                                    {})
          client-io-handle (message/start! client-initialized parent-cb child-cb)]
      (reset! srvr-io-atom srvr-io-handle)
      (reset! client-io-atom client-io-handle)

      (try
        (let [;; Note that this is what the child sender should be supplying
              message-body (byte-array (range msg-len))]
          (log/debug prelog "Replicating child-send to " client-io-handle)
          (try-multiple-sends message/child->!
                              prelog
                              5
                              client-io-handle
                              message-body
                              (str "Buffered "
                                   msg-len
                                   " bytes to child")
                              "Buffering big message from child failed"
                              {::buffer-size msg-len})
          (message/child-close! client-io-handle)
          (let [outcome (deref response 10000 ::timeout)
                end-time (System/nanoTime)]
            (is (not= outcome ::timeout))
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
                  (let [stream-address (:address outcome)]
                    (is (= msg-len stream-address))
                    (let [rcvd-blocks (:buffer outcome)
                          ;; This is not working at all.
                          ;; Q: Why not?
                          byte-seq (into [] (apply concat rcvd-blocks))
                          _ (log/debug prelog
                                       "Trying to recreate the incoming stream from"
                                       (count byte-seq)
                                       "'somethings' in a"
                                       (class byte-seq)
                                       "that looks like\n"
                                       byte-seq
                                       "\nBased upon"
                                       (count rcvd-blocks)
                                       "instances of"
                                       (class (first rcvd-blocks))
                                       "\nFirst one:\n"
                                       (first rcvd-blocks))
                          rcvd-strm (byte-array byte-seq)]
                      (is (= (count message-body) (count rcvd-strm)))
                      (is (b-t/bytes= message-body rcvd-strm)))))))))
        (let [{:keys [::specs/incoming
                      ::specs/outgoing]
               :as outcome} (message/get-state client-io-handle 500 ::time-out)]
          (is (not= outcome ::time-out))
          (when (not= outcome ::time-out)
            (is outgoing)
            ;; The ACK for EOF marks 1 past the end of stream, to indicate
            ;; that we also received the EOF.
            (is (= (inc msg-len) (::specs/ackd-addr outgoing)))
            (is (= 0 (from-child/buffer-size outcome)))
            (is (= ::specs/normal (::specs/send-eof outgoing)))
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

(deftest check-initial-state-override
  (let [opts {::specs/outgoing {::specs/pipe-from-child-size K/k-1}
              ::specs/incoming {::specs/pipe-to-child-size K/k-4}}
        start-state (message/initial-state "Overflowing Test" true opts)]
    (is (= K/k-1 (get-in start-state [::specs/outgoing ::specs/pipe-from-child-size])))
    (is (= K/k-4 (get-in start-state [::specs/incoming ::specs/pipe-to-child-size])))))

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
