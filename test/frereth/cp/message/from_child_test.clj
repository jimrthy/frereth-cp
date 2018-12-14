(ns frereth.cp.message.from-child-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth.cp.message :as msg]
            [frereth.cp.message
             [constants :as K]
             [from-child :as from-child]
             [specs :as specs]]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [util :as utils]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]])
  (:import clojure.lang.PersistentQueue
           [java.io
            IOException
            PipedInputStream
            PipedOutputStream]))

(deftest child-consumption
  (let [logger (log/std-out-log-factory)
        log-state (log/init ::child-consumption)
        message-loop-name "Testing basic consumption from child"
        un-ackd-blocks (msg/build-un-ackd-blocks {::weald/logger logger
                                                  ::weald/state log-state})
        start-state #:frereth.cp.message.specs {:message-loop-name message-loop-name
                                                :outgoing #:frereth.cp.message.specs {:max-block-length 512
                                                                                      :ackd-addr 0
                                                                                      :strm-hwm 0
                                                                                      :un-sent-blocks PersistentQueue/EMPTY
                                                                                      :un-ackd-blocks un-ackd-blocks}
                                                ::weald/state log-state}
        bytes-to-send (byte-array (range 8193))]
    ;; This test is now completely broken.
    ;; And obsolete.
    ;; The basic premise has changed out from underneath it.
    ;; The real thing to do is to start up a messaging loop, write these bytes to
    ;; the appropriate PipedOutputStream, and verify that they end up in the outbound
    ;; queues.
    ;; That seems like more trouble than it's worth, since I have bigger-picture
    ;; tests that already cover this more thoroughly in message-test.
    ;; I should probably just scrap this.
    (let [{log-state ::weald/state
           consumer ::from-child/callback} (from-child/build-byte-consumer message-loop-name log-state bytes-to-send)
          {:keys [::specs/outgoing]
           :as result} (consumer start-state)]
      (is (= 8193 (::specs/strm-hwm outgoing)))
      (is (zero? (::specs/ackd-addr outgoing)))
      (is (= 512 (::specs/max-block-length outgoing)))
      (is (= 1 (+ (count (::specs/un-sent-blocks outgoing))
                  (count (::specs/un-ackd-blocks outgoing))))))))

(deftest read-next-bytes
  (let [writer (PipedOutputStream.)
        reader (PipedInputStream. writer K/k-2)
        send (byte-array (range K/k-1))
        human-name "Mock message bufferer"
        buffer-name "Mock child writer"
        logger (log/std-out-log-factory)
        log-state (log/init ::read-next-bytes)]
    (try
      (future
        (let [log-state (log/info log-state ::writing)]
          (.write writer send 0 64)
          ;; According to the docs, the data pipe should be
          ;; considered broken when this thread exits.
          ;; Actually, that kind of approach would make these
          ;; PipedStreams useless to me.
          ;; The fact that this test passes despite the docs
          ;; bothers me.
          ;; Q: Is this an accidental implementation detail of
          ;; the JVM I happen to be using?
          ;; Actually, it's probably because this future is
          ;; running inside the agent pool. So the thread
          ;; doesn't die; it just gets recycled back into
          ;; the pool.
          ;; That seems pretty flimsy, but the idea of tying
          ;; the reader to a single thread associated with the
          ;; writer just seems idiotic.
          (let [log-state (log/debug log-state ::written)]
            (log/flush-logs! logger log-state))))
      (testing "Basic chunk transfer"
        ;; FIXME: read-next-bytes-from-child! has a different return value
        (let [{in1 ::specs/bs-or-eof
               log-state ::weald/state}
                (from-child/read-next-bytes-from-child! human-name
                                                        log-state
                                                        reader
                                                        64
                                                        32)]
            (is (= 32 (count in1)))
            (let [{in2 ::specs/bs-or-eof
                   log-state ::weald/state}
                  (from-child/read-next-bytes-from-child! human-name
                                                          log-state
                                                          reader
                                                          in1
                                                          32
                                                          256)]
              (future
                (let [log-state (log/debug log-state ::pausing)]
                  (Thread/sleep 250)
                  (let [log-state (log/debug log-state ::unpaused)]
                    (.write writer send 64 64)
                    ;; In at least one test, it took 750 ms
                    ;; from the time I called .write to the
                    ;; time the reader thread unblocked.
                    ;; TODO: Keep a very close eye on that. It
                    ;; may destroy this approach.
                    (log/flush-logs! logger
                                     (log/debug log-state ::sent)))))
              (let [n-remaining (- (count send) 128)
                    ;; This definitely should block due to the Thread/sleep
                    ;; in the sender
                    {in3 ::specs/bs-or-eof
                     log-state ::weald/state} (from-child/read-next-bytes-from-child! human-name
                                                                                      log-state
                                                                                      reader
                                                                                      in2
                                                                                      0
                                                                                      256)]
                (is (= 128 (count in3)))
                (future
                  (let [log-state (log/init ::remainder)
                        log-state (log/debug log-state ::sending)]
                    (.write writer send 128 n-remaining)
                    (log/flush-logs! logger (log/debug log-state ::sent))))
                ;; There's a good chance this next line will block,
                ;; waiting for the previous future.
                ;; We're cheating by pretending bytes are available before
                ;; the really are.
                (let [{in4 ::specs/bs-or-eof
                       log-state ::weald/log} (from-child/read-next-bytes-from-child! human-name
                                                                                      log-state
                                                                                      reader
                                                                                      in3
                                                                                      n-remaining
                                                                                      (* 2 n-remaining))]
                  (is (= (count send) (count in4)))
                  (when-not (b-t/bytes= send in4)
                    (dotimes [i (count send)]
                      (is (= (aget send i)
                             (aget in4 i))
                          (str "Mismatch at offset " i)))))))))
      (testing "Buffer overflow"
        (let [log-state (log/info log-state ::starting)
              size (+ (* 3 K/k-4) 37)]
          (future
            (let [send (byte-array (range size))
                  log-state (log/info log-state
                                      ::sender
                                      "Writing something much to large")]
              ;; Note: the actual client API that the child calls
              ;; needs to at least optionally have a way to return
              ;; an error indicator if this would have blocked.
              (.write writer send 0 (count send))
              (log/flush-logs! (log/debug log-state
                                          ::sender
                                          "Wrote too many bytes"))))
          (loop [n 0
                 log-state (log/flush-logs! logger log-state)]
            ;; There isn't really much to do here that's interesting.
            (let [remaining (- size n)
                  log-state (log/info log-state
                                      ::read-top
                                      {::expecting remaining})]
              (if (pos? remaining)
                (let [{rcvd ::specs/bs-or-eof
                       log-state ::weald/state} (from-child/read-next-bytes-from-child! human-name
                                                                                        log-state
                                                                                        reader
                                                                                        remaining
                                                                                        size)
                      m (count rcvd)
                      log-state (log/debug log-state
                                           ::read-bottom
                                           ::received m)]
                  (when (>= 0 m)
                    (throw (RuntimeException. "Unexpected EOF")))
                  (recur (+ n m)
                         (log/flush-logs! logger log-state)))
                (log/flush-logs! logger log-state))))))
      (finally
        (.close writer)
        (let [log-state (log/init ::cleanup)
              log-state
              (log/debug log-state
                         ::denouement
                         "Verifying what happens to reader after closing writer")]
          (try
            (is (zero? (.available reader)))
            (let [final (.read reader)
                  log-state (log/info log-state
                                      ::unexpected
                                      "According to the docs, that should have thrown an exception")]
              ;; At least this part's correct
              (is (= final -1)))
            (catch IOException _
              (is true "Actually, this is what I expect"))))
        (.close reader)))))
