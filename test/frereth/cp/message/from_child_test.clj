(ns frereth-cp.message.from-child-test
  (:require [clojure.test :refer (deftest is testing)]
            ;; FIXME: Make this go away
            [clojure.tools.logging :as log]
            [frereth-cp.message :as msg]
            [frereth-cp.message
             [constants :as K]
             [from-child :as from-child]
             [specs :as specs]]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils])
  (:import clojure.lang.PersistentQueue
           [java.io
            IOException
            PipedInputStream
            PipedOutputStream]))

(deftest child-consumption
  (let [message-loop-name "Testing basic consumption from child"
        start-state #:frereth-cp.message.specs {:message-loop-name message-loop-name
                                                :outgoing #:frereth-cp.message.specs {:max-block-length 512
                                                                                      :ackd-addr 0
                                                                                      :strm-hwm 0
                                                                                      :un-sent-blocks PersistentQueue/EMPTY
                                                                                      :un-ackd-blocks (msg/build-un-ackd-blocks)}}
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
    (let [consumer (from-child/build-byte-consumer message-loop-name bytes-to-send)
          {:keys [::specs/outgoing]
           :as result} (consumer start-state)]
      (is (= 8193 (::specs/strm-hwm outgoing)))
      (is (= 0 (::specs/ackd-addr outgoing)))
      (is (= 512 (::specs/max-block-length outgoing)))
      (is (= 1 (+ (count (::specs/un-sent-blocks outgoing))
                  (count (::specs/un-ackd-blocks outgoing))))))))

(deftest read-next-bytes
  (let [writer (PipedOutputStream.)
        reader (PipedInputStream. writer K/k-2)
        send (byte-array (range K/k-1))
        human-name "Mock message bufferer"
        buffer-name "Mock child writer"]
    (try
      (future
        (let [prelog (utils/pre-log buffer-name)]
          (log/info prelog "Writing first messages")
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
          (log/debug prelog "Wrote first 64 bytes")))
      (testing "Basic chunk transfer"
          (let [in1
                (from-child/read-next-bytes-from-child! human-name
                                                        reader
                                                        []
                                                        64
                                                        32)]
            (is (= 32 (count in1)))
            (let [in2
                  (from-child/read-next-bytes-from-child! human-name
                                                          reader
                                                          in1
                                                          32
                                                          256)]
              (future
                (let [prelog (utils/pre-log buffer-name)]
                  (log/debug prelog "Pausing to force child to block")
                  (Thread/sleep 250)
                  (log/debug prelog "Sending 64 more")
                  (.write writer send 64 64)
                  ;; In at least one test, it took 750 ms
                  ;; from the time I called .write to the
                  ;; time the reader thread unblocked.
                  ;; TODO: Keep a very close eye on that. It
                  ;; may destroy this approach.
                  (log/debug prelog "64 bytes sent")))
              (let [n-remaining (- (count send) 128)
                    ;; This definitely should block due to the Thread/sleep
                    ;; in the sender
                    in3 (from-child/read-next-bytes-from-child! human-name
                                                                reader
                                                                in2
                                                                0
                                                                256)]
                (is (= 128 (count in3)))
                (future
                  (let [prelog (utils/pre-log buffer-name)]
                    (log/debug prelog "Sending the rest of the batch")
                    (.write writer send 128 n-remaining)))
                ;; There's a good chance this next line will block,
                ;; waiting for the previous future.
                ;; We're cheating by pretending bytes are available before
                ;; the really are.
                (let [in4 (from-child/read-next-bytes-from-child! human-name
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
        (let [prelog (utils/pre-log buffer-name)]
          (log/info prelog "Starting buffer portion of the test")
          (let [size (+ (* 3 K/k-4) 37)]
            (future
              (let [prelog (utils/pre-log buffer-name)
                    send (byte-array (range size))]
                (log/info prelog "Writing something much to large")
                ;; Note: the actual client API that the child calls
                ;; needs to at least optionally have a way to return
                ;; an error indicator if this would have blocked.
                (.write writer send 0 (count send))
                (log/debug prelog "Wrote too many bytes")))
            (loop [n 0]
              ;; There isn't really much to do here that's interesting.
              (let [remaining (- size n)]
                (log/info prelog "Top of read loop. Expecting" remaining "more bytes")
                (when (< 0 remaining)
                  (let [rcvd (from-child/read-next-bytes-from-child! human-name
                                                                     reader
                                                                     (byte-array 0)
                                                                     remaining
                                                                     size)]
                    (let [m (count rcvd)]
                      (log/debug "Received" m "bytes")
                      (when (>= 0 m)
                        (throw (RuntimeException. "Unexpected EOF")))
                      (recur (+ n m))))))))))
      (finally
        (.close writer)
        (log/debug "Verifying what happens to reader after closing writer")
        (try
          (is (= 0 (.available reader)))
          (let [final (.read reader)]
            (log/info "According to the docs, that should have thrown an exception")
            ;; At least this part's correct
            (is (= final -1)))
          (catch IOException _
            (is true "Actually, this is what I expect")))
        (.close reader)))))
