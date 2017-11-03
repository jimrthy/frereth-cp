(ns frereth-cp.message.from-child-test
  (:require [clojure.test :refer (deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.from-child :as from-child]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils])
  (:import clojure.lang.PersistentQueue
           [java.io
            IOException
            PipedInputStream
            PipedOutputStream]))

(deftest child-consumption
  (let [start-state #:frereth-cp.message.specs {:message-loop-name "Testing basic consumption from child"
                                                :outgoing #:frereth-cp.message.specs {:max-block-length 512
                                                                                      :ackd-addr 0
                                                                                      :strm-hwm 0
                                                                                      :un-sent-blocks PersistentQueue/EMPTY}}
        bytes-to-send (byte-array (range 8193))]
    (let [{:keys [::specs/outgoing]
           :as result} (from-child/consume-from-child start-state bytes-to-send)]
      (is (= 8193 (::specs/strm-hwm outgoing)))
      (is (= 0 (::specs/ackd-addr outgoing)))
      (is (= 512 (::specs/max-block-length outgoing)))
      (is (= 17 (count (::specs/un-sent-blocks outgoing)))))))

(deftest read-next-bytes
  (let [writer (PipedOutputStream.)
        reader (PipedInputStream. writer K/k-64)
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
              (.write writer send 64 64)))
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
              (is (b-t/bytes= send in4))))))
      (finally
        (.close writer)
        (log/debug "Verifying what happens to reader after closing writer")
        (try
          (let [final (.read reader)]
            (log/info "That was odd")
            (is (= final -1)))
          (catch IOException _
            (is true "Actually, this is what I expect")))
        (.close reader)))))
