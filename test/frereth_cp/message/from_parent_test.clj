(ns frereth-cp.message.from-parent-test
  (:require [clojure.test :refer (deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.from-parent :as from-parent]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-utilities :as test-helpers]
            [frereth-cp.message.to-parent :as to-parent]
            [frereth-cp.util :as utils])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(deftest verify-block-collapse
  ;; TODO: This is screaming for generative testing
  (let [^ByteBuf buf (Unpooled/buffer 128)]
    (try
      (.writeBytes buf (byte-array (range 100)))
      (let [half (byte-array 50)]
        (.readBytes buf half)
        (is (= (vec half) (range 50)))
        (.discardReadBytes buf)
        (.capacity buf 50)
        (.readBytes buf half)
        (is (= (vec half) (range 50 100))))
      (finally
        (.release buf)))))

(deftest check-flacked-others
  ;; This test is [still] failing with logic errors.
  ;; I think this is probably because I botched up the starting
  ;; conditions.
  (let [start-state (test-helpers/build-ack-flag-message-portion)
        raw-buffer (::test-helpers/packet start-state)
        start-state (dissoc start-state ::test-helpers/packet)
        decoded-packet (from-parent/deserialize raw-buffer)]
    (log/debug "Calling failing flag-acked with\n"
               (utils/pretty start-state)
               "\nand\n"
               (utils/pretty decoded-packet))
    (let [{{:keys [::specs/blocks
                   ::specs/send-acked
                   ::specs/send-bytes
                   ::specs/send-processed
                   ::specs/total-blocks
                   ::specs/total-block-transmissions]} ::specs/outgoing
           :as flagged} (from-parent/flag-acked-others! start-state decoded-packet)
          ;; The ACKs specified in the incoming packet should drop the first two blocks
          expected-remaining-blocks (drop 2 (get-in start-state [::specs/outgoing ::specs/blocks]))]
      (try
        (let [dropped-block-length (reduce + 0
                                           (->> start-state
                                                ::specs/outgoing
                                                ::specs/blocks
                                                (take 2)
                                                (map ::specs/length)))]
          (is (= 5 total-blocks) "Total blocks ACK'd")
          (is (= (+ (get-in start-state [::specs/outgoing ::specs/blocks 0 ::specs/length])
                    (get-in start-state [::specs/outgoing ::specs/blocks 1 ::specs/length]))
                 send-acked) "Bytes that have been dropped")
          (is (= (- (get-in start-state [::specs/outgoing ::specs/send-bytes])
                    dropped-block-length)
                 send-bytes) "Bytess that have not been sent but not dropped")
          (is (= (- (get-in start-state [::specs/outgoing ::specs/send-processed]) dropped-block-length)
                 send-processed) "Sent bytes that have been absorbed into blocks")
          (is (= 20 total-block-transmissions))
          (is (= (map #(dissoc % ::specs/time) expected-remaining-blocks)
                 (map #(dissoc % ::specs/time) blocks))))
        (finally
          (doseq [b (get-in flagged [::specs/outgoing ::specs/blocks])]
            (.release (::specs/buf b))))))))
(comment
  (check-flacked-others)
  )

(deftest check-start-stop-calculation
  (testing "Happy Path"
    (testing "Initial message"
      (let [size K/k-1
            buf (Unpooled/buffer size)
            ;; Just pick something arbitrary that's easy to identify.
            ;; Not that it matters for the purposes of this test.
            src (byte-array (take K/k-1 (repeat 3)))]
        (.writeBytes buf src)
        (let [^bytes pkt (to-parent/build-message-block 1 {::specs/start-pos 0
                                                           ::specs/buf buf
                                                           ::specs/length size
                                                           ::specs/send-eof false})
              decoded-packet (from-parent/deserialize pkt)
              ;; Rubber meets the road.
              ;; receive-bytes is the "number of initial bytes fully received"
              ;; receive-written is "within receivebytes, number of bytes given to child"
              start-state {::specs/incoming {::specs/receive-bytes 0
                                             ::specs/receive-written 0}}
              calculated (from-parent/calculate-start-stop-bytes start-state decoded-packet)]
          (is (= #:frereth-cp.message.from-parent {:min-k 0
                                                   :max-k size
                                                   :delta-k size
                                                   :max-rcvd K/k-128
                                                   ;; The value here depends on the
                                                   ;; send-eof flag.
                                                   :receive-total-bytes nil}
                 calculated)))))
    (testing "Second message"
      (is false "Start here")))
  (testing "with a gap"
    ;; TODO: Add a function that lets me specify a packet's stream address.
    ;; Add another that takes the guesswork out of setting up the system state
    ;; for building the packet in the first place.
    ;; (i.e. which parts of state am I really using?)
    ;; That should really just be a wrapper around my existing packet-generator
    ;; code.
    ;; That's probably just a new spec and then something like select-in and/or
    ;; rename-keys.
    ;; It seems like it would make a lot of sense to switch to using that pretty
    ;; much everywhere I'm calling the existing version

    ;; Bigger TODO: Write a couple of exe's for sandwiching the reference message
    ;; implementation. In something with fast startup time. cljs and ruby both
    ;; seem likely choices.
    ;; That comment doesn't belong in here, but this part's going to stand out
    ;; in a git diff, for now. So this seems like my best chance to remember
    ;; it the next time I get a chance to look at it

    ;; TODO: Make sure I've correctly replicated whatever DJB is doing
    ;; with receivevalid. That has to be the magic secret sauce for coping
    ;; with gaps.
    (is true "Add a variation with a gap between the last byte written and the first byte in our stream")))
(comment
  (-> (test-helpers/build-packet-with-message) ::specs/incoming keys)
  )


(deftest check-big-flacked-others
  ;; This needs to be expanded to match the behavior in check-flacked-others
  (testing "Values for big message streams"
    (let [^ByteBuf buf (Unpooled/buffer 48)]
      ;; We're going to have to be able to cope with big numbers
      ;; sooner or later
      (.writeLong buf -56)   ; bytes in range #1
      (.writeInt buf -4)     ; bytes between ranges 1-2
      (.writeShort buf -256) ; bytes in range #1
      (.writeShort buf 7)   ; bytes between ranges 2-3
      (.writeShort buf 25)  ; bytes in range #3
      (.writeShort buf 32)  ; bytes between ranges 3-4
      (.writeShort buf 8)   ; bytes in range #4
      (.writeShort buf 12)  ; bytes between ranges 4-5
      (.writeShort buf 16)  ; bytes in range #5
      (.writeShort buf 24)  ; bytes between ranges 5-6
      (.writeShort buf 32)  ; bytes in range #6
      (let [flagged (from-parent/flag-acked-others! {::specs/receive-buf buf})]
        (is (not flagged) "What should that look like?")))))
