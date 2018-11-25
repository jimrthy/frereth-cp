(ns frereth-cp.message.test-utilities
  "Utility functions shared among different tests"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message :as msg]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth.weald
             [logging :as log]
             [specs :as weald]])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(s/fdef build-flag-ack-start-state
        :args (s/cat :logger ::weald/logger)
        :ret ::specs/state)
(defn build-flag-ack-start-state
  [logger]
  (let [bytes-acked (+ 56 256 25 8 16 32)
        now #_(System/nanoTime) 1234
        ;; To be safe, any test that uses these needs
        ;; to .release() these buffers before it ends.
        ;; Q: Doesn't it?
        b1 (Unpooled/buffer 40)
        _ (.writeBytes b1 (byte-array (range 40)))
        b2 (Unpooled/buffer 256)
        _ (.writeBytes b2 (byte-array (->> (range) (drop 40) (take 256))))
        b3 (Unpooled/buffer 64)
        _ (.writeBytes b3 (byte-array (->> (range) (drop 296) (take 64))))
        b4 (Unpooled/buffer 8)
        _ (.writeBytes b4 (byte-array (->> (range) (drop 360) (take 8))))
        b5 (Unpooled/buffer 12)
        _ (.writeBytes b5 (byte-array (->> (range) (drop 368) (take 12))))
        b6 (Unpooled/buffer 16)
        _ (.writeBytes b6 (byte-array (->> (range) (drop 380) (take 16))))
        b7 (Unpooled/buffer 32)
        _ (.writeBytes b7 (byte-array (->> (range) (drop 396) (take 32))))
        unsorted-start-blocks [{::specs/ackd? false
                                ::specs/buf b1
                                ::specs/start-pos 10
                                ::specs/length 40
                                ::specs/time (- now 1)
                                ::specs/transmissions 1}  ; Covered by range 1
                               {::specs/ackd? false
                                ::specs/buf b2
                                ::specs/start-pos 60
                                ::specs/length 256
                                ::specs/time (- now 2)
                                ::specs/transmissions 2} ; Range 2
                               {::specs/ackd? false
                                ::specs/buf b3
                                ::specs/start-pos 316
                                ::specs/length 64
                                ::specs/time (- now 3)
                                ::specs/transmissions 3}  ; Partially covered by range 3
                               ;; Since that hasn't been ACK'd, we can'd drop any of the rest
                               {::specs/ackd? false
                                ::specs/buf b4
                                ::specs/start-pos 380
                                ::specs/length 8
                                ::specs/time (- now 4)
                                ::specs/transmissions 4}   ; Covered by range 4
                               {::specs/ackd? false
                                ::specs/buf b5
                                ::specs/start-pos 388
                                ::specs/length 12
                                ::specs/time (- now 5)
                                ::specs/transmissions 5}  ; Gap between 4 and 5
                               {::specs/ackd? false
                                ::specs/buf b6
                                ::specs/start-pos 400
                                ::specs/length 16
                                ::specs/time (- now 6)
                                ::specs/transmissions 6}  ; Block 5
                               {::specs/ackd? false
                                ::specs/buf b7
                                ::specs/start-pos 440
                                ::specs/length 32
                                ::specs/time (- now 7)
                                ::specs/transmissions 7}]  ; block 6
        log-state (log/init ::build-flag-ack-start-state 0)
        start-blocks (reduce (fn [acc block]
                               (conj acc block))
                             (msg/build-un-ackd-blocks {::weald/logger logger
                                                        ::weald/state log-state})
                             unsorted-start-blocks)]
    ;; This was built for a test where I send back an ACK.
    ;; It's tempting to make it more generally applicable,
    ;; but it seems like that would muddy up the point
    ;; between the ack-flag test for which this was intended
    ;; and whichever initial state might be required for other
    ;; tests that want to use something similar.
    ;; After all, this starts out as more-than-complicated enough.
    ;; OTOH...it wasn't a lot of fun to put this together once.
    {::specs/message-loop-name "Unit Testing"
     ::weald/state log-state
     ::specs/outgoing {::specs/ackd-addr 0
                       ::specs/contiguous-stream-count 0
                       ::specs/earliest-time 0
                       ::specs/strm-hwm 1000 ; Something bigger than what's getting acked
                       ::specs/total-block-transmissions 0
                       ::specs/total-blocks 0
                       ::specs/un-ackd-blocks start-blocks}}))

(defn build-ack-flag-message-portion
  "Set up a starting State that's primed with an
  incoming message buffer to ACK most of its pending
  sent blocks."
  [logger]
  (let [^ByteBuf buf (.order (Unpooled/buffer 48) java.nio.ByteOrder/LITTLE_ENDIAN)
        msg-id 161053530
        ack-id 1798373271]
    ;; There are no .writeUnsigned??? methods
    ;; This seems problematic.
    ;; For this implementation, where we never bother
    ;; ACKing anything except the first block (immediately),
    ;; it probably doesn't matter.
    (.writeInt buf msg-id)
    (.writeInt buf ack-id)
    (.writeLong buf 56)   ; bytes in range #1
    (.writeInt buf 4)     ; bytes between ranges 1-2
    (.writeShort buf 256) ; bytes in range #2
    (.writeShort buf 7)   ; bytes between ranges 2-3
    (.writeShort buf 25)  ; bytes in range #3
    (.writeShort buf 32)  ; bytes between ranges 3-4
    (.writeShort buf 8)   ; bytes in range #4
    (.writeShort buf 12)  ; bytes between ranges 4-5
    (.writeShort buf 16)  ; bytes in range #5
    (.writeShort buf 24)  ; bytes between ranges 5-6
    (.writeShort buf 32)  ; bytes in range #6
    (.writeShort buf 0)   ; (bit-or D SUCC FAIL)
    (.writeLong buf 0)    ; stream position of first byte in this message
    (let [actual-array (byte-array (.readableBytes buf))]
      (.getBytes buf 0 actual-array)
      ;; I expect packet to decode to something along these lines:
      #_{::specs/buf actual-array
         ;; Just picked something random
         ;; TODO: Also use something that would overflow
         ;; the 32-bit signed limit
         ::specs/message-id msg-id
         ::acked-message ack-id
         ::ack-length-1 56}
      (assoc (build-flag-ack-start-state logger)
             ::packet actual-array))))

(defn build-packet-with-message
  ;; This probably doesn't make any sense.
  ;; build-ack-flag-message-portion is intended
  ;; to simulate messages that have been sent but
  ;; not ACK'd.
  ;; Whereas this is about adding a message to
  ;; send.
  ;; Mixing the two takes the tests to an entirely
  ;; new level and really involves two separate
  ;; pieces doing the swapping.
  ;; This kind of low-level approach just does not
  ;; work there.
  ;; Yet.
  ([size]
   (throw (RuntimeException. "This was a bad idea"))
   size)
  ([]
   (build-packet-with-message 192)))
