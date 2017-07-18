(ns frereth-cp.message.test-utilities
  "Utility functions shared among different tests"
  (:require [frereth-cp.message.specs :as specs])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(defn build-ack-flag-message-portion
  "Set up a starting State that's primed with an
  incoming message buffer to ACK most of its pending
  sent blocks."
  []
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
    (let [bytes-acked (+ 56 256 25 8 16 32)
          now #_(System/nanoTime) 1234
          ;; To be safe, any test that uses these needs
          ;; to .release() these buffers before it ends.
          ;; Q: Doesn't it?
          b1 (Unpooled/buffer 16)
          _ (.writeBytes b1 (byte-array [1]))
          b2 (Unpooled/buffer 16)
          _ (.writeBytes b2 (byte-array [2]))
          b3 (Unpooled/buffer 16)
          _ (.writeBytes b3 (byte-array [1]))
          b4 (Unpooled/buffer 16)
          _ (.writeBytes b4 (byte-array [2]))
          b5 (Unpooled/buffer 16)
          _ (.writeBytes b5 (byte-array [1]))
          b6 (Unpooled/buffer 16)
          _ (.writeBytes b6 (byte-array [2]))
          b7 (Unpooled/buffer 16)
          _ (.writeBytes b7 (byte-array [2]))
          start-blocks [{::specs/buf b1
                         ::specs/start-pos 10
                         ::specs/length 40
                         ::specs/time (- now 1)
                         ::specs/transmissions 1}  ; Covered by range 1
                        {::specs/buf b2
                         ::specs/start-pos 60
                         ::specs/length 256
                         ::specs/time (- now 2)
                         ::specs/transmissions 2} ; Range 2
                        {::specs/buf b3
                         ::specs/start-pos 316
                         ::specs/length 64
                         ::specs/time (- now 3)
                         ::specs/transmissions 3}  ; Partially covered by range 3
                        ;; Since that hasn't been ACK'd, we can'd drop any of the rest
                        {::specs/buf b4
                         ::specs/start-pos 380
                         ::specs/length 8
                         ::specs/time (- now 4)
                         ::specs/transmissions 4}   ; Covered by range 4
                        {::specs/buf b5
                         ::specs/start-pos 388
                         ::specs/length 12
                         ::specs/time (- now 5)
                         ::specs/transmissions 5}  ; Gap between 4 and 5
                        {::specs/buf b6
                         ::specs/start-pos 400
                         ::specs/length 16
                         ::specs/time (- now 6)
                         ::specs/transmissions 6}  ; Block 5
                        {::specs/buf b7
                         ::specs/start-pos 440
                         ::specs/length 32
                         ::specs/time (- now 7)
                         ::specs/transmissions 7}]]   ; block 6
      ;; I expect packet to decode to something along these lines:
       {::specs/buf buf
                 ;; Just picked something random
                 ;; TODO: Also use something that would overflow
                 ;; the 32-bit signed limit
                 ::specs/message-id msg-id
                 ::acked-message ack-id
                 ::ack-length-1 56}
      {::packet buf
       ::specs/outgoing {::specs/blocks start-blocks
                         ::specs/earliest-time 0
                         ::specs/send-acked 0
                         ::specs/send-bytes 1000   ; Something bigger than what's getting acked
                         ::specs/send-processed (* 2 bytes-acked)  ; 786
                         ::specs/total-block-transmissions 0
                         ::specs/total-blocks 0}})))
