(ns frereth-cp.message.to-parent
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef calculate-message-data-block-length
        :args ::specs/block
        :ret (s/and nat-int?
                    ;; max possible:
                    ;; k-4 is the flag for FAIL.
                    ;; + k-1 for the actual message length
                    ;; This has other restrictions based on
                    ;; the implementation details, but those
                    ;; aren't covered by the spec
                    #(< (+ K/k-1 K/error-eof) %)))
(defn calculate-message-data-block-length-flags
  [block]
  (let [len (::specs/length block)]
    (bit-or len
            (case (::specs/send-eof block)
              false 0
              ::specs/normal K/normal-eof
              ::specs/error K/error-eof))))

(s/fdef check-for-previous-block-to-resend
        :args ::specs/state
        :ret (s/nilable ::specs/state))
(defn check-for-previous-block-to-resend
  "Returns a modified state to resend, or nil if it's safe to move on to something fresh
;;;  339-356: Try re-sending an old block: (DJB)
;;;           Picks out the oldest block that's waiting for an ACK
;;;           If it's older than (+ lastpanic (* 4 rtt_timeout))
;;;              Double nsecperblock
;;;              Update trigger times
;;;           goto sendblock

"
  [{:keys [::specs/blocks
           ::specs/earliest-time
           ::specs/last-edge
           ::specs/last-panic
           ::specs/n-sec-per-block
           ::specs/recent
           ::specs/rtt-timeout]
    :as state}]
  (assert (and earliest-time
               n-sec-per-block
               recent
               rtt-timeout))
  (when (and (< recent (+ earliest-time n-sec-per-block))
             (not= 0 earliest-time)
             (>= recent (+ earliest-time rtt-timeout)))
    ;; This gets us to line 344
    ;; It finds the first block that matches earliest-time
    ;; It's going to re-send that block (it *does* exist...right?)
    ;; TODO: Need to verify that nothing fell through the cracks
    ;; But first, it might adjust some of the globals.
    (reduce (fn [{:keys [::specs/current-block-cursor]
                  :as acc}
                 block]
              (if (= earliest-time (::specs/time block))
                (reduced
                 (assoc
                  (if (> recent (+ last-panic (* 4 rtt-timeout)))
                    (assoc state
                           ::specs/n-sec-per-block (* n-sec-per-block 2)
                           ::specs/last-panic recent
                           ::specs/last-edge recent))))
                (update-in acc [::specs/current-block-cursor 0] inc)))
            (assoc state
                   ::specs/current-block-cursor [0])
            blocks)))

(defn check-for-new-block-to-send
  "Q: Is there a new block ready to send?

  357-378:  Sets up a new block to send
  Along w/ related data flags in parallel arrays"
  [{:keys [::specs/blocks
           ::specs/earliest-time
           ::specs/n-sec-per-block
           ::specs/recent
           ::specs/send-acked
           ::specs/send-bytes
           ::specs/send-eof
           ::specs/send-eof-processed
           ::specs/send-processed
           ::specs/want-ping]
    :as state}]
  (when (and (>= recent (+ earliest-time n-sec-per-block))
             (< (count blocks) K/max-outgoing-blocks)
             (or want-ping
                 ;; This next style clause is used several times in
                 ;; the reference implementation.
                 ;; The actual check is negative in context, so
                 ;; it's really a not
                 ;; if (sendeof ? sendeofprocessed : sendprocessed >= sendbytes)
                 ;; This is my best guess about how to translate that, but I
                 ;; really need to build a little C program to verify the
                 ;; syntax
                 (if send-eof
                   (not send-eof-processed)
                   (< send-bytes send-processed))))
    ;; XXX: if any Nagle-type processing is desired, do it here (--DJB)
    (let [start-pos (+ send-acked send-processed)
          block-length (max (- send-bytes send-processed)
                            K/max-block-length)
          ;; This next construct seems pretty ridiculous.
          ;; It's just assuring that (<= send-byte-buf-size (+ start-pos block-length))
          ;; The bitwise-and is a shortcut for module that used to be faster,
          ;; once upon a time (Q: does it make any difference at all these days?)
          ;; Then again, maybe it's a vital piece to the puzzle.
          ;; TODO: Get an opinion from a cryptographer.
          block-length (if (> (+ (bit-and start-pos (dec K/send-byte-buf-size))
                                 block-length)
                              K/send-byte-buf-size)
                         (- K/send-byte-buf-size (bit-and start-pos (dec K/send-byte-buf-size)))
                         block-length)
          eof (if (= send-processed send-bytes)
                send-eof
                false)
          ;; TODO: Use Pooled buffers instead!  <---
          block {::specs/buf (Unpooled/buffer 1024)  ;; Q: How big should this be?
                 ::specs/length block-length
                 ::specs/send-eof eof
                 ::specs/start-pos start-pos
                 ;; Q: What about ::specs/time?
                 ::specs/transmissions 0}
          ;; XXX: or could have the full block in post-buffer space (DJB)
          ;; "absorb" this new block -- JRG
          send-processed (+ send-processed block-length)
          ;; We're going to append this block to the end.
          ;; So we want don't want (dec length) here the
          ;; way you might expect.
          cursor [(count (::specs/blocks state))]]
      (-> state
          (update ::specs/blocks conj block)
          (update ::specs/send-processed + block-length)
          (assoc ::specs/send-eof-processed (and (= send-processed send-bytes)
                                                 send-eof
                                                 true)
                 ::specs/current-block-cursor cursor)))))

(defn pick-next-block-to-send
  [state]
  (or (check-for-previous-block-to-resend state)
;;;       357-410: Try sending a new block: (-- DJB)
                  ;; There's goto-fun overlap with resending
                  ;; a previous block -- JRG
      (check-for-new-block-to-send state)))

(defn pre-calculate-state-after-send
  "This is mostly setting up the buffer to do the send from child to parent

  Starts with line 380 sendblock:
  Resending old block will goto this

  It's in the middle of a do {} while(0) loop"
  [{:keys [::specs/block-to-send
           ::specs/next-message-id
           ::specs/recent
           ::specs/send-buf-size]
    ^ByteBuf buf ::specs/buf
    :as state}]
;;;      382-406:  Build (and send) the message packet
;;;                N.B.: Ignores most of the ACK bits
;;;                And really does not seem to match the spec
;;;                This puts the data block size at pos 46
;;;                And the data block's first byte  position
;;;                goes in position 48.
;;;                The trick happens in line 404: he starts
;;;                the write to FD9 at offset +7, which is the
;;;                len/16 byte.
;;;                So everything else is shifted right by 8 bytes

  (let [next-message-id (let [n' (inc next-message-id)]
                          ;; Stupid unsigned math
                          (if (> n' K/MAX_32_UINT)
                            1 n'))
        cursor (vec (concat [::specs/blocks] (::specs/current-block-cursor state)))
        state'
        (-> state
            (update-in (conj cursor ::specs/transmissions) inc)
            (update-in (conj cursor ::specs/time) (constantly recent))
            (assoc-in (conj cursor ::message-id) next-message-id)
            (assoc ::next-message-id next-message-id))
        block-to-send (get-in state' cursor)
        block-length (::length block-to-send)
        ;; constraints: u multiple of 16; u >= 16; u <= 1088; u >= 48 + blocklen[pos]
        ;; (-- DJB)
        ;; Set the number of bytes we're going to send for this block?
        u (condp <= (+ 64 block-length)
            ;; Stair-step the number of bytes that will get sent for this block
            ;; Suspect that this has something to do with traffic-shaping
            ;; analysis
            ;; Q: Would named constants be useful here at all?
            192 192
            320 320
            576 576
            1088 1088
            (throw (AssertionError. "block too big")))]
    (when (or (neg? block-length)
              (> K/k-1 block-length))
      (throw (AssertionError. "illegal block length")))
    ;; TODO: Use compose for this next part?

    ;; We need a prefix byte that tells the other end (/ length 16)
    ;; I'm fairly certain that this extra up-front padding
    ;; (writing it as a word) is to set
    ;; up word alignment boundaries so the actual byte copies can proceed
    ;; quickly.
    ;; This extra length byte is a key part of the reference
    ;; interface.
    ;; Q: Does it make any sense in this context?
    (.writeLong buf (quot u 16))
    (.writeInt buf next-message-id)
    ;; XXX: include any acknowledgments that have piled up (--DJB)
    (.writeBytes buf #^bytes shared/all-zeros 0 36)  ; all the ACK fields
    ;; SUCC/FAIL flag | data block size
    (.writeShort buf (calculate-message-data-block-length-flags block-to-send))
    ;; stream position of the first byte in the data block being sent
    (.writeLong buf (::start-pos block-to-send))
    ;; Copy bytes to the send-buf
    ;; TODO: make this thread-safe.
    ;; Need to save the initial read-index because we aren't ready
    ;; to discard the buffer until it's been ACK'd.
    ;; This is a fairly hefty departure from the reference implementation,
    ;; which is all based around the circular buffer concept.
    ;; I keep telling myself that a ByteBuffer will surely be fast
    ;; enough.
    (.markReaderIndex buf)
    (let [send-buf (Unpooled/buffer (.readableBytes buf))]
      (.writeBytes send-buf buf)
      (.resetReaderIndex buf)
      ;; This is the approach taken by the reference implementation
      (comment
        (b-t/byte-copy! buf (+ 8 (- u block-length)) block-length send-buf (bit-and (::start-pos block-to-send)
                                                                                    (dec send-buf-size))))
      ;; Reference implementation waits until after the actual write before setting any of
      ;; the next pieces. But it's a single-threaded process that's going to block at the write,
      ;; and this part's purely functional anyway. So it should be safe enough to set up this transition here
      (assoc state'
             ::specs/last-block-time recent
             ::specs/send-buf send-buf
             ::specs/want-ping 0))))

(defn block->parent!
  "Actually send the message block to the parent

  Corresponds to line 404 under the sendblock: label"
  [{{:keys [::specs/->parent]} ::specs/callbacks
    ^ByteBuf send-buf ::specs/send-buf
    :as state}]
  ;; Don't forget the special offset+7
  ;; Although it probably doesn't make a lot of
  ;; sense after switching to ByteBuf
  (when send-buf
    (->parent send-buf)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef maybe-send-block!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn maybe-send-block!
  "Possibly send a block from child to parent

  There's a lot going on in here."
  [state]
  (if-let [state' (pick-next-block-to-send state)]
    (let [state'' (pre-calculate-state-after-send state')]
      (block->parent! state'')
;;;      408: earliestblocktime_compute()
      ;; TODO: Honestly, we could probably shave some time/effort by
      ;; just tracking the earliest block here instead of searching for
      ;; it in check-for-previous-block-to-resend
      (dissoc (assoc state'' ::earliest-time (help/earliest-block-time (::blocks state'')))
              ::specs/send-buf))
    state))
