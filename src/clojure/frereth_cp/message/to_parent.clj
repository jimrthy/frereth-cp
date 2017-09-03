(ns frereth-cp.message.to-parent
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as shared-K])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef calculate-padded-size
        :args (s/cat :block ::specs/block)
        ;; constraints: u multiple of 16; u >= 16; u <= 1088; u >= 48 + blocklen[pos]
        ;; (-- DJB, line 387)
        :fn (fn [{:keys [:args :ret]}]
              (let [{:keys [::specs/length] :as block} (:block args)]
                (>= ret (+ 48 length))))
        :ret (s/and nat-int?
                    #(= 0 (mod % 16))
                    #(<= 16 %)
                    #(<= 1088 %)))
(defn calculate-padded-size
  [{:keys [::specs/length] :as block}]
  ;; Set the number of bytes we're going to send for this block
  ;; Q: Why the extra 16?
  ;; Current guess: Allows at least 16 bytes of padding.
  ;; Then we'll round up to an arbitrary length.
  (condp >= (+ K/header-length K/min-padding-length length)
    ;; Stair-step the number of bytes that will get sent for this block
    ;; This probably has something to do with traffic-shaping
    ;; analysis
    ;; Q: Would named constants be useful here at all?
    192 192
    320 320
    576 576
    1088 1088
    (throw (AssertionError. "block too big"))))

(s/fdef calculate-message-data-packet-length-flags
        :args ::specs/block
        :ret (s/and nat-int?
                    ;; max possible:
                    ;; k-4 is the flag for FAIL.
                    ;; + k-1 for the actual message length
                    ;; This has other restrictions based on
                    ;; the implementation details, but those
                    ;; aren't covered by the spec
                    #(< (+ K/k-1 K/error-eof) %)))
(defn calculate-message-data-packet-length-flags
  [{:keys [::specs/length] :as block}]
  (bit-or length
          (case (::specs/send-eof block)
            false 0
            ::specs/normal K/normal-eof
            ::specs/error K/error-eof)))

(s/fdef build-message-block
        :args (s/cat :next-message-id nat-int?
                     :block-to-send ::specs/block)
        :ret bytes?)
(defn build-message-block
  ^bytes [^Integer next-message-id
          {^Long start-pos ::specs/start-pos
           ;; TODO: Switch this to either a bytes or a clojure
           ;; vector of bytes.
           ;; Then again...the bit about tracking the current
           ;; read position seems pretty worthwhile.
           ^ByteBuf buf ::specs/buf
           :keys [::specs/length]
           :as block-to-send}]
  ;;; Lines 387-402
  ;;; Q: make this thread-safe?

  ;; It's tempting to use a direct buffer here, but that temptation
  ;; would probably be wrong.
  ;; Since this has to be converted to a ByteArray so it can be
  ;; encrypted.
  ;; OTOH, there's Norman Mauer's "Best Practices" that include
  ;; the points about "Use pooled direct buffers" and "Write
  ;; direct buffers...always."

  ;; For now, that concern is premature optimization
  ;; Back to regularly scheduled actual implementation comments:
  ;; Note that we also need padding.
  (let [u (calculate-padded-size block-to-send)
        ;; Q: Why does this happen after calculating u?
        _ (when (or (neg? length)
                    (< K/k-1 length))
            (throw (AssertionError. (str "illegal block length: " length))))
        ;; ByteBuf instances default to BIG_ENDIAN, which is not what CurveCP uses
        ;; It seems like it would be better to switch to a Pooled allocator
        ;; Or, better yet, just start with a byte-array.
        ;; It's not like there are a lot of aset calls to make here.
        ;; And I have the functions in bit-twiddling that should
        ;; correspond to the proper little-endian packing.
        ;; Then again...this is something that really deserves some
        ;; hefty bookmarking.
        ;; TODO: That.
        send-buf (.order (Unpooled/buffer u)
                         java.nio.ByteOrder/LITTLE_ENDIAN)]
    ;; Q: Is this worth switching to shared/compose?
    (.writeInt send-buf next-message-id)
    ;; XXX: include any acknowledgments that have piled up (--DJB)
    ;; Reference implementation doesn't zero anything out. It just skips these
    ;; bytes. Which seems like it can't possibly be correct.
    (.writeBytes send-buf #^bytes shared/all-zeros 0 34)  ; all the ACK fields
    ;; SUCC/FAIL flag | data block size
    (.writeShort send-buf (calculate-message-data-packet-length-flags block-to-send))
    ;; stream position of the first byte in the data block being sent
    ;; If D==0 but SUCC>0 or FAIL>0 then this is the success/failure position.
    ;; i.e. the total number of bytes in the stream.
    (.writeLong send-buf start-pos)
    ;; Note that we're a fairly arbitrary amount of padding
    (let [data-start (- u length)
          writer-index (.writerIndex send-buf)]

      ;; This is the copy approach taken by the reference implementation
      ;; Note that he's just skipping the padding bytes rather than
      ;; filling them with zeros
      (comment
        (b-t/byte-copy! buf (+ 8 (- u block-length)) block-length send-buf (bit-and (::start-pos block-to-send)
                                                                                    (dec send-buf-size))))
      (.writerIndex send-buf data-start))

    ;; Need to save buf's initial read-index because we aren't ready
    ;; to discard the buffer until it's been ACK'd.
    ;; This is a fairly hefty departure from the reference implementation,
    ;; which is all based around the circular buffer concept.
    ;; I keep telling myself that a ByteBuffer will surely be fast
    ;; enough.
    (.markReaderIndex buf)
    (.writeBytes send-buf buf)
    (.resetReaderIndex buf)
    (.array send-buf)))

(s/fdef pre-calculate-state-after-send
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn pre-calculate-state-after-send
  "This is mostly setting up the buffer to do the send from child to parent

  Starts with line 380 sendblock:
  Resending old block will goto this

  It's in the middle of a do {} while(0) loop"
  [{:keys [::specs/recent]
    {:keys [::specs/current-block-cursor
            ::specs/next-message-id
            ::specs/send-buf-size]} ::specs/outgoing
    :as state}]
;;;      382-404:  Build the message packet
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
                          (if (> n' shared-K/max-32-uint)
                            1 n'))
        cursor (vec (concat [::specs/blocks] current-block-cursor))
        state'
        (-> state
            (update-in (conj cursor ::specs/transmissions) inc)
            (update-in (conj cursor ::specs/time) (constantly recent))
            (assoc-in (conj cursor ::specs/message-id) next-message-id)
            (assoc-in [::specs/outgoing ::specs/next-message-id] next-message-id))
        block-to-send (get-in state' cursor)
        buf (build-message-block next-message-id block-to-send)]

    ;; Reference implementation waits until after the actual write before setting any of
    ;; the next pieces. But it's a single-threaded process that's going to block at the write,
    ;; and this part's purely functional anyway. So it should be safe enough to set up this transition here
    (update state'
            ::specs/outgoing
            (fn [cur]
              (assoc cur
                     ::specs/last-block-time recent
                     ::specs/send-buf buf
                     ::specs/want-ping 0)))))

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
  [{:keys [::specs/recent]
    {:keys [::specs/blocks
            ::specs/earliest-time
            ::specs/last-panic]} ::specs/outgoing
    {:keys [::specs/last-edge
            ::specs/n-sec-per-block
            ::specs/rtt-timeout]} ::specs/flow-control
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
    (reduce (fn [{{:keys [::specs/current-block-cursor]} ::specs/outgoing
                  :as acc}
                 block]
              (if (= earliest-time (::specs/time block))
                ;; We found the block that interests up.
                (reduced
                 (assoc
                  (if (> recent (+ last-panic (* 4 rtt-timeout)))
                    ;; Need to update some of the related flow-control fields
                    (-> state
                        (update-in [::specs/flow-control ::specs/n-sec-per-block] * 2)
                        (assoc-in [::specs/outgoing ::specs/last-panic] recent)
                        (assoc-in [::specs/flow-control ::specs/last-edge] recent))
                    ;; We haven't had another timeout since the last-panic.
                    ;; Don't adjust those dials.
                    state)))
                ;; We still haven't found what we're looking for.
                ;; Proceed to the next block
                (update-in acc [::specs/outgoing ::specs/current-block-cursor 0] inc)))
            (assoc-in state
                      [::specs/outgoing ::specs/current-block-cursor]
                      [0])
            blocks)))

(defn check-for-new-block-to-send
  "Q: Is there a new block ready to send?

  357-378:  Sets up a new block to send
  Along w/ related data flags in parallel arrays"
  [{:keys [::specs/recent]
    {:keys [::specs/blocks
            ::specs/earliest-time
            ::specs/max-block-length
            ::specs/send-acked
            ::specs/send-bytes
            ::specs/send-eof
            ::specs/send-eof-processed
            ::specs/send-processed
            ::specs/want-ping]
     :as outgoing} ::specs/outgoing
    {:keys [::specs/n-sec-per-block]} ::specs/flow-control
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
                            max-block-length)
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
          block {::specs/buf (Unpooled/buffer K/k-1)  ;; Q: How big should this be?
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
          cursor [(count blocks)]]
      (-> state
          ;; TODO: Just update inside specs/outgoing and merge that back in
          ;; over what we currently have
          (update ::specs/outgoing
                  (fn [cur]
                    (-> cur
                        (update ::specs/blocks conj block)
                        (update ::specs/send-processed + block-length)
                        (assoc ::specs/send-eof-processed (and (= send-processed send-bytes)
                                                               send-eof)))))
          (assoc-in [::specs/outgoing ::specs/current-block-cursor] cursor)))))

(defn pick-next-block-to-send
  [state]
  (or (check-for-previous-block-to-resend state)
;;;       357-410: Try sending a new block: (-- DJB)
                  ;; There's goto-fun overlap with resending
                  ;; a previous block -- JRG
      (check-for-new-block-to-send state)))

(defn block->parent!
  "Actually send the message block to the parent

  Corresponds to line 404 under the sendblock: label"
  [{{:keys [:specs/->parent]
     ^ByteBuf send-buf ::specs/send-buf} ::specs/outgoing
    :as state}]
  ;; Note that I've ditched the special offset+7
  ;; That kind of length calculation is just built
  ;; into everything on the JVM.
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
    (let [state'' (pre-calculate-state-after-send state')
          buf (build-message-block state'')]
      (block->parent! buf)
;;;      408: earliestblocktime_compute()
      ;; TODO: Honestly, we could probably shave some time/effort by
      ;; just tracking the earliest block here instead of searching for
      ;; it in check-for-previous-block-to-resend
      (assoc-in state''
                [::specs/outgoing ::specs/earliest-time]
                (help/earliest-block-time (get-in state'' [::specs/outgoing ::specs/blocks]))))
    state))
