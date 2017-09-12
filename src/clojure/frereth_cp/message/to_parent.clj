(ns frereth-cp.message.to-parent
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as shared-K]
            [frereth-cp.util :as utils])
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
  (condp >= #_(+ K/header-length K/min-padding-length length) length
    ;; Stair-step the number of bytes that will get sent for this block
    ;; This probably has something to do with traffic-shaping
    ;; analysis
    ;; Q: Would named constants be useful here at all?
    192 192
    320 320
    576 576
    1088 1088
    ;; This is supposed to be fatal, although that seems a little
    ;; heavy-handed
    (throw (AssertionError. (str length "-byte block too big")))))

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
  "This is mostly setting up the buffer to do the send from child to parent"
  [{:keys [::specs/recent]
    {:keys [::specs/current-block-cursor
            ::specs/send-buf-size]
     current-message-id ::specs/next-message-id
     :as outgoing} ::specs/outgoing
    :as state}]
  ;; Starts with line 380 sendblock:
  ;; Resending old block will goto this
  ;; It's in the middle of a do {} while(0) loop

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
  (assert current-block-cursor
          (str "No current-block-cursor to tell us what to send\nAvailable:\n"
               (keys outgoing)))
  (let [next-message-id (let [n' (inc current-message-id)]
                          ;; Stupid unsigned math
                          ;; Actually, this seems problematic.
                          ;; Really shouldn't be reusing IDs.
                          ;; Q: Does that matter?
                          (if (> n' shared-K/max-32-uint)
                            ;; TODO: Just roll with the negative IDs. The only
                            ;; one that's special is 0
                            1 n'))
        cursor (vec (concat [::specs/outgoing ::specs/blocks] current-block-cursor))
        _ (assert (get-in state (conj cursor ::specs/transmissions))
                  (str "Missing ::transmissions under "
                       cursor
                       "\nbased on "
                       current-block-cursor
                       "\nHave:\n"
                       (let [current-block (get-in state cursor)]
                         (if current-block
                           (utils/pretty current-block)
                           (str "Missing current block completely, but do have "
                                (count (get-in state [::specs/outgoing ::specs/blocks]))
                                " blocks we *could* have been looking at")))))
        state'
        (-> state
            (update-in (conj cursor ::specs/transmissions) inc)
            (update-in (conj cursor ::specs/time) (constantly recent))
            (assoc-in (conj cursor ::specs/message-id) current-message-id)
            (assoc-in [::specs/outgoing ::specs/next-message-id] next-message-id))
        block-to-send (get-in state' cursor)
        _ (log/debug "Getting ready to build next message block for message "
                     current-message-id
                     "\nbased on:\n"
                     (utils/pretty block-to-send))
        buf (build-message-block current-message-id block-to-send)]

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
  {:pre [earliest-time
         n-sec-per-block
         recent
         rtt-timeout]}
  (log/debug "Checking for a block to resend")
  (when (and (not= 0 earliest-time)
             (< recent (+ earliest-time n-sec-per-block))
             (>= recent (+ earliest-time rtt-timeout)))
    (log/debug "It's been long enough to justify resending")
    ;; This gets us to line 344
    ;; It finds the first block that matches earliest-time
    ;; It's going to re-send that block (it *does* exist...right?)
    ;; TODO: Seems like just keeping a sorted-map with timestamps
    ;; for keys would be more efficient. But that probably depends
    ;; on how big these queues get.
    ;; TODO: Need to verify that nothing fell through the cracks
    ;; But first, it might adjust some of the globals.
    (reduce (fn [{{:keys [::specs/current-block-cursor]} ::specs/outgoing
                  :as acc}
                 block]
              (if (= earliest-time (::specs/time block))
                (do
                  (log/info "Found earliest old block to resend")
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
                      state))))
                ;; We still haven't found what we're looking for.
                ;; Proceed to the next block
                (update-in acc [::specs/outgoing ::specs/current-block-cursor 0] inc)))
            (assoc-in state
                      [::specs/outgoing ::specs/current-block-cursor]
                      [0])
            blocks)))

(defn remove-unsent
  "Get the blocks that have been put onto the wire"
  [blocks]
  (filter (fn [block]
            (not= 0 (::specs/transmissions block)))
          blocks))

(s/fdef check-for-new-block-to-send
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
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
  (when (< 0 (count blocks))
    (if (and (>= recent (+ earliest-time n-sec-per-block))
             ;; If we have too many outgoing blocks being
             ;; tracked, don't put more in flight.
             ;; There's obviously something going wrong
             ;; somewhere.
             ;; Reference implementation tracks them all.
             ;; However: if the client dumps 256K worth of
             ;; message on us in one fell swoop, this check
             ;; would guarantee that none of them ever get sent.
             ;; So only consider the ones that have already
             ;; been put on the wire.
             (< (count (remove-unsent blocks)) K/max-outgoing-blocks)
             (or want-ping
                 ;; This next style clause is used several times in
                 ;; the reference implementation.
                 ;; The actual check is negative in context, so
                 ;; it's really a not
                 ;; if (sendeof ? sendeofprocessed : sendprocessed >= sendbytes)
                 ;; C programmers have assured me that it translates into
                 (if send-eof
                   (not send-eof-processed)
                   (< send-processed send-bytes))))
      ;; XXX: if any Nagle-type processing is desired, do it here (--DJB)
      (let [start-pos (+ send-acked send-processed)
            block-length (max (- send-bytes send-processed)
                              max-block-length)
            ;; This next construct seems pretty ridiculous.
            ;; It's just assuring that (<= send-byte-buf-size (+ start-pos block-length))
            ;; The bitwise-and is a shortcut for modulo that used to be faster,
            ;; once upon a time.
            ;; Q: does it make any difference at all these days?
            ;; A: According to stack overflow, the modulo will get optimized
            ;; to bitwise logic by any decent compiler.
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
            ;; XXX: or could have the full block in post-buffer space (DJB)
            ;; "absorb" this new block -- JRG
            send-processed (+ send-processed block-length)
            ;; Want to send a new block.
            ;; In a single-threaded world where we're processing one
            ;; message packet/block at a time, that will always be the last.
            ;; In this scenario, it's really the first block with a transmission
            ;; count of 0.
            cursor [(reduce (fn [acc block]
                              (if (= 0 (::specs/transmissions block))
                                (reduced acc)
                                (inc acc)))
                            0
                            blocks)]]
        (log/debug "Conditions ripe for sending a new outgoing message")
        (-> state
            (assoc-in [::specs/outgoing ::specs/current-block-cursor] cursor)))
      (log/debug (str "Bad preconditions for sending a new block:\n"
                      "recent: " recent " <? " (+ earliest-time n-sec-per-block)
                      "\nBlock count: " (count blocks)
                      "\nwant-ping: " want-ping
                      "\nsend-eof: " send-eof
                      "\n\tsend-eof-processed: " send-eof-processed
                      "\n\tsend-processed: " send-processed
                      "\nsend-bytes: " send-bytes)))))

(s/fdef pick-next-block-to-send
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
(defn pick-next-block-to-send
  [state]
  ;; TODO: Instead of returning nil on nothing to do, just
  ;; do something like setting a nil cursor.
  ;; That should simplify the caller.
  (or (check-for-previous-block-to-resend state)
;;;       357-410: Try sending a new block: (-- DJB)
                  ;; There's goto-fun overlap with resending
                  ;; a previous block -- JRG
      (check-for-new-block-to-send state)))

(s/fdef block->parent!
        :args (s/cat :send-buf ::specs/buf)
        :ret any?)
(defn block->parent!
  "Actually send the message block to the parent

  Corresponds to line 404 under the sendblock: label"
  [->parent send-buf]
  {:pre [send-buf]}
  ;; Note that I've ditched the special offset+7
  ;; That kind of length calculation is just built
  ;; into everything on the JVM.

  ;; Note that, really, I want to send a byte-array
  (->parent send-buf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef maybe-send-block!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn maybe-send-block!
  "Possibly send a block from child to parent"
  [state]
  ;; I could have pick-next-block-to-send just adjust the state
  ;; to signal whether there *is* a next block to send, instead
  ;; of having it return nil like this.
  ;; That seems like a better API.
  ;; TODO: Make that so.
  (if-let [state' (pick-next-block-to-send state)]
    (let [state'' (pre-calculate-state-after-send state')
          buf (get-in state'' [::specs/outgoing ::specs/send-buf])
          ->parent (get-in state'' [::specs/outgoing ::specs/->parent])]
      (log/debug "Sending" buf "to parent")
      (block->parent! ->parent buf)
;;;      408: earliestblocktime_compute()
      ;; TODO: Honestly, we could probably shave some time/effort by
      ;; just tracking the earliest block here instead of searching for
      ;; it in check-for-previous-block-to-resend
      (-> state''
          (assoc-in
           [::specs/outgoing ::specs/earliest-time]
           (help/earliest-block-time (get-in state'' [::specs/outgoing ::specs/blocks])))
          (update ::specs/outgoing dissoc ::specs/current-block-cursor)))
    state))
