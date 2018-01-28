(ns frereth-cp.message.to-parent
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as shared-K]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::ok-send? boolean?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal Helpers

(s/fdef calculate-padded-size
        :args (s/cat :block ::specs/block)
        ;; constraints: u multiple of 16; u >= 16; u <= 1088; u >= 48 + blocklen[pos]
        ;; (-- DJB, line 387)
        :fn (fn [{:keys [:args :ret]}]
              (let [buf (get-in args [:block ::specs/buf])
                    length (.readableBytes buf)]
                (>= ret (+ 48 length))))
        :ret (s/and nat-int?
                    #(= 0 (mod % 16))
                    #(<= 16 %)
                    #(<= 1088 %)))
(defn calculate-padded-size
  "Set the number of bytes we're going to send for this block"
  [{:keys [::specs/buf] :as block}]
  (let [length (.readableBytes buf)]
    ;; Q: Why the extra 16?
    ;; A: Allows at least 16 bytes of padding.
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
           ;; This is supposed to be fatal, although that seems a little
           ;; heavy-handed
           (throw (AssertionError. (str length "-byte block too big"))))))

(s/fdef calculate-message-data-packet-length-flags
        :args ::specs/block
        :ret (s/and nat-int?
                    ;; max possible:
                    ;; k-4 is the flag for FAIL.
                    ;; + k-1 for the actual message length
                    ;; This has other restrictions based on
                    ;; the implementation details, but those
                    ;; aren't covered by the spec
                    #(< (+ K/k-1 K/eof-error) %)))
(defn calculate-message-data-packet-length-flags
  [{:keys [::specs/buf] :as block}]
  (let [length (.readableBytes buf)]
    (bit-or length
            (case (::specs/send-eof block)
              ::specs/false 0
              ::specs/normal K/eof-normal
              ::specs/error K/eof-error))))

(s/fdef build-message-block-description
        :args (s/cat :log-state ::log/state
                     :block-description ::specs/block)
        :ret {::specs/bs-or-eof
              ::log/state})
(defn build-message-block-description
  [log-state
   {^Long start-pos ::specs/start-pos
    ^Integer next-message-id ::specs/message-id
    ;; TODO: Switch this to either a bytes or a clojure
    ;; vector of bytes.
    ;; Then again...the bit about tracking the current
    ;; read position seems pretty worthwhile.
    ^ByteBuf buf ::specs/buf
    :as block-to-send}]
  ;;; Lines 387-402

  ;; Note that we're messing around with mutable data.
  ;; Tread carefully.
  (let [length (.readableBytes buf)]
    ;; The reference implementation does this after calculating u,
    ;; which just seems silly.
    (when (or (neg? length)
              (< K/k-1 length))
      (throw (AssertionError. (str "illegal block length: " length))))

    ;; Comment rot. Q: *Which* concern?
    ;; For now, that concern is premature optimization.
    ;; Back to regularly scheduled actual implementation comments:
    ;; Note that we also need padding.
    (let [u (calculate-padded-size block-to-send)
          ;; ByteBuf instances default to BIG_ENDIAN, which is not what CurveCP uses.
          ;; It seems like it would be better to switch to a Pooled allocator
          ;; Or, better yet, just start with a byte-array.
          ;; It's not like there are a lot of aset calls to make here.
          ;; And I have the functions in bit-twiddling that should
          ;; correspond to the proper little-endian packing.
          ;; Then again...this is something that really deserves some
          ;; hefty benchmarking.
          ;; TODO: That.
          send-buf (.order (Unpooled/buffer u)
                           java.nio.ByteOrder/LITTLE_ENDIAN)
          flag-size (calculate-message-data-packet-length-flags block-to-send)
          log-state (log/debug log-state
                               ::build-message-block-description
                               "Building a Message Block byte array for message"
                               {::flags|size flag-size
                                ::total-length u
                                ::specs/message-id next-message-id
                                ::specs/start-pos start-pos})]
      ;; Q: Is this worth switching to shared/compose?
      (.writeInt send-buf next-message-id)

      ;; XXX: include any acknowledgments that have piled up (--DJB)
      ;; Reference implementation doesn't zero anything out. It just skips these
      ;; bytes. Which seems like it can't possibly be correct.
      (.writeBytes send-buf #^bytes shared/all-zeros 0 34)  ; all the ACK fields

      ;; SUCC/FAIL flag | data block size
      (.writeShort send-buf flag-size)

      ;; stream position of the first byte in the data block being sent
      ;; If D==0 but SUCC>0 or FAIL>0 then this is the success/failure position.
      ;; i.e. the total number of bytes in the stream.
      (.writeLong send-buf start-pos)

      ;; Note that we're sending a fairly arbitrary amount of padding
      ;; This is the copy approach taken by the reference implementation
      ;; Note that he's just skipping the padding bytes rather than
      ;; filling them with zeros
      (comment
        (b-t/byte-copy! buf (+ 8 (- u block-length)) block-length send-buf (bit-and (::start-pos block-to-send)
                                                                                    (dec send-buf-size))))
      (let [data-start (- u length)
            writer-index (.writerIndex send-buf)]
        ;; Start by skipping to the appropriate start position
        (.writerIndex send-buf data-start))

      ;; Q: What happens on the other side?
      ;; A: The client, at least, is expecting a manifold stream that sends
      ;; it ByteBuf instances.
      ;; The server implementation has been waiting for me to
      ;; decide what to do here.
      ;; Which it immediately converts to byte arrays.

      ;; Need to save buf's initial read-index because we aren't ready
      ;; to discard the buffer until it's been ACK'd.
      ;; This is a fairly hefty departure from the reference implementation,
      ;; which is all based around the circular buffer concept.
      ;; I keep telling myself that a ByteBuffer will surely be fast
      ;; enough.
      ;; And...at this point, it seems a little silly for buf to be
      ;; a ByteBuf instead of ordinary byte array.
      ;; That's a concern for some other day.
      (.markReaderIndex buf)
      (.writeBytes send-buf buf)
      (.resetReaderIndex buf)
      (let [result (byte-array (.readableBytes send-buf))]
        (.readBytes send-buf result)
        {::log/state log-state
         ::specs/bs-or-eof result}))))

(s/fdef mark-block-sent
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn mark-block-sent
  "Move block from un-sent to un-acked"
  [{{:keys [::specs/send-eof
            ::specs/un-sent-blocks
            ::specs/un-ackd-blocks]
     :as outgoing} ::specs/outgoing
    :keys [::specs/message-loop-name]
    :as state}
   updated-block]
  (assert (= ::specs/un-sent-blocks
             (::specs/next-block-queue outgoing)))
  (let [block-to-move (peek un-sent-blocks)]
    (assert block-to-move (str "Trying to move non-existent block from among\n"
                               (keys outgoing)))
    (-> state
        (update ::log/state
                #(log/debug %
                            ::mark-block-sent
                            "Moving first un-sent block to un-ackd"
                            {::specs/block block-to-move
                             ::specs/un-sent-blocks un-sent-blocks
                             ::un-sent-count (count un-sent-blocks)
                             ::specs/un-ackd-blocks un-ackd-blocks
                             ::un-ackd-count (count un-ackd-blocks)
                             ::updated-block updated-block}))
        ;; Since I've had issues with this, it seems worth mentioning that
        ;; this is a sorted-set (by specs/time)
        (update-in [::specs/outgoing ::specs/un-ackd-blocks] conj updated-block)
        (update-in [::specs/outgoing ::specs/un-sent-blocks] pop))))

(s/fdef mark-block-resent
        :args (s/cat :state ::specs/state
                     :updated-block ::specs/block)
        :ret ::specs/state)
(defn mark-block-resent
  [{:keys [::specs/message-loop-name
           ::specs/outgoing]
    :as state}
   prev-block
   updated-block]
  (assert (= ::specs/un-ackd-blocks
             (::specs/next-block-queue outgoing)))
  (let [result
        (-> state
            (update ::log/state
                    #(log/debug %
                                ::mark-block-resent
                                "Resending a block"))
            (update-in [::specs/outgoing ::specs/un-ackd-blocks]
                       (fn [cur]
                         (conj (disj cur prev-block) updated-block))))]
    result))

(s/fdef pre-calculate-state-after-send
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn pre-calculate-state-after-send
  "This is mostly setting up the buffer to do the send from child to parent"
  [{:keys [::specs/message-loop-name
           ::specs/recent]
    {:keys [::specs/next-block-queue
            ::specs/send-buf-size]
     current-message-id ::specs/next-message-id
     :as outgoing} ::specs/outgoing
    log-state ::log/state
    :as state}]
  (let [prelog (utils/pre-log message-loop-name)
        label ::pre-calculate-state-after-send
        ;; Really just for timing info
        log-state (log/debug log-state
                             label
                             "Top of pre-calculate after-send")]
    (assert next-block-queue
            (str prelog
                 "No next-block-queue to tell us what to send\nAvailable:\n"
                 (keys outgoing)
                 "\nHopeful: \""
                 next-block-queue
                 "\""))
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

    (let [q (next-block-queue outgoing)
          current-message (first q)
          ;; This is where message consolidation would be
          ;; a good thing, at least for new messages.
          ;; Really should pull all the bytes we can
          ;; send (which depends on whether :client-waiting-on-response
          ;; in :flow-control has been delivered) from queue.
          ;; Although that consolidation probably doesn't make a lot
          ;; of sense here
          ;; TODO: make that happen. Somewhere.
          ;; In my message-test/bigger-outbound test, this message is
          ;; causing problems because it's trying to log a Buf with refCnt
          ;; 0.
          ;; Meaning that it got released before we got around to actually
          ;; calling log! (which now happens inside an agent).
          ;; TODO: Narrow down the culprit (current guess: one of the
          ;; un-ackd queues in outbound)
          log-state (log/debug log-state
                               label
                               "Next message source"
                               {::next-block-queue-size (count q)
                                ::specs/next-block-queue next-block-queue
                                ::specs/outgoing (shared/format-map-for-logging outgoing)})
          transmission-count (::specs/transmissions current-message)
          _ (assert transmission-count
                    (str prelog
                         "Missing ::transmissions under "
                         next-block-queue
                         " for "
                         current-message))
          ;; Q: How much time could I save right here and now by making
          ;; state transient?
          ;; (possibly using something like proteus)
          next-message-id (let [n' (inc current-message-id)]
                            ;; Stupid unsigned math
                            ;; Actually, this seems even more problematic
                            ;; than it looks at first glance.
                            ;; Really shouldn't be reusing IDs.
                            ;; Q: Does that matter?
                            (if (<= n' shared-K/max-32-int)
                              (if (= 0 n')
                                1
                                n')
                              (dec (- shared-K/max-32-int))))
          ;; It's tempting to pop that message off of whichever queue is its current home.
          ;; That doesn't make sense here/yet.
          ;; Either we're resending a previous message that never got ACK'd (in which
          ;; case it must stay exactly where it is until we *do* get an ACK), or we're
          ;; sending a new message.
          ;; If it's the latter, it *does* need to move from the un-sent queue to the
          ;; un-ackd queue.
          ;; But that's an operation to handle elsewhere.
          _ (assert current-message)
          ;; It's tempting to try to re-use a previously sent message ID for a re-send.
          ;; After all, if I send message 39, then resend it as message 50, then get
          ;; an ACK for message 39, the only way I have to correlate that to message
          ;; 50 is the stream address.
          ;; Which should be good enough.
          ;; And this seems like a better way to debug messages on the wire.
          ;; And this is the way the reference implementation works.
          state' (assoc-in state [::specs/outgoing ::specs/next-message-id] next-message-id)
          updated-message (-> current-message
                              (update ::specs/transmissions inc)
                              (assoc ::specs/time recent)
                              (assoc ::specs/message-id current-message-id))
          log-state (log/debug log-state
                               label
                               "Getting ready to build message block for message"
                               {::specs/next-message-id next-message-id
                                ::based-on updated-message})
          {buf ::specs/bs-or-eof
           log-state ::log/state} (build-message-block-description log-state
                                                                   updated-message)
          ;; Reference implementation waits until after the actual write before setting any of
          ;; the next pieces. But it's a single-threaded process that's going to block at the write,
          ;; and this part's purely functional anyway. So it should be safe enough to set up
          ;; this transition here
          result (update state'
                         ::specs/outgoing
                         (fn [cur]
                           (assoc cur
                                  ;; Q: Is it really worth tracking this separately?
                                  ;; A: Yes, absolutely.
                                  ;; It *is* readily available in un-ackd-blocks,
                                  ;; until the last block gets ACK'd.
                                  ::specs/last-block-time recent
                                  ;; Note that send-buf is just a byte-array that's
                                  ;; ready to send to the parent.
                                  ;; It's very tempting to make it a queue or set,
                                  ;; and then buffer the sends. But that's half the
                                  ;; point behind the message "package."
                                  ;; This is the culmination of that buffer/send
                                  ;; process.
                                  ;; It cannot matter whether we send duplicates
                                  ;; or a packet gets sent out of order:
                                  ;; our "parent" does not care, and the other
                                  ;; side has to cope with those problems anyway,
                                  ;; since we're using UDP (that's the other half
                                  ;; of the point)
                                  ::specs/send-buf buf
                                  ::specs/want-ping ::specs/false)))
          result (assoc result
                        ::log/state
                        (log/debug log-state
                                   label
                                   "Next block built and control state updated to"
                                   {::log/state (dissoc result ::log/state)}))]
      ;; It's tempting to split this part up to avoid the conditional.
      ;; Maybe turn the call into a multimethod.
      ;; The latter would be a mistake, since there are
      ;; really only 2 possibilities (I'm sending a new block or
      ;; resending one that had its ACK timeout)
      (if (= ::specs/un-sent-blocks next-block-queue)
        (mark-block-sent result updated-message)
        (mark-block-resent result current-message updated-message)))))

(s/fdef check-for-previous-block-to-resend
        :args ::specs/state
        :ret ::specs/state)
(defn check-for-previous-block-to-resend
  "Return value includes next-block-queue, if we should resend
;;;  339-356: Try re-sending an old block: (DJB)
;;;           Picks out the oldest block that's waiting for an ACK
;;;           If it's older than (+ lastpanic (* 4 rtt_timeout))
;;;              Double nsecperblock
;;;              Update trigger times
;;;           goto sendblock
"
  [{:keys [::specs/message-loop-name
           ::specs/recent]
    {:keys [::specs/earliest-time
            ::specs/last-panic
            ::specs/un-ackd-blocks]
     :as outgoing} ::specs/outgoing
    {:keys [::specs/last-edge
            ::specs/n-sec-per-block
            ::specs/rtt-timeout]} ::specs/flow-control
    log-state ::log/state
    :as state}]
  {:pre [(< 0 n-sec-per-block)
         recent
         rtt-timeout]}
  ;; It's tempting to make adjustments in here using now vs. recent.
  ;; Q: How much impact would that really have?
  ;; (There would definitely be *some*)
  (let [prelog (utils/pre-log message-loop-name)
        _ (assert earliest-time
                  (str prelog
                       "Missing earliest-time among"
                       (keys outgoing)))
        label ::check-for-previous-block-to-resend
        log-state (log/debug log-state
                             label
                             "Checking for a block to resend")]
    (if (and (< 0 (count un-ackd-blocks))
             (>= recent (+ earliest-time n-sec-per-block))
             (>= recent (+ earliest-time rtt-timeout)))
      (let [log-state (log/debug log-state
                                 label
                                 "It has been long enough to justify resending one of our un-ACK'd blocks"
                                 {::specs/message-loop-name message-loop-name
                                  ::un-ackd-block-count (count un-ackd-blocks)})
            ;; This gets us to line 344
            ;; It finds the first block that matches earliest-time
            ;; It's going to re-send that block (it *does* exist...right?)
            block (first un-ackd-blocks)
            state' (assoc-in state [::specs/outgoing ::specs/next-block-queue] ::specs/un-ackd-blocks)
            log-state (log/debug log-state
                                   label
                                   "Prepping flow-control updates"
                                   (assoc
                                    (select-keys (::specs/flow-control state')
                                                 [::specs/n-sec-per-block
                                                  ::specs/last-edge])
                                    ::specs/last-panic (-> state' ::specs/outgoing ::specs/last-panic)
                                    ::n-sec-per-block-class (-> state'
                                                                ::specs/flow-control
                                                                ::specs/n-sec-per-block
                                                                class)))]
        (assoc
         ;; But first, it might adjust some of the globals.
         (if (> recent (+ last-panic (* 4 rtt-timeout)))
           ;; Need to update some of the related flow-control fields
           (-> state'
               (update-in [::specs/flow-control ::specs/n-sec-per-block] * 2)
               (assoc-in [::specs/outgoing ::specs/last-panic] recent)
               (assoc-in [::specs/flow-control ::specs/last-edge] recent))
           ;; We haven't had another timeout since the last-panic.
           ;; Don't adjust those dials.
           state')
         ::log/state log-state))
      ;; Honestly, it makes more sense to consolidate the
      ;; gap-buffer with any ACKs in this message before
      ;; looking for messages to resend.
      ;; TODO: That instead.
      (update state
              ::log/state
              #(log/debug %
                          label
                          "Conditions wrong for resending any of our previously sent un-ack'd blocks"
                          {::un-ackd-count (count un-ackd-blocks)
                           ::specs/earliest-time earliest-time
                           ::specs/n-sec-per-block n-sec-per-block
                           ::specs/rtt-timeout (long rtt-timeout)
                           ::specs/recent recent})))))

(declare send-eof-buffered?)
(s/fdef ok-to-send-new?
        :args (s/cat :state ::specs/state)
        :ret (s/keys :req [::ok-send? ::log/state]))
(defn ok-to-send-new?
  [{:keys [::specs/message-loop-name
           ::specs/recent]
    {:keys [::specs/earliest-time
            ::specs/send-eof
            ::specs/strm-hwm
            ::specs/un-ackd-blocks
            ::specs/un-sent-blocks
            ::specs/want-ping]
     :as outgoing} ::specs/outgoing
    {:keys [::specs/n-sec-per-block]} ::specs/flow-control
    log-state ::log/state
    :as state}]
  #_{:pre [strm-hwm]}
  (when-not strm-hwm
    (throw (ex-info "Missing strm-hwm"
                    {::among (keys outgoing)
                     ::have strm-hwm
                     ::details outgoing})))
  ;; Centered around lines 358-361
  ;; It seems crazy that 3 lines of C expand to this much
  ;; code. But that's what happens when you add error
  ;; handling and logging.
  (let [earliest-send-time (+ earliest-time n-sec-per-block)
        un-ackd-count (count un-ackd-blocks)
        send-eof-processed (send-eof-buffered? outgoing)
        result
        (and (>= recent earliest-send-time)
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
             (< un-ackd-count K/max-outgoing-blocks)
             (or (not= ::specs/false want-ping)
                 ;; This next style clause is used several times in
                 ;; the reference implementation.
                 ;; The actual check is negative in context, so
                 ;; it's really a not
                 ;; if (sendeof ? sendeofprocessed : sendprocessed >= sendbytes)
                 ;; C programmers have assured me that it translates into
                 (if (= ::specs/false send-eof)
                   (or (< 0 un-ackd-count)
                       (< 0 (count un-sent-blocks)))
                   ;; The reference implementation sets this flag
                   ;; after checking this (line 376), just before it builds
                   ;; the message packet that it's going to send.
                   (not send-eof-processed))))]
    {::ok-send? result
     ::log/state
     (if result
       log-state
       (log/debug log-state
                  ::ok-to-send-new?
                  "Bad preconditions for sending a new block"
                  {::specs/recent recent
                   ::specs/earliest-send-time earliest-send-time
                   ::un-sent-count (count un-sent-blocks)
                   ::un-ackd-count (count un-ackd-blocks)
                   ::specs/want-ping want-ping
                   ::specs/send-eof send-eof
                   ::specs/send-eof-processed send-eof-processed
                   ::specs/strm-hwm strm-hwm}))}))

(s/fdef check-for-new-block-to-send
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn check-for-new-block-to-send
  "Q: Is there a new block ready to send?

  357-378:  Sets up a new block to send
  Along w/ related data flags in parallel arrays"
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/max-block-length
            ::specs/ackd-addr
            ::specs/send-eof
            ::specs/strm-hwm
            ::specs/un-sent-blocks]
     :as outgoing} ::specs/outgoing
    :as state}]
  (let [label ::check-for-new-block-to-send
        block-count (count un-sent-blocks)
        prelog (utils/pre-log message-loop-name)
        state (update state
                      ::log/state
                      #(log/debug %
                                  label
                                  "Does it make sense to try to send any of our unsent blocks?"
                                  {::un-sent-count block-count}))
        {:keys [::ok-send?]
         log-state ::log/state} (ok-to-send-new? state)]
    ;; This is one of those places where I'm getting confused
    ;; by mixing the new blocks with the ones that have already
    ;; been sent at least once.
    (if (and (< 0 block-count)
             ok-send?)
      ;; XXX: if any Nagle-type processing is desired, do it here (--DJB)
      ;; Consolidating smaller blocks *would* be a good idea -- JRG
      (let [block (first un-sent-blocks)
            start-pos (::specs/start-pos block)
            block-length (.readableBytes (::specs/buf block))
            ;; There's some logic going on here, around line
            ;; 361, that I didn't translate correctly.
            ;; TODO: Get back to this when I can think about
            ;; coping with EOF
            last-buffered-block (last un-sent-blocks)  ; Q: How does that perform?

            eof (if (= (+ (::specs/start-pos last-buffered-block)
                          (-> last-buffered-block ::specs/buf .readableBytes))
                       strm-hwm)
                  send-eof
                  false)]
        (-> state
            (update ::log/state
                    #(log/debug %
                                label
                                "Conditions ripe for sending a new outgoing message"))
            (assoc-in
             [::specs/outgoing ::specs/next-block-queue]
             ::specs/un-sent-blocks)))
      ;; Leave it as-is
      state)))

(s/fdef pick-next-block-to-send
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn pick-next-block-to-send
  [state]
  (let [found? (check-for-previous-block-to-resend state)]
    (if (get-in found? [::specs/outbound ::specs/next-block-queue])
      found?
;;;       357-410: Try sending a new block: (-- DJB)
      ;; There's goto-fun overlap with resending
      ;; a previous block -- JRG
      (check-for-new-block-to-send found?))))

(s/fdef block->parent!
        :args (s/cat :logger ::log/logger
                     :log-state ::log/state
                     :->parent ::specs/->parent
                     :send-buf ::specs/buf)
        :ret ::log/state)
(defn block->parent!
  "Actually send the message block to the parent"
  ;; Corresponds to line 404 under the sendblock: label
  [message-loop-name
   logger
   log-state
   ->parent
   ^bytes send-buf]
  {:pre [send-buf]}
  ;; Note that I've ditched the special offset+7
  ;; That kind of length calculation is just built
  ;; into everything on the JVM.

  ;; I keep thinking that I want to send a byte-array.
  ;; After all, the parent *does* have to encrypt
  ;; it and convert that to a Message packet.
  ;; It seems like a mistake to have already done
  ;; that conversion.
  ;; That's part of the semantic overlap:
  ;; This part is building the actual Message,
  ;; which will later get tucked into a Message
  ;; Packet as a crypto box.

  ;; There used to be more involved in this
  (let [size (count send-buf)
        succeeded? (dfrd/future (->parent send-buf))
        triggerer (utils/pre-log message-loop-name)
        [caller-log-state internal-log-state] (log/fork log-state ::block->parent!)]
    (dfrd/on-realized succeeded?
                      (fn [succeeded]
                        ;; If I'm going to set send-eof-processed,
                        ;; this is really the first time that it
                        ;; has made any sense to do so.
                        ;; Which really means that I would have to convert
                        ;; it to a deferred, and change anywhere/everywhere
                        ;; that checks its value to check (realized?)
                        ;; instead.
                        ;; That destroys functional purity, so is not
                        ;; an option.
                        (log/flush-logs! logger
                                         (log/info internal-log-state
                                                   ::succeeded
                                                   "Forwarded"
                                                   {::buffer-size size
                                                    ::specs/send-buf send-buf
                                                    ::send-from triggerer
                                                    ::success succeeded})))
                      (fn [failed]
                        (log/flush-logs! logger
                                         (log/error internal-log-state
                                                    ::failed
                                                    ;; This will trigger again, won't
                                                    ;; it? (i.e. we'll keep trying to
                                                    ;; send until we get an ACK)
                                                    "Forwarding. Q: Do we care?"
                                                    {::buffer-size size
                                                     ::specs/send-buf send-buf
                                                     ::send-from triggerer
                                                     ::failure failed}))))
    caller-log-state))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef maybe-send-block!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        :ret ::specs/state)
(defn maybe-send-block!
  "Possibly send a block from child to parent"
  [{:keys [::log/logger
           ::specs/->parent]
    :as io-handle}
   {:keys [::specs/message-loop-name]
    log-state ::log/state
    :as state}]
  {:pre [log-state]}
  (let [label ::maybe-send-block!
        log-state (if message-loop-name
                    log-state
                    (log/warn log-state
                              label
                              "Missing message-loop-name"
                              {::specs/state state}))
        log-state (log/debug log-state
                             label
                             "Picking next block to possibly send"
                             {::specs/message-loop-name message-loop-name})]
    (try
      (let [{{:keys [::specs/next-block-queue]} ::specs/outgoing
             :as state'} (pick-next-block-to-send (assoc state
                                                         ::log/state
                                                         log-state))]
        (assert (::log/state state'))
        (if next-block-queue
          (let [{{:keys [::specs/send-buf
                         ::specs/un-ackd-blocks]} ::specs/outgoing
                 log-state ::log/state
                 :as state''} (pre-calculate-state-after-send state')
                ;; Actually, calling count here tells the entire
                ;; story: I have either a byte-array or vector
                ;; rather than the ByteBuf that spec demands.
                ;; Actually, the spec is wrong.
                ;; I *want*
                ;; TODO: Fix the spec.
                ;; That probably means switching the key name.
                ;; FIXME: Comment rot. What did/do I want?
                ;; This entire comment should probably just go away,
                ;; since the code works
                n (count send-buf)
                ;; Doing a spec test here seems worrisome from a
                ;; performance perspective.
                ;; But it really does need to happen (at least at dev
                ;; time, and probably always).
                ;; And this seems like the most obvious location.
                log-state (as-> (if (s/valid? ::specs/send-buf send-buf)
                                  log-state
                                  (log/warn log-state
                                            label
                                            "Illegal outgoing buffer"
                                            {::problem (s/explain-data ::specs/send-buf send-buf)
                                             ::specs/message-loop-name message-loop-name}))
                              log-state
                            (log/debug log-state
                                       label
                                       "Sending bytes to parent"
                                       {::buffer-size n
                                        ::specs/message-loop-name message-loop-name
                                        ::specs/send-buf send-buf})
                            ;; TODO: This includes one of the side-effects that I really should
                            ;; be accumulating rather than calling willy-nilly.
                            (block->parent! message-loop-name logger log-state ->parent send-buf)
                            (log/debug log-state
                                       label
                                       (str "Calculating earliest time among un-ACK'd block(s)"
                                            "\n(totally distinct from un-sent)")
                                       {::un-ackd-block-count (count un-ackd-blocks)
                                        ::un-sent-block-count (count (get-in state''
                                                                             [::specs/outgoing ::specs/un-sent-blocks]))
                                        ::specs/message-loop-name message-loop-name}))
                {:keys [::specs/earliest-time]
                 log-state ::log/state} (help/earliest-block-time message-loop-name log-state un-ackd-blocks)]
;;;      408: earliestblocktime_compute()
            (-> (assoc state'' ::log/state log-state)
                (assoc-in [::specs/outgoing ::specs/earliest-time] earliest-time)
                (update ::specs/outgoing dissoc ::specs/next-block-queue)))
          ;; To make traffic analysis more difficult for bad guys, should intermittently
          ;; send meaningless garbage when nothing else is available.
          ;; TODO: Lots of research to make sure I do this correctly.
          ;; (The obvious downside is increased bandwidth)
          (update state
                  ::log/state
                  #(log/debug %
                              label
                              "Nothing to send"
                              (dissoc  state ::log/state)))))
      (catch Exception ex
        (update state
                ::log/state
                #(log/exception %
                                ex
                                label
                                "Trying to send message block to parent"
                                {::specs/message-loop-name message-loop-name}))))))

(s/fdef send-eof-buffered?
        :args (s/cat :outgoing ::specs/outgoing)
        :ret boolean?)
(defn send-eof-buffered?
  "Has the EOF packet been set up to send?"
  [{:keys [::specs/send-eof
           ::specs/un-sent-blocks]
    :as outgoing}]
  (and (not= send-eof ::specs/false)
       (empty? un-sent-blocks)))
