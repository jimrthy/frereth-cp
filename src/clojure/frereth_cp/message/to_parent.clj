(ns frereth-cp.message.to-parent
  (:require [clojure.pprint :refer [cl-format]]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as shared-K]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

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
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :block-description ::specs/block)
        :ret bytes?)
(defn build-message-block-description
  ^ByteBuf [message-loop-name
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
          flag-size (calculate-message-data-packet-length-flags block-to-send)]
      (log/debug (utils/pre-log message-loop-name)
                 (str "Building a Message Block byte array for message "
                      next-message-id
                      "\nTotal length: " u
                      "\nSize | Flags: " flag-size
                      "\nStart Position: " start-pos))

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
        result))))

(s/fdef mark-block-sent
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn mark-block-sent
  "Move block from un-sent to un-acked"
  [{{:keys [::specs/un-sent-blocks
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
    (log/debug (utils/pre-log message-loop-name)
               (str "Moving first unsent block\n("
                    ;; TODO: Verify that this has a ::specs/time key and value
                    block-to-move
                    ")\nfrom\na queue of "
                    (count un-sent-blocks)
                    " unsent\nto join "
                    (count un-ackd-blocks)
                    " un-ACK'd blocks among\n"
                    un-ackd-blocks
                    "\nas\n"
                    updated-block))
    (-> state
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
  (log/debug (str message-loop-name ": Resending a block"))
  (assert (= ::specs/un-ackd-blocks
             (::specs/next-block-queue outgoing)))
  (update-in state
             [::specs/outgoing ::specs/un-ackd-blocks]
             (fn [cur]
               (conj (disj cur prev-block) updated-block))))

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
    :as state}]
  (let [pre-log (utils/pre-log message-loop-name)]
    ;; Really just for timing info
    (log/debug pre-log
               "Top of pre-calculate after-send")
    (assert next-block-queue
            (str pre-log
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
    (let [q (get-in state [::specs/outgoing next-block-queue])
          current-message (first q)]
      ;; This is where message correlation would be
      ;; a good thing, at least for new messages.
      ;; Really should pull pull all the bytes we can
      ;; send (which depends on whether :client-waiting-on-response
      ;; in :flow-control has been delivered) from q.
      ;; Although that consolidation probably doesn't make a lot
      ;; of sense here
      ;; TODO: make that happen
      (log/debug pre-log
                 (str "Next message should come from "
                      (count q)
                      " block(s) in\n"
                      next-block-queue
                      "\ninside\n"
                      (::specs/outgoing state)))
      (let [transmission-count (::specs/transmissions current-message)]
        (assert transmission-count
                (str pre-log
                     "Missing ::transmissions under "
                     next-block-queue
                     " for "
                     current-message)))
      ;; Q: How much time could I save right here and now by making
      ;; state transient?
      ;; (possibly using something like proteus)
      (let [next-message-id (let [n' (inc current-message-id)]
                              ;; Stupid unsigned math
                              ;; Actually, this seems even more problematic
                              ;; than it looks at first glance.
                              ;; Really shouldn't be reusing IDs.
                              ;; Q: Does that matter?
                              (if (> n' shared-K/max-32-uint)
                                ;; TODO: Just roll with the negative IDs. The only
                                ;; one that's special is 0
                                1 n'))]
        ;; It's tempting to pop that message off of whichever queue is its current home.
        ;; That doesn't make sense here/yet.
        ;; Either we're resending a previous message that never got ACK'd (in which
        ;; case it must stay exactly where it is until we *do* get an ACK), or we're
        ;; sending a new message.
        ;; If it's the latter, it *does* need to move from the un-sent queue to the
        ;; un-ackd queue.
        ;; But that's an operation to handle elsewhere.
        (assert current-message)
        ;; It's tempting to try to re-use a previously sent message ID for a re-send.
        ;; After all, if I send message 39, then resend it as message 50, then get
        ;; an ACK for message 39, the only way I have to correlate that to message
        ;; 50 is the stream address.
        ;; Which should be good enough.
        ;; And this seems like a better way to debug messages on the wire.
        ;; And this is the way the reference implementation works.
        (let [state' (assoc-in state [::specs/outgoing ::specs/next-message-id] next-message-id)
              updated-message (-> current-message
                                  (update ::specs/transmissions inc)
                                  (assoc ::specs/time recent)
                                  (assoc ::specs/message-id current-message-id))]
          ;; There's a 4-6 ms gap in logs between log entry message and this one.
          ;; FIXME: Profile to see where that time went
          ;; alt: try converting current-message to a transient before using it to
          ;; build updated message
          ;; cheaper alt: eliminate the call to pretty below
          ;; Q: How much difference did that make?
          (log/debug pre-log
                     (str "Getting ready to build message block for message "
                          current-message-id
                          "\nbased on:\n")
                     #_(utils/pretty updated-message)
                     updated-message)
          (let [buf (build-message-block-description message-loop-name
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
                                        ::specs/want-ping ::specs/false)))]
            (log/debug pre-log
                       "Next block built and control state updated to"
                       result)
            ;; It's tempting to split this part up to avoid the conditional.
            ;; Maybe turn the call into a multimethod.
            ;; The latter would be a mistake, since there are
            ;; really only 2 possibilities (I'm sending a new block or
            ;; resending one that had its ACK timeout)
            (if (= ::specs/un-sent-blocks next-block-queue)
              (mark-block-sent result updated-message)
              (mark-block-resent result current-message updated-message))))))))

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
    :as state}]
  {:pre [n-sec-per-block
         recent
         rtt-timeout]}
  ;; It's tempting to make adjustments in here using now vs. recent.
  ;; Q: How much impact would that really have?
  ;; (There would definitely be *some*)
  (let [prelog (utils/pre-log message-loop-name)]
    (assert earliest-time
            (str prelog
                 "Missing earliest-time among"
                 (keys outgoing)))
    (log/debug prelog "Checking for a block to resend")
    (if (and (< 0 (count un-ackd-blocks))
             (>= recent (+ earliest-time n-sec-per-block))
             (>= recent (+ earliest-time rtt-timeout)))
      (do
        (log/debug prelog
                   "It has been long enough to justify resending one of our"
                   (count un-ackd-blocks)
                   "un-ACK'd blocks")
        ;; This gets us to line 344
        ;; It finds the first block that matches earliest-time
        ;; It's going to re-send that block (it *does* exist...right?)
        (let [block (first un-ackd-blocks)
              state' (assoc-in state [::specs/outgoing ::specs/next-block-queue] ::specs/un-ackd-blocks)]
          ;; But first, it might adjust some of the globals.
          (if (> recent (+ last-panic (* 4 rtt-timeout)))
            ;; Need to update some of the related flow-control fields
            (-> state'
                (update-in [::specs/flow-control ::specs/n-sec-per-block] * 2)
                (assoc-in [::specs/outgoing ::specs/last-panic] recent)
                (assoc-in [::specs/flow-control ::specs/last-edge] recent))
            ;; We haven't had another timeout since the last-panic.
            ;; Don't adjust those dials.
            state')))
      (do
        ;; Honestly, it makes more sense to consolidate the
        ;; gap-buffer with any ACKs in this message before
        ;; looking for messages to resend.
        ;; TODO: That instead.
        (log/debug prelog
                   (cl-format nil
                              (str
                               "Conditions wrong"
                               " for resending any of our ~d previously "
                               "sent un-ack'd blocks, based on"
                               "\nEarliest time: ~:d"
                               "\nnanoseconds per block: ~:d"
                               "\nrtt-timeout: ~:d"
                               "\nrecent: ~:d")
                              (count un-ackd-blocks)
                              earliest-time
                              n-sec-per-block
                              (int rtt-timeout)
                              recent))
        state))))

(s/fdef ok-to-send-new?
        :args (s/cat :state ::specs/state)
        :ret boolean?)
(defn ok-to-send-new?
  [{:keys [::specs/message-loop-name
           ::specs/recent]
    {:keys [::specs/earliest-time
            ::specs/send-eof
            ::specs/send-eof-processed
            ::specs/strm-hwm
            ::specs/un-ackd-blocks
            ::specs/un-sent-blocks
            ::specs/want-ping]
     :as outgoing} ::specs/outgoing
    {:keys [::specs/n-sec-per-block]} ::specs/flow-control
    :as state}]
  #_{:pre [strm-hwm]}
  (when-not strm-hwm
    (throw (ex-info "Missing strm-hwm"
                    {::among (keys outgoing)
                     ::have strm-hwm
                     ::details outgoing})))
  (let [result
        (and (>= recent (+ earliest-time n-sec-per-block))
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
             (< (count un-ackd-blocks) K/max-outgoing-blocks)
             (or (not= ::specs/false want-ping)
                 ;; This next style clause is used several times in
                 ;; the reference implementation.
                 ;; The actual check is negative in context, so
                 ;; it's really a not
                 ;; if (sendeof ? sendeofprocessed : sendprocessed >= sendbytes)
                 ;; C programmers have assured me that it translates into
                 (if (not= ::specs/false send-eof)
                   (not send-eof-processed)
                   (or (< 0 (count un-ackd-blocks))
                       (< 0 (count un-sent-blocks))))))]
    (when-not result
      (let [fmt (str "~a: Bad preconditions for sending a new block:\n"
                     "recent: ~:d <? ~:d\n"
                     "New block count: ~d"
                     "\nPreviously sent block count: ~d"
                     "\nwant-ping: ~d"
                     "\nsend-eof: ~a"
                     "\n\tsend-eof-processed: ~a"
                     "\n\tstrm-hwm: ~:d")]
        (log/debug (cl-format nil
                              fmt
                              message-loop-name
                              recent
                              (+ earliest-time n-sec-per-block)
                              (count un-sent-blocks)
                              (count un-ackd-blocks)
                              want-ping
                              send-eof
                              send-eof-processed
                              strm-hwm))))
    result))

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
  (let [block-count (count un-sent-blocks)
        prelog (utils/pre-log message-loop-name)]
    ;; This is one of those places where I'm getting confused
    ;; by mixing the new blocks with the ones that have already
    ;; been sent at least once.
    (log/debug prelog
               "Does it make sense to try to send any of our"
               block-count
               "unsent blocks?")
    (if (< 0 block-count)
      (if (ok-to-send-new? state)
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
          (log/debug prelog
                     "Conditions ripe for sending a new outgoing message")
          (assoc-in state
                    [::specs/outgoing ::specs/next-block-queue]
                    ::specs/un-sent-blocks))
        ;; Leave it as-is
        state))))

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
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :->parent ::specs/->parent
                     :send-buf ::specs/buf)
        :ret any?)
(defn block->parent!
  "Actually send the message block to the parent"
  ;; Corresponds to line 404 under the sendblock: label
  [message-loop-name
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

  ;; I have what seems to be a deadlock, in my handshake
  ;; test, which probably stems from callin this synchronously.
  ;; This one's different than ->child.
  ;; I don't really care very much whether it succeeds. Half
  ;; the point behind the entire message "package" is
  ;; buffering up sends for when they fail.
  ;; I've run across a couple of successful approaches
  ;; for coping with this.
  ;; 1) Just put the send into its own thread
  ;; 2) Convert this part to an enqueue. Have a dedicated
  ;; thread that runs dequeue and does the send.

  ;; Approach 2) has the same problem as this, almost:
  ;; time spent on the library client side blocks that thread.
  ;; In particular, for the specific test failure that I
  ;; currently see, it gets blocked by sending "too many"
  ;; requests in a row.

  ;; Honestly, I need to figure out why that's causing problems
  ;; and solve it.
  ;; TODO: Take the time to do that.

  ;; For now:
  ;; Try putting this inside a dfrd/future
  ;; TODO: Compare/contrast with using a regular future
  (let [size (count send-buf)
        succeeded? (dfrd/future (->parent send-buf))
        triggerer (utils/pre-log message-loop-name)]
    (dfrd/on-realized succeeded?
                      (fn [succeeded]
                        (log/info (utils/pre-log message-loop-name)
                                  (str size
                                       " bytes in "
                                       send-buf
                                       " forwarded to parent, triggered by\n"
                                       triggerer
                                       succeeded)))
                      (fn [failed]
                        (log/error failed
                                   (utils/pre-log message-loop-name)
                                   (str "Failed to forward "
                                        size
                                        " bytes in "
                                        send-buf
                                        " to parent.\n"
                                        "Probably don't care.\n"
                                        "Triggered by\n"
                                        triggerer))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef maybe-send-block!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        :ret ::specs/state)
(defn maybe-send-block!
  "Possibly send a block from child to parent"
  [{:keys [::specs/->parent]
    :as io-handle}
   {:keys [::specs/message-loop-name]
    :as state}]
  (let [{{:keys [::specs/next-block-queue]} ::specs/outgoing
         :as state'} (pick-next-block-to-send state)
        prelog (utils/pre-log message-loop-name)]
    (if next-block-queue
      (let [{{:keys [::specs/send-buf
                     ::specs/un-ackd-blocks]} ::specs/outgoing
             :as state''} (pre-calculate-state-after-send state')
            n (count send-buf)]
        (when-not (s/valid? ::specs/send-buf send-buf)
          ;; Doing a spec test here seems worrisome from a
          ;; performance perspective.
          ;; But it really does need to happen (at least at dev
          ;; time, and probably always).
          ;; And this seems like the most obvious location.
          (log/warn prelog
                    "Illegal outgoing buffer\n"
                    (s/explain-data ::specs/send-buf send-buf)))
        (log/debug prelog
                   "Sending"
                   ;; Actually, calling count here tells the entire
                   ;; story: I have either a byte-array or vector
                   ;; rather than the ByteBuf that spec demands.
                   ;; Actually, the spec is wrong.
                   ;; I *want*
                   ;; TODO: Fix the spec.
                   ;; That probably means switching the key name.
                   n
                   "bytes to parent in"
                   send-buf)
        ;; TODO: This is one of the side-effects that I really should
        ;; be accumulating rather than calling willy-nilly.
        (block->parent! message-loop-name ->parent send-buf)
        (log/debug prelog
                   (str "Calculating earliest time among "
                        (count un-ackd-blocks)
                        " un-ACK'd block(s)"
                        ".\nThose are very distinct from the "
                        (count (get-in state'' [::specs/outgoing ::specs/un-sent-blocks]))
                        " that is/are left in un-sent-blocks"))
;;;      408: earliestblocktime_compute()

        (-> state''
            (assoc-in [::specs/outgoing ::specs/earliest-time]
                      (help/earliest-block-time message-loop-name un-ackd-blocks))
            (update ::specs/outgoing dissoc ::specs/next-block-queue)))
      (do
        ;; To aid in traffic analysis, should intermittently send meaningless
        ;; garbage when nothing else is available.
        ;; TODO: Lots of research to make sure I do this correctly.
        ;; (The obvious downside is increased bandwidth)
        (log/debug prelog
                   "Nothing to send")
        state))))
