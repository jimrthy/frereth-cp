(ns frereth-cp.message.from-parent
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.marshall :as marshall]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils])
  (:import [io.netty.buffer ByteBuf Unpooled]
           java.nio.ByteOrder))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::delta-k nat-int?)
(s/def ::max-k nat-int?)
(s/def ::min-k nat-int?)
;; Q: What is this, really?
(s/def ::max-rcvd nat-int?)
(s/def ::start-stop-details (s/keys :req [::min-k
                                          ::max-k
                                          ::delta-k
                                          ::max-rcvd]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Implementation

(s/fdef deserialize
        :args (s/cat :buf bytes?)
        :ret ::specs/packet)
(defn deserialize
  "Convert a raw message block into a message structure"
  ;; Important: there may still be overlap with previously read bytes!
  ;; (but that's a problem for downstream)
  [message-loop-name
   ^bytes incoming]
  {:pre [incoming]
   :post [%]}
  (let [;; It's tempting to use something like doto here
        ;; instead.
        ;; Don't.
        ;; This is actually a functional call.
        ;; .order returns a new buffer with different
        ;; semantics.
        buf (.order (Unpooled/wrappedBuffer incoming)
                    ByteOrder/LITTLE_ENDIAN)
        ;; Q: How much of a performance hit do I take by
        ;; wrapping this?
        ;; Using decompose is nice and convenient here, but
        ;; I can definitely see it cause problems.
        ;; TODO: Benchmark!
        header (shared/decompose marshall/message-header-dscr buf)
        D' (::specs/size-and-flags header)
        SF (bit-and D' (bit-or K/eof-normal K/eof-error))
        D (- D' SF)
        padding-count (- (.readableBytes buf)
                         D')]
    (log/debug (str message-loop-name
                    ": Decomposed "
                    (count incoming)
                    " bytes into\n"
                    header))
    ;; Start by skipping the initial padding (if any)
    (when (and (nat-int? padding-count)
               (pos? padding-count))
      (.skipBytes buf padding-count))

    ;;; And then return a portion of buf that we can
    ;;; safely mangle later.
    ;;; I really don't like any of the obvious options.

    ;; 3 approaches seem to make sense here:
    ;; 1. Create a copy of buf and release the original,
    ;; trying to be memory efficient.
    (comment
      (let [result (assoc header ::specs/buf (.copy buf))]
        (.release buf)
        result))
      ;; 2. Avoid the time overhead of making the copy.
      ;; If we don't release this very quickly, something
      ;; bigger/more important is drastically wrong.

    (comment
      ;; TODO: Try out this potential compromise:
      ;; (preliminary testing suggests that it should work)
      ;; This is really an artifact from an early implementation
      ;; when I was trying to stick very closely to the
      ;; reference implementation. Which reads a length
      ;; byte followed by a stream of bytes from a pipe.
      ;; Q: Does this make any sense at all now?
      (.discardReadBytes buf)
      (.capacity buf D'))
      ;; 3. Just do these manipulations on the incoming
      ;; byte-array (vector?) and avoid the overhead (?)
      ;; of adding a ByteBuf to the mix

      ;; Going with easiest approach to option 2 for now

    (assoc header ::specs/buf buf)))

(s/fdef calculate-start-stop-bytes
        :args (s/cat :state ::specs/state
                     :packet ::specs/packet)
        :ret (s/nilable ::start-stop-details))
(defn calculate-start-stop-bytes
  "Extract start/stop ACK addresses (lines 562-574)"
  [{{:keys [::specs/receive-written]
     :as incoming} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}
   {^ByteBuf incoming-buf ::specs/buf
    D ::specs/size-and-flags
    start-byte ::specs/start-byte
    :as packet}]
  (let [prelog (utils/pre-log message-loop-name)]
    (assert D (str prelog "Missing ::specs/size-and-flags among\n" (keys packet)))
    (log/debug prelog
               "calculate-start-stop-bytes: D =="
               D
               "\nIncoming State:\n"
               incoming)
    ;; If we're re-receiving bytes...well, the reference
    ;; implementation just discards them.
    ;; It would be safer to verify that the overlapping bits
    ;; match, since that sort of thing is an important attack
    ;; vector.
    ;; Then again, we've already authenticated the message and
    ;; verified its signature. If an attacker can break that,
    ;; doing extra work here isn't going to protect anything.
    ;; We're back to the "DJB thought it was safe" appeal to
    ;; authority.
    ;; So stick with the current approach for now.
    (let [starting-point (.readerIndex incoming-buf)
          D' D
          SF (bit-and D (bit-or K/eof-normal K/eof-error))
          D (- D SF)
          message-length (.readableBytes incoming-buf)]
      (log/debug prelog
                 (str "Setting up initial read from position "
                      starting-point
                      ": " D' " bytes/flags"))
      (if (<= D K/k-1)
        ;; start-byte and stop-byte are really addresses in the
        ;; message stream
        (let [stop-byte (+ D start-byte)]
          (log/debug prelog
                     "Calculating ACK gaps from"
                     start-byte
                     "to"
                     ;; It looks like there's a 1-off error here.
                     ;; If Message 1 (start-byte 0) is 1024
                     ;; bytes long, stop-byte should be at
                     ;; address 1023.
                     ;; At least for purposes of the ACK.
                     ;; Q: Right?
                     ;; A: Wrong.
                     ;; Lines 589-593:
                     ;; If we receive 1 byte at address 0,
                     ;; that increments receivebytes to 1.
                     ;; Line 605:
                     ;; That's what goes into the ACK block.
                     stop-byte
                     "\ncalculate-start-stop-bytes\nreceive-written:"
                     receive-written
                     "\nstop-byte:"
                     stop-byte
                     ;; We aren't using anything like this.
                     ;; Big Q: Should we?
                     ;; A: Maybe. It would save some GC.
                     ;; "\nreceive-buf writable length:" (.writableBytes receive-buf)
                     )

          ;; of course, flow control would avoid this case -- DJB
          ;; Q: What does that mean? --JRG
          ;; Whatever it means:
          ;; Note that both stop-byte and receive-written are absolute
          ;; stream addresses. So we're just tossing messages for addresses
          ;; that are too far past the last portion of that stream that
          ;; we've passed along to the child.
          (when (<= stop-byte (+ receive-written K/recv-byte-buf-size))
            ;; 576-579: SF (StopFlag? deals w/ EOF)
            (let [receive-eof (condp = SF
                                0 ::specs/false
                                K/eof-normal ::specs/normal
                                K/eof-error ::specs/error)
                  ;; Note that this needs to update the "global state" because
                  ;; we've reached the end of the stream.
                  receive-total-bytes (when (not= ::specs/false receive-eof)
                                        stop-byte)]
              ;; 581-588: copy incoming into receivebuf
              (comment (throw (RuntimeException. "Setting receive-written has broken this")))
              (let [gap-after-start (- receive-written start-byte)
                    min-k (if (< 0 gap-after-start)
                            0 gap-after-start)  ; drop bytes we've already written
                    ;; Address at the limit of our buffer size
                    max-rcvd (+ receive-written K/recv-byte-buf-size)
                    ;; N.B.: D is a relative address.
                    ^Long max-k (min D (- max-rcvd start-byte))
                    delta-k (- max-k min-k)]
                (assert (<= 0 max-k))
                (when (neg? delta-k)
                  (throw (ex-info (str prelog "stop-byte before start-byte")
                                  {::max-k max-k
                                   ::min-k min-k
                                   ::D D
                                   ::max-rcvd max-rcvd
                                   ::start-byte start-byte
                                   ::receive-written receive-written})))

                {::min-k min-k
                 ::max-k max-k
                 ::delta-k delta-k
                 ::max-rcvd max-rcvd
                 ::receive-eof receive-eof
                 ;; Yes, this might well be nil if there's no reason to "change"
                 ;; the "global state".
                 ;; This smells suspiciously tightly coupled.
                 ::receive-total-bytes receive-total-bytes}))))
        (do
          (log/warn prelog
                    "Message packet from parent is too long. D =="
                    D
                    "\nRemaining readable bytes:"
                    message-length)
          ;; This needs to short-circuit.
          ;; Q: is there a better way to accomplish that?
          nil)))))

(s/fdef extract-message!
        :args (s/cat :state ::specs/state
                     :packet ::specs/packet)
        :ret ::specs/state)
(defn extract-message!
  "Lines 562-593"
  [{{:keys [::specs/gap-buffer
            ::specs/strm-hwm]} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}
   {^ByteBuf incoming-buf ::specs/buf
    D ::specs/size-and-flags
    start-byte ::specs/start-byte
    :keys [::specs/message-id]
    :as packet}]
  {:pre [start-byte]}
  (let [calculated (calculate-start-stop-bytes state packet)]
    (if calculated
      (let [{:keys [::delta-k
                    ::max-rcvd
                    ::min-k
                    ::receive-eof]
             overridden-recv-total-bytes ::receive-total-bytes
             ^Long max-k ::max-k} calculated]
        ;; There are at least a couple of curve balls in the air right here:
        ;; 1. Only write bytes at stream addresses(?)
        ;;    (< receive-written where (+ receive-written receive-buf-size))

        ;; Q: Why haven't I converted incoming-buf to a vector of bytes?
        ;; Or even a byte-array?
        ;; A: Because I still need to slice and dice later, when I'm doing
        ;; gap consolidation.
        (when (pos? min-k)
          (.skipBytes incoming-buf min-k))

        ;;          set the receivevalid flags
        ;; 2. Update the receive-valid flag associated with each byte as we go
        ;;    The receivevalid array is declared with this comment:
        ;;    1 for byte successfully received; XXX: use buddy structure to speed this up --DJB
        ;; This point is moot, considering the way I'm using a priority queue.
        ;; Keeping the comment around as a reminder that the ring buffer is probably
        ;; quite a bit more efficient, and that I should look into using a buddy structure.

        ;; 3. The array of receivevalid flags is used in the loop between lines
        ;;    589-593 to decide how much to increment strm-hwm (a.k.a receivebytes,
        ;;    in the original).
        ;;    It's cleared on line 630, after we've written the bytes to the
        ;;    child pipe.
        ;; I'm fairly certain that for loop amounts to:

        (if (not= 0 message-id)
          (let [current-eof (get-in state [::specs/incoming ::specs/receive-eof])]
            (update state
                    ::specs/incoming
                    (fn [cur]
                      (cond-> cur
                        (not= current-eof receive-eof) (assoc ::specs/receive-eof
                                                              receive-eof)
                        true (assoc ::specs/strm-hwm
                                    (min max-rcvd
                                         (+ strm-hwm delta-k)))
                        ;; calculate-start-stop-bytes might have overriden for this
                        ;; In the outer scope.
                        overridden-recv-total-bytes (assoc ::specs/receive-total-bytes
                                                           overridden-recv-total-bytes)
                        true (update ::specs/gap-buffer
                                     assoc
                                     ;; These are the absolute stream positions
                                     ;; of the values that are left
                                     [(+ start-byte min-k) (+ start-byte max-k)]
                                     incoming-buf)))))
          (do
            ;; This seems problematic, but that's because
            ;; it's easy to tangle up the outgoing vs. incoming buffers.
            ;; The ACK was for the sake of the un-ackd-blocks in
            ;; outgoing.
            ;; The gap-buffer that we are *not* updating is filled with
            ;; arriving messages that might have been dropped/misordered
            ;; due to UDP issues.
            (log/debug (utils/pre-log message-loop-name)
                       "Pure ACK never updates received gap-buffer")
            state)))
      state)))

(s/fdef flag-acked-others!
        :args (s/cat :state ::specs/state
                     :packet ::specs/packet)
        :ret ::specs/state)
(defn flag-acked-others!
  "Cope with sent message the other side just ACK'd

  Lines 544-560"
  [{:keys [::specs/message-loop-name]
    :as state}
   {:keys [::specs/message-id]
    :as packet}]
  ;; TODO: If message-id is 0, don't waste time doing any
  ;; of this.
  ;; That really should be just a simple if check.
  ;; But the caller may have different ideas.
  ;; Actually, if (= message-id 0), this probably shouldn't
  ;; have been called in the first place.
  (let [prelog (utils/pre-log message-loop-name)]
    (log/info prelog
              (str "Top of flag-acked-others!\nHandling gaps ACK'd from\n"
                   packet
                   "\n"))
    ;; TODO: Check for performance difference if we switch to a reducible.
    (let [gaps (map (fn [[startfn stopfn]]
                      [(startfn packet) (stopfn packet)])
                    [[(constantly 0) ::specs/ack-length-1] ;  0-8
                     [::specs/ack-gap-1->2 ::specs/ack-length-2] ; 16-20
                     [::specs/ack-gap-2->3 ::specs/ack-length-3] ; 22-24
                     [::specs/ack-gap-3->4 ::specs/ack-length-4] ; 26-28
                     [::specs/ack-gap-4->5 ::specs/ack-length-5] ; 30-32
                     [::specs/ack-gap-5->6 ::specs/ack-length-6]])] ; 34-36
      (log/debug prelog
                 (str "ACK'd with Gaps: " (into [] gaps)
                      "\nState: " state))
      (->
       (reduce (fn [{:keys [::stop-byte]
                     :as state}
                    [start stop :as gap-key]]
                 (when-not (and start stop)
                   (log/error (str prelog
                                   "missing either "
                                   start
                                   " or "
                                   stop
                                   " somewhere in packet.")))
                 ;; Note that this is based on absolute stream addresses
                 (let [start-byte (+ stop-byte start)
                       stop-byte (+ start-byte stop)]
                   ;; This seems like an awkward way to get state modified to
                   ;; adjust the return value.
                   ;; It actually fits perfectly, but it isn't as obvious as
                   ;; I'd like.
                   (assoc (help/mark-ackd-by-addr state start-byte stop-byte)
                          ::stop-byte
                          stop-byte)))
               (assoc state ::stop-byte 0)
               gaps)
       ;; Ditch the temp key we used to track the stop point
       (dissoc ::stop-byte)))))

(s/fdef prep-send-ack
        :args (s/cat :state ::state
                     :msg-id (s/and int?
                                    pos?))
        :ret (s/nilable bytes?))
(defn prep-send-ack
  "Build a byte array to ACK the message we just received"
  ;;   Lines 595-606
  [{{:keys [::specs/contiguous-stream-count
            ::specs/receive-eof
            ::specs/receive-total-bytes
            ::specs/receive-written
            ::specs/strm-hwm]} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}
   message-id]
  {:pre [contiguous-stream-count
         message-id
         receive-eof
         (nat-int? receive-total-bytes)
         strm-hwm]}
  ;; XXX: incorporate selective acknowledgments --DJB
  ;; never acknowledge a pure acknowledgment --DJB
  ;; I've seen at least one email pointing out that the
  ;; author (Matthew Dempsky...he's the only person I've
  ;; run across who's published any notes about
  ;; the messaging protocol) has a scenario where the
  ;; child just hangs, waiting for an ACK to the ACKs
  ;; it sends 4 times a second.
  (if (not= message-id 0)
    (do
      ;; Note that strm-hwm is the address of the stream
      ;; that either
      ;; 1. have been forwarded along to the child
      ;; or
      ;; 2. are buffered and ready to forward to the child
      ;; So we have "fully" received every byte sent, up
      ;; to this point.
      ;; Although there's some weird off-by-1 issues
      ;; baked into the logic.
      ;; The important thing is that this isn't just the last
      ;; byte in the message we most recently received.
      (log/debug (utils/pre-log message-loop-name)
                 (str "Building an ACK for message "
                      message-id
                      "\nup to address "
                      ;; TODO: Honestly, receive-written would
                      ;; be more accurate here.
                      contiguous-stream-count
                      "/"
                      strm-hwm))
      ;; DJB reuses the incoming message that we're preparing
      ;; to ACK, locked to 192 bytes.
      ;; Q: Is that worth the GC savings?
      (let [response (byte-array 192)]
        ;; XXX: delay acknowledgments  --DJB
        ;; 0 ID for pure ACK (4 bytes)
        ;; 4 bytes for the message-id
        (b-t/uint32-pack! response 4 message-id)
        ;; Line 602
        (b-t/uint64-pack! response 8 (if (and receive-eof
                                              (= contiguous-stream-count receive-total-bytes))
                                       ;; Avoid 1-off errors due to the
                                       ;; difference between tracking
                                       ;; the stream address (which I'm
                                       ;; doing) vs. the receivebytes
                                       ;; count (which is how the
                                       ;; reference implementation tracks
                                       ;; this)
                                       (inc contiguous-stream-count)
                                       contiguous-stream-count))
        ;; Note that the gap-buffer should make it easy to also ACK
        ;; messages that aren't part of that contiguous stream.
        ;; TODO: Go ahead and add that functionality.
        response))
    (do
      (log/debug (utils/pre-log message-loop-name) "Never ACK a pure ACK")
      nil)))

(defn send-ack!
  "Write ACK buffer back to parent

Line 608"
  [{:keys [::specs/->parent
           ::specs/message-loop-name]
    :as io-handle}
   ^bytes send-buf]
  (if send-buf
    (do
      (when-not ->parent
        (throw (ex-info "Missing ->parent callback"
                        {::callbacks (::specs/callbacks io-handle)
                         ::available-keys (keys io-handle)})))
      (try
        (->parent send-buf)
        ;; TODO: Need a status reporter callback for something like this
        (catch RuntimeException ex
          (log/error ex "send-ack! failed during supplied callback"))))
    (log/debug (str message-loop-name
                    ": No bytes to send...presumably we just processed a pure ACK"))))

(s/fdef flag-blocks-ackd-by-id
        :args (s/cat :state ::specs/state
                     :acked-blocks ::specs/blocks)
        :ret ::specs/state)
(defn flag-blocks-ackd-by-id
  "Reference implementation ignores these"
  ;; Q: Should this go away?
  ;; Only recognize the flag by address, which means
  ;; that bytes reached the child.
  ;; It probably doesn't make any meaningful difference, but
  ;; that approach seems safer.
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/un-ackd-blocks]
     :as outgoing} ::specs/outgoing
    :as state}
   ackd-blocks]
  ;; Note that, in theory, we *could*
  ;; have multiple blocks with the same message ID.
  ;; But probably not inside the available 128K buffer space.
  ;; At best, we have 32 bits for block IDs, -1 for
  ;; ID 0 (which is a pure ACK).
  ;; And in java land with only signed integers, there's
  ;; a good chance we really only have 16 bits.
  ;; But we're limiting the buffer to ~256 messages at a time,
  ;; (depending on size) so it shouldn't happen here.
  (reduce (fn [acc ackd]
            ;; The block should get cleared (and ackd-addr
            ;; updated) in mark-acknowledged!
            (log/debug (utils/pre-log message-loop-name)
                       "Marking"
                       ackd
                       "as ACK'd, due to its ID")
            (update acc ::specs/outgoing
                    #(help/mark-block-ackd % ackd)))
          state
          ackd-blocks))

(s/fdef cope-with-child-eof
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn cope-with-child-eof
  "If the child's sent EOF, and all blocks have been sent/ACK'd, we're done"
  [{{:keys [::specs/send-eof
            ::specs/un-ackd-blocks
            ::specs/un-sent-blocks]} ::specs/outgoing
    :as state}]
  (if (and (not= ::specs/normal send-eof)
           (empty? un-ackd-blocks)
           (empty? un-sent-blocks))
    (assoc-in state [::specs/outgoing ::specs/send-eof-acked] true)
    state))

(s/fdef handle-incoming-ack
        :args (s/cat :state ::specs/state
                     :packet ::specs/packet)
        :ret ::specs/state)
(defn handle-incoming-ack
  "Update outbound queues w/ new ACKs"
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/un-ackd-blocks]
     :as outgoing} ::specs/outgoing
    :as initial-state}
   {:keys [::specs/acked-message]
    :as packet}]
  (let [log-prefix (utils/pre-log message-loop-name)]
    (log/debug log-prefix
               (str "looking for un-acked blocks among\n"
                    un-ackd-blocks
                    "\nthat match message ID "
                    acked-message))
    ;; The acked-message ID should only be 0 on the
    ;; first outgoing message block, since we don't
    ;; ACK pure ACKs
    (as-> (if (not= 0 acked-message)
            ;; Gaping open Q: Do I really want to do this?
            ;; (the reference implementation absolutely does not)
            (let [ackd-blocks (filter #(= acked-message (::specs/message-id %))
                                      un-ackd-blocks)]
              (flag-blocks-ackd-by-id initial-state
                                      ackd-blocks))
            initial-state)
        state
      ;; That takes us down to line 544
      ;; It seems more than a bit silly to calculate flag-acked-others!
      ;; if the incoming message is a pure ACK (i.e. message ID 0).
      ;; That seeming silliness is completely correct: this
      ;; is the entire point behind a pure ACK.
      (flag-acked-others! state packet)
      (reduce flow-control/update-statistics
              state
              (filter ::specs/ackd?
                      (get-in state
                              [::specs/outgoing
                               ::specs/un-ackd-blocks])))
      (-> state
          help/drop-ackd!
          cope-with-child-eof))))

(s/fdef handle-comprehensible-message!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        ;; TODO: This should not be nilable
        :ret (s/nilable ::specs/state))
(defn handle-comprehensible-message!
  "handle this message if it's comprehensible: (DJB)

  This seems like the interesting part.
  lines 444-609"
  [io-handle
   {{^bytes parent->buffer ::specs/parent->buffer} ::specs/incoming
    {original-eof ::specs/receive-eof
     :as original-incoming} ::specs/incoming
    ;; It seems really strange to have anything that involves
    ;; the outgoing blocks in here.
    ;; But there's an excellent chance that the incoming message
    ;; is going to ACK some or all of what we have pending in here.
    {:keys [::specs/un-ackd-blocks]
     :as outgoing} ::specs/outgoing
    :keys [::specs/flow-control
           ::specs/message-loop-name]
    :as state}]
  ;; Keep in mind that parent->buffer is an array of bytes that has
  ;; just been pulled off the wire
  (let [len (count parent->buffer)
        log-prefix (utils/pre-log message-loop-name)]
    (log/debug log-prefix
               "Handling a"
               len
               "byte message")
    ;; Lines 452-453
    (if (and (>= len K/min-msg-len)
             (<= len K/max-msg-len))
      (do
        (log/debug log-prefix
                   (str  "Deserializing parent->buffer: "
                        parent->buffer ", a " (class parent->buffer)
                        " containing " (count parent->buffer) " bytes"))

        ;; TODO: Time this. See whether it's worth combining these calls
        ;;  using either some version of comp or as-> (or possibly
        ;; transducers?)
        ;; At the very least, find a way to break it into multiple
        ;; functions.
        ;; This gigantic let is awful
        (let [;; This looks like a discrepancy with reference implementation:
              ;; that calls the flow control updates before anything else.
              ;; It doesn't quite mesh up, since there's never any
              ;; explicit call like this to do the deserialization.
              ;; But the next real steps are
              ;; 1. updating the statistics and
              ;; 2. Set up the flags for sending an ACK
              ;; So it has remained mostly faithful to the original
              packet (deserialize message-loop-name parent->buffer)
              ;; Discard the raw incoming byte array
              state (update state
                            ::specs/incoming
                            dissoc
                            ::specs/parent->buffer)]
          (assert packet (str message-loop-name
                              ": Unable to extract a packet from "
                              parent->buffer))

          (let [state (handle-incoming-ack state packet)
                starting-hwm (get-in state [::specs/incoming ::specs/strm-hwm])
                {:keys [::specs/flow-control
                        ::specs/outgoing]
                 {:keys [::specs/receive-eof
                         ::specs/strm-hwm]
                  :as incoming} ::specs/incoming
                 :as extracted} (extract-message! state packet)]
            (log/debug log-prefix
                       "handle-comprehensible message/extracted:\n"
                       "\n\tincoming:\n"
                       incoming
                       "\n\tflow-control:\n"
                       flow-control
                       "\n\toutgoing:\n"
                       outgoing
                       "\n\tFields:\n"
                       (keys extracted))
            ;; Q: Did fresh data arrive?
            (if (or (not= starting-hwm strm-hwm)
                    (not= original-eof receive-eof))
              (or
               (let [msg-id (::specs/message-id packet)]
                 (log/debug log-prefix (str "ACK message-id " msg-id "?"))
                 (when-not msg-id
                   ;; Note that 0 is legal: that's a pure ACK.
                   ;; We just have to have something.
                   ;; (This comment is because I have to keep remembering
                   ;; how truthiness works in C)
                   (throw (ex-info (str log-prefix "Missing the incoming message-id")
                                   extracted)))
                 (when-let [ack-msg (prep-send-ack extracted msg-id)]
                   (log/debug log-prefix (str "Have an ACK to send back"))
                   ;; since this is called for side-effects, ignore the
                   ;; return value.
                   ;; TODO: Place this in a buffer of side-effects that should
                   ;; happen once all the purely functional stuff is done
                   (send-ack! io-handle ack-msg)
                   (log/debug log-prefix "ACK'd")
                   (update extracted
                           ::specs/incoming
                           dissoc
                           ::specs/packet)))
               extracted)
              state))))
      (do
        (if (< 0 len)
          (log/warn (utils/pre-log message-loop-name)
                    (str "Illegal incoming message length:") len)
          ;; Nothing to see here. Move along.
          (log/debug (utils/pre-log message-loop-name)
                     "i/o loop iteration w/out parent interaction"))
        ;; Be explicit about this
        nil))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef try-processing-message!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        ;; TODO: This should not be nilable
        ;; (it is, due to handle-comprehensible-message.
        ;; Which also shouldn't be)
        :ret (s/nilable ::specs/state))
(defn try-processing-message!
  "436-613: try processing a message: --DJB"
  [io-handle
   {{:keys [::specs/->child-buffer
            ::specs/parent->buffer
            ::specs/receive-written
            ::specs/strm-hwm]} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}]
  (let [pre-log (utils/pre-log message-loop-name)
        child-buffer-count (count ->child-buffer)]
    (log/debug pre-log
               (str "try-processing-message"
                    "\nchild-buffer-count: " child-buffer-count
                    "\nparent->buffer count: " (count parent->buffer)
                    "\nreceive-written: " receive-written
                    "\nstrm-hwm: " strm-hwm))
    (if (or (< 0 (count parent->buffer))   ; new incoming message?
            ;; any previously buffered incoming messages to finish
            ;; processing?
            (not= 0 child-buffer-count)
            ;; This next check (line 438) includes an &&
            ;; to verify that tochild is > 0 (I'm
            ;; pretty sure that's just verifying that
            ;; the pipe is open)
            ;; I think the point of this next check
            ;; is back-pressure:
            ;; If we have pending bytes from the parent that have not
            ;; been written to the child, don't add more.
            ;; Note that there's really an && close connected
            ;; to this check: it quits mattering once the tochild
            ;; pipe has been closed.
            (> receive-written strm-hwm))
      ;; 440: sets maxblocklen=1024
      ;; Q: Why was it ever 512?
      ;; Guess: for initial Message part of Initiate packet, although
      ;; that limit's higher.
      ;; If that's the case, it seems like a mistake to do this after the
      ;; first non-ACK response.
      ;; That isn't true. The message handshake pieces happen at the
      ;; client layer. This part receives the decrypted message payloads
      ;; and reassembles them into the stream.
      (let [state' (assoc-in state [::specs/outgoing ::specs/max-block-length] K/k-1)]
        (log/debug pre-log
                   "Handling incoming message, if it's comprehensible")
        ;; Move on to line 444
        ;; It seems as though this should forward the incoming message
        ;; along to the child. But it's really just setting up the
        ;; state to do that.
        (handle-comprehensible-message! io-handle state'))
      (do
        ;; Nothing to do.
        (log/debug pre-log
                   "No pending messages from parent to send to child")
        state))))
