(ns frereth.cp.message.from-parent
  (:require [clojure.spec.alpha :as s]
            [frereth.cp
             [shared :as shared]]
            [frereth.cp.message
             [constants :as K]
             [flow-control :as flow-control]
             [headers :as hdr]
             [helpers :as help]
             [specs :as specs]]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [serialization :as serial]
             [util :as utils]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]])
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
        :args (s/cat :log-state ::weald/state
                     :buf bytes?)
        :ret (s/keys :req [::specs/packet ::weald/state]))
(defn deserialize
  "Convert a raw message block into a message structure"
  ;; Important: there may still be overlap with previously read bytes!
  ;; (but that's a problem for downstream)
  [log-state
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
        ;; I can definitely see it causing performance problems.
        ;; Q: Really? I may be able to improve on it by just
        ;; hard-coding the places where I use it to optimize
        ;; for just the reads that I actually need, but I'm
        ;; skeptical.
        ;; TODO: Benchmark!
        header (serial/decompose hdr/message-header-dscr buf)
        D' (::specs/size-and-flags header)
        SF (bit-and D' (bit-or K/eof-normal K/eof-error))
        D (- D' SF)
        padding-count (- (.readableBytes buf)
                         D')
        log-state (log/debug log-state
                             ::deserialize
                             "Decomposed"
                             {::buffer-size (count incoming)
                              ::header header})]
    ;; Start by skipping the initial padding (if any)
    (when (and (nat-int? padding-count)
               (pos? padding-count))
      (.skipBytes buf padding-count))

    ;;; And then return a portion of buf that we can
    ;;; safely mangle later (i.e. it's shared state that
    ;;; will get modified destructively)
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
    {::specs/packet (assoc header ::specs/buf buf)
     ::weald/state log-state}))

(s/fdef calculate-start-stop-bytes
        :args (s/cat :state ::specs/state
                     :packet ::specs/packet)
        :ret [(s/nilable ::start-stop-details) ::weald/state])
(defn calculate-start-stop-bytes
  "Extract start/stop ACK addresses (lines 562-574)"
  [{{:keys [::specs/receive-written]
     :as incoming} ::specs/incoming
    :keys [::specs/message-loop-name]
    log-state ::weald/state
    :as state}
   {^ByteBuf incoming-buf ::specs/buf
    D ::specs/size-and-flags
    start-byte ::specs/start-byte
    :as packet}]
  (let [prelog (utils/pre-log message-loop-name)
        _ (assert D (str prelog "Missing ::specs/size-and-flags among\n" (keys packet)))
        log-state (log/debug log-state
                              ::calculate-start-stop-bytes
                              "Top"
                              {::D D
                               ::specs/incoming incoming})]
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
          message-length (.readableBytes incoming-buf)
          log-state (log/debug log-state
                               ::calculate-start-stop-bytes
                               "Setting up initial read"
                               {::starting-address starting-point
                                ::bytes-flags D'})]
      (if (<= D K/k-1)
        ;; start-byte and stop-byte are really addresses in the
        ;; message stream
        (let [stop-byte (+ D start-byte)
              log-state (log/debug log-state
                                   ::calculate-start-stop-bytes
                                   "Calculating ACK gaps"
                                   {::start-byte start-byte
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
                                    ::stop-byte stop-byte
                                    ::specs/receive-written receive-written
                                    ;; We aren't using anything like this.
                                    ;; Big Q: Should we?
                                    ;; A: Maybe. It would save some GC.
                                    ;; "\nreceive-buf writable length:" (.writableBytes receive-buf)
                                    })]
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
                  ;; This is actually a flag that indicates the caller needs
                  ;; to make some hefty changes to the global state:
                  ;; we've now received the EOF flag.
                  ;; If nothing else, this is a terrible name (though I'm
                  ;; sure I took it from the reference implementation)
                  receive-total-bytes (when (not= ::specs/false receive-eof)
                                        stop-byte)]
              ;; 581-588: copy incoming into receivebuf
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

                [{::min-k min-k
                   ::max-k max-k
                   ::delta-k delta-k
                   ::max-rcvd max-rcvd
                   ::receive-eof receive-eof
                   ;; Yes, this might well be nil if there's no reason to "change"
                   ;; the "global state".
                   ;; This smells suspiciously tightly coupled.
                  ::receive-total-bytes receive-total-bytes}
                 log-state]))))
        (let [log-state (log/warn log-state
                                  ::calculate-start-stop-bytes
                                  "Message packet from parent is too long"
                                  {::D D
                                   ::readable-bytes message-length})]
          ;; This should short-circuit to avoid wasting CPU cycles.
          ;; Q: is there a better way to accomplish that?
          [nil log-state])))))

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
  (let [[calculated log-state] (calculate-start-stop-bytes state packet)]
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
          (let [current-eof (get-in state [::specs/incoming ::specs/receive-eof])
                eof-changed? (not= current-eof receive-eof)]
            (update (assoc state ::weald/state log-state)
                    ::specs/incoming
                    (fn [cur]
                      (cond-> cur
                        eof-changed? (assoc ::specs/receive-eof
                                            receive-eof)
                        true (assoc ::specs/strm-hwm
                                    (min max-rcvd
                                         (+ strm-hwm delta-k)))
                        ;; calculate-start-stop-bytes might have overriden for this
                        ;; In the outer scope.
                        overridden-recv-total-bytes (assoc ::specs/receive-total-bytes
                                                           overridden-recv-total-bytes)
                        true (update ::specs/gap-buffer
                                     (fn [cur]
                                       (let [result
                                             (assoc cur
                                                    ;; These are the absolute stream positions
                                                    ;; of the values that are left
                                                    [(+ start-byte min-k) (+ start-byte max-k)]
                                                    incoming-buf)]
                                         (if eof-changed?
                                           (do
                                             ;; When the last gap's been consolidated (but not before),
                                             ;; we need to
                                             ;; a) write final pipes to child
                                             ;; b) close that pipe
                                             ;;    Except this isn't quite correct.
                                             ;;    No, it is.
                                             ;;    It's just that my handshake can't really
                                             ;;    cope with it as-is.
                                             ;;    It really needs something to happen when
                                             ;;    this pipe closes.
                                             ;;    Except that I think it's a stream closing.
                                             ;;    Child can't know about those.
                                             ;;    We need to send a ::eof signal to its callback.
                                             ;; c) Also need to close the parent->child pipes
                                             ;; d) And, really, need to deliver a deferred
                                             ;;    that, in conjunction with the child->parent
                                             ;;    parent pipes, will cause the main ioloop
                                             ;;    to exit.
                                             ;; Q: Is all that happening somewhere?
                                             (assoc result
                                                    [(+ start-byte max-k) (+ start-byte max-k)]
                                                    receive-eof))
                                           result))))))))

          ;; This seems problematic, but that's because
          ;; it's easy to tangle up the outgoing vs. incoming buffers.
          ;; The ACK was for the sake of the un-ackd-blocks in
          ;; outgoing.
          ;; The gap-buffer that we are *not* updating is filled with
          ;; arriving messages that might have been dropped/misordered
          ;; due to UDP issues.
          (update state
                  ::weald/state
                  #(log/debug %
                              ::extract-message!
                              "Pure ACK never updates received gap-buffer"))))
      (assoc state ::weald/state log-state))))

(s/fdef flag-ackd-others!
  :args (s/cat :state ::specs/state
               :packet ::specs/packet)
        :ret ::specs/state)
(defn flag-ackd-others!
  "Cope with sent message the other side just ACK'd

  Lines 544-560"
  [{:keys [::specs/message-loop-name]
    log-state ::weald/state
    :as state}
   {:keys [::specs/message-id]
    :as packet}]
  ;; TODO: If message-id is 0, don't waste time doing any
  ;; of this.
  ;; That really should be just a simple if check.
  ;; But the caller may have different ideas.
  ;; Actually, if (= message-id 0), this probably shouldn't
  ;; have been called in the first place.
  (let [prelog (utils/pre-log message-loop-name)
        log-state (log/info log-state
                            ::flag-ackd-others!
                            "Top of flag-ackd-others!\nHandling gaps ACK'd"
                            packet)]
    ;; TODO: Check for performance difference if we switch to a reducible.
    (let [gaps (map (fn [[startfn stopfn]]
                      [(startfn packet) (stopfn packet)])
                    [[(constantly 0) ::specs/ack-length-1] ;  0-8
                     [::specs/ack-gap-1->2 ::specs/ack-length-2] ; 16-20
                     [::specs/ack-gap-2->3 ::specs/ack-length-3] ; 22-24
                     [::specs/ack-gap-3->4 ::specs/ack-length-4] ; 26-28
                     [::specs/ack-gap-4->5 ::specs/ack-length-5] ; 30-32
                     [::specs/ack-gap-5->6 ::specs/ack-length-6]]) ; 34-36
          log-state (log/debug log-state
                               ::flag-ackd-others!
                               "ACK'd with Gaps"
                               {::gaps (into [] gaps)
                                ::specs/state state})]
      (->
       (reduce (fn [{:keys [::stop-byte]
                     log-state ::weald/state
                     :as state}
                    [start stop :as gap-key]]
                 (println "Reducing from" start "to" stop "until" stop-byte "based on" gap-key)
                 (let [log-state
                       (if-not (and start stop)
                         (log/error log-state
                                    ::flag-ackd-others!
                                    "Missing stop/start somewhere in packet"
                                    {::start start
                                     ::stop stop})
                         log-state)
                       ;; Note that this is based on absolute stream addresses
                       start-byte (+ stop-byte start)
                       stop-byte (+ start-byte stop)]
                   ;; This seems like an awkward way to get state modified to
                   ;; adjust the return value.
                   ;; It actually fits perfectly, but it isn't as obvious as
                   ;; I'd like.
                   (assoc (help/mark-ackd-by-addr (assoc state
                                                         ::weald/state
                                                         log-state)
                                                  start-byte
                                                  stop-byte)
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
        :ret (s/keys :req [::weald/state
                           (s/nilable ::specs/ack-body)]))
(defn prep-send-ack
  "Build a byte array to ACK the message we just received"
  ;;   Lines 595-606
  [{{:keys [::specs/contiguous-stream-count
            ::specs/receive-eof
            ::specs/receive-total-bytes
            ::specs/receive-written
            ::specs/strm-hwm]} ::specs/incoming
    :keys [::specs/message-loop-name]
    log-state ::weald/state
    :as state}
   message-id]
  {:pre [contiguous-stream-count
         log-state
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
    (let [log-state
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
          (log/debug log-state
                     ::prep-send-ack
                     "Building an ACK"
                     {::specs/message-id message-id
                      ;; TODO: Honestly, receive-written would
                      ;; be more accurate here.
                      ::specs/contiguous-stream-count contiguous-stream-count
                      ::specs/strm-hwm strm-hwm})
          ;; DJB reuses the incoming message that we're preparing
          ;; to ACK, locked to 192 bytes.
          ;; Q: Is that worth the GC savings?
          response (byte-array 192)]
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

      {::weald/state log-state
       ::specs/ack-body response})
    {::weald/state (log/debug log-state
                              ::prep-send-ack
                              "Never ACK a pure ACK")
     ::specs/ack-body nil}))

(s/fdef send-ack!
        :args (s/cat :io-handle ::specs/io-handle
                     ;; These next 2 parameters seem swapped.
                     ;; But this opens up the potential for just
                     ;; setting up a partial that accepts the
                     ;; log-state as its only remaining parameter.
                     ;; For the much-improved approach of triggering
                     ;; side-effects after all the logic is done.
                     :send-buf bytes?
                     :log-state ::weald/state)
        :ret ::weald/state)
(defn send-ack!
  "Write ACK buffer back to parent

Line 608"
  [{:keys [::weald/logger
           ::specs/->parent]
    :as io-handle}
   send-buf
   log-state]
  {:pre [logger
         log-state]}
  (if send-buf
    (let [send-buf (bytes send-buf)]
      (when-not ->parent
        (throw (ex-info "Missing ->parent callback"
                        {::callbacks (::specs/callbacks io-handle)
                         ::available-keys (keys io-handle)})))
      (try
        (->parent send-buf)
        ;; TODO: Need a status reporter callback for situations like this
        log-state
        (catch RuntimeException ex
          (log/exception log-state
                         ex
                         ::send-ack!
                         "send-ack! failed during supplied callback"))))
    (log/debug log-state
               ::send-ack!
               ": No bytes to send...presumably we just processed a pure ACK")))

(s/fdef flag-blocks-ackd-by-id
        :args (s/cat :state ::specs/state
                     :ackd-blocks ::specs/blocks)
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
  (reduce (fn [state ackd]
            ;; The block should get cleared (and ackd-addr
            ;; updated) in mark-acknowledged!
            (-> state
                (update ::weald/state
                        #(log/debug % ::flag-blocks-ackd-by-id
                                    "Marking as ACK'd, due to its ID"
                                    ackd))
                (update ::specs/outgoing
                        #(help/mark-block-ackd % ackd))))
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
    :keys [::specs/message-loop-name]
    :as state}]
  (let [state (update state ::weald/state
                      #(log/debug %
                                  ::cope-with-child-eof
                                  "Q: Has other side ACKd the child's EOF message?"
                                  {::specs/send-eof send-eof
                                   ::pending-block-count (+ (count un-ackd-blocks)
                                                            (count un-sent-blocks))}))]
  ;;;           177-182: Possibly set sendeofacked flag
    ;; Note that this particular step is pretty far from where the original
    ;; does it (our equivalent to that is under helpers, when it copes with
    ;; ACKs)
    (if (and (not= ::specs/false send-eof)
             ;; It's
             (empty? un-ackd-blocks)
             (empty? un-sent-blocks))
      (assoc-in state [::specs/outgoing ::specs/send-eof-acked] true)
      state)))

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
  (let [{log-state ::weald/state
         :as initial-state} (update initial-state
                                    ::weald/state
                                    #(log/debug %
                                                ::handle-incoming-ack
                                                "looking for un-ackd blocks by message ID"
                                                {::specs/un-ackd-blocks un-ackd-blocks
                                                 ::specs/acked-message acked-message}))]
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
      ;; It seems more than a bit silly to calculate flag-ackd-others!
      ;; if the incoming message is a pure ACK (i.e. message ID 0).
      ;; That seeming silliness is completely correct: this
      ;; is the entire point behind a pure ACK.
      (flag-ackd-others! state packet)
      (reduce flow-control/update-statistics
              state
              (filter ::specs/ackd?
                      (get-in state
                              [::specs/outgoing
                               ::specs/un-ackd-blocks])))
      (let [result
            (-> state
                help/drop-ackd!
                cope-with-child-eof)]
        result))))

(s/fdef possibly-ack!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        :ret ::specs/state)
(defn possibly-ack!
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
    log-state ::weald/state
    :as state}]
  ;; Keep in mind that parent->buffer is an array of bytes that has
  ;; just been pulled off the wire
  (let [len (count parent->buffer)
        log-state (log/debug log-state
                             ::possibly-ack!
                             "incoming"
                             {::message-length len})]
    ;; Lines 452-453
    (if (and (>= len K/min-msg-len)
             (<= len K/max-msg-len))
      (let [log-state (log/debug log-state
                                 ::possibly-ack!
                                 "Deserializing parent->buffer"
                                 {::specs/parent->buffer parent->buffer
                                  ::buffer-class (class parent->buffer)
                                  ::buffer-size (count parent->buffer)})]

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
              {{msg-id ::specs/message-id
                :as packet} ::specs/packet
               log-state ::weald/state} (deserialize log-state parent->buffer)
              ;; Discard the raw incoming byte array
              state (update state
                            ::specs/incoming
                            dissoc
                            ::specs/parent->buffer)
              _ (assert packet (str (utils/pre-log message-loop-name)
                                    ": Unable to extract a packet from "
                                    parent->buffer))
              _ (assert msg-id
                        ;; Note that 0 is legal: that's a pure ACK.
                        ;; We just have to have something.
                        ;; (This comment is because I have to keep remembering
                        ;; how truthiness works in C)
                        (str (utils/pre-log message-loop-name)
                             "Missing the incoming message-id"))
              _ (assert log-state)
              state (handle-incoming-ack (assoc state
                                                ::weald/state log-state)
                                         packet)
              starting-hwm (get-in state [::specs/incoming ::specs/strm-hwm])
              {:keys [::specs/flow-control
                      ::specs/outgoing]
               {:keys [::specs/receive-eof
                       ::specs/strm-hwm]
                :as incoming} ::specs/incoming
               log-state ::weald/state
               :as extracted} (extract-message! state packet)
              log-state (log/debug log-state
                                   ::possibly-ack!
                                   "possibly-ack!/extracted. ACK message-id?"
                                   {::specs/incoming incoming
                                    ::specs/receive-eof receive-eof
                                    ::specs/flow-control flow-control
                                    ::specs/outgoing outgoing
                                    ::fields (keys extracted)
                                    ::specs/message-id msg-id})
              log-state (let [{log-state ::weald/state
                               ack-msg ::specs/ack-body} (prep-send-ack extracted msg-id)]
                          (if ack-msg
                            (as-> (log/debug log-state
                                             ::possibly-ack!
                                             "Have an ACK to send back")
                                log-state
                              ;; TODO: Place this in a buffer of side-effects that should
                              ;; happen once all the purely functional stuff is done
                              (send-ack! io-handle ack-msg log-state)
                              (log/debug log-state
                                         ::possibly-ack!
                                         "ACK'd"))
                            log-state))]
          (assoc (if (or (not= starting-hwm strm-hwm)
                         (not= original-eof receive-eof))
                   ;; Fresh data arrived
                   (update extracted
                           ::specs/incoming
                           dissoc
                           ::specs/packet)
                   state)
                 ::weald/state log-state)))
      ;; Illegal message arrived.
      (update state
              ::weald/state
              (fn [cur]
                (if (< 0 len)
                  (log/warn cur
                            ::possibly-ack!
                            "Illegal incoming message length"
                            len)
                  ;; Nothing to see here. Move along.
                  (log/debug cur
                             ::possibly-ack!
                             "i/o loop iteration w/out parent interaction")))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef try-processing-message!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state)
        :ret ::specs/state)
(defn try-processing-message!
  "436-613: try processing a message: --DJB"
  [io-handle
   {{:keys [::specs/->child-buffer
            ::specs/parent->buffer
            ::specs/receive-written
            ::specs/strm-hwm]} ::specs/incoming
    :keys [::specs/message-loop-name]
    log-state ::weald/state
    :as state}]
  (let [child-buffer-count (count ->child-buffer)
        log-state (log/debug log-state
                             ::try-processing-message!
                             "Top"
                             {::child-buffer-count child-buffer-count
                              ::parent->buffer-count (count parent->buffer)
                              ::specs/receive-written receive-written
                              ::specs/strm-hwm strm-hwm})]
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
      (let [state' (assoc-in state [::specs/outgoing ::specs/max-block-length] K/k-1)
            log-state (log/debug log-state
                                 ::try-processing-message!
                                 "Handling incoming message, if it's comprehensible")]
        ;; Move on to line 444
        ;; It seems as though this should forward the incoming message
        ;; along to the child. But it's really just setting up the
        ;; state to do that.
        (possibly-ack! io-handle (assoc state' ::weald/state log-state)))
      ;; Nothing to do.
      (update state
              ::weald/state
              #(log/debug
                %
                ::try-processing-message!
                "No pending messages from parent to send to child")))))
