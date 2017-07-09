(ns frereth-cp.message
  "Translation of curvecpmessage.c

  This is really a generic buffer program

  The \"parent\" child/server reads/writes to pipes that this provides,
  in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns.

  I keep wanting to think of this as a simple transducer and just
  skip the buffering pieces, but they (and the flow control) are
  really the main point."
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.executor :as exec]
            ;; This next reference should go away
            ;; Except...I *am* using it as part of
            ;; aleph. And, really, what alternatives
            ;; are available?
            ;; (agents and core.async seem to be the
            ;; best)
            [manifold.stream :as strm])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(set! *warn-on-reflection* true)

(def recv-byte-buf-size
  "How many bytes from the parent will we buffer to send to the child?"
  K/k-128)

(def send-byte-buf-size
  "How many child bytes will we buffer to send?

Don't want this too big, to avoid buffer bloat effects.

At the same time, it seems likely that the optimum will
vary from one application to the next.

Start with the default.

The reference implementation notes that this absolutely
must be a power of 2. Pretty sure that's because it involves
a circular buffer and uses bitwise ands for quick/cheap
modulo arithmetic."
  K/k-128)

(def max-outgoing-blocks
  "How many outgoing, non-ACK'd blocks will we buffer?

Corresponds to OUTGOING in the reference implementation.

That includes a comment that it absolutely must be a power of 2.

I think that's because it uses bitwise and for modulo to cope
with the ring buffer semantics, but there may be a deeper motivation."
  128)

(def max-block-length
  K/k-div2)

(def error-eof K/k-4)
(def normal-eof K/k-2)

(def max-child-buffer-size
  "Maximum message blocks from parent to child that we'll buffer before dropping

  must be power of 2 -- DJB"
  64)

(def min-msg-len 48)
(def max-msg-len 1088)

(def write-from-parent-timeout
  "milliseconds before we give up on writing a packet from parent to child"
  5000)

(def write-from-child-timeout
  "milliseconds before we give up on writing a packet from child to parent"
  5000)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::state-agent (s/and #(instance? clojure.lang.Agent %)
                            #(s/valid? ::specs/state (deref %))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal API

;;;; Q: what else is in the reference implementation?
;;;; A:
;;;; 186-654 main
;;;          186-204 boilerplate

;;;          260-263 set up some globals
;;;          264-645 main event loop
;;;          645-651 wait on children to exit
;;;          652-653 exit codes

;;; 264-645 main event loop
;;; 263-269: exit if done
;;; 271-306: Decide what and when to poll, based on global state

;;; This next piece seems like it deserves a prominent place.
;;; But, really, it needs to be deeply hidden from the end-programmer.
;;; I want it to be easy for me to change out and swap around, but
;;; that means no one else should ever really even need to know that
;;; it happens (no matter how vital it obviously is)
;;; 307-318: Poll for incoming data
;;;     317 XXX: keepalives

(defn room-for-child-bytes?
  [{:keys [::specs/send-bytes]
    :as state}]
  ;; Line 322: This also needs to account for send-acked
  ;; For whatever reason, DJB picked this as the end-point to refuse to read
  ;; more child data before we hit send-byte-buf-size.
  ;; Presumably that reason remains valid

  ;; Q: Is that an important part of the algorithm, or is
  ;; it "just" dealing with the fact that we have a circular
  ;; buffer with parts that have not yet been GC'd?
  ;; And is it possible to tease apart that distinction?
  (< (+ send-bytes K/k-4) send-byte-buf-size))

(s/fdef child-consumer
        :args (s/cat :state ::specs/state
                     :buf ::specs/buf))
(defn child-consumer
  "Accepts buffers of bytes from the child.

  Lines 319-337

The obvious approach is just to feed ByteBuffers
from this callback to the parent's callback.

That obvious approach completely misses the point that
this ns is a buffer. We need to hang onto those buffers
here until they've been ACK'd.

This approach was really designed as an event that
would be triggered when an event arrives on a stream.
Or maybe as part of an event loop that polls various
streams for available events.

It really should just be a plain function call.
I think this is really what I have planned for
the ::child-> key under state.

TODO: Untangle the strands and get this usable.
"
  [{:keys [::specs/send-acked
           ::specs/send-bytes]
    :as state}
   ^ByteBuf buf]
  ;; Q: Need to apply back-pressure if we
  ;; already have ~124K pending?
  ;; (It doesn't seem like it should matter, except
  ;; as an upstream signal that there's a network
  ;; issue)
  (let [;; In the original, this is the offset into the circular
        ;; buf where we're going to start writing incoming bytes.
        pos (+ (rem send-acked send-byte-buf-size) send-bytes)
        available-buffer-space (- send-byte-buf-size pos)
        bytes-to-read (min available-buffer-space (.readableBytes buf))
        send-bytes (+ send-bytes bytes-to-read)
        block {::buf buf
               ::transmissions 0}]
    (when (>= send-bytes K/stream-length-limit)
      ;; Want to be sure standard error handlers don't catch
      ;; this...it needs to force a fresh handshake.
      (throw (AssertionError. "End of stream")))
    (-> state
        (update ::blocks conj block)
        (assoc ::send-bytes send-bytes
;;;  337: update recent
               ::recent (System/nanoTime)))))

(s/fdef check-for-previous-block-to-resend
        :args ::state
        :ret (s/nilable ::state))
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
             (< (count blocks) max-outgoing-blocks)
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
          block-length (if (> (+ (bit-and start-pos (dec send-byte-buf-size))
                                 block-length)
                              send-byte-buf-size)
                         (- send-byte-buf-size (bit-and start-pos (dec send-byte-buf-size)))
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

(s/fdef calculate-message-data-block-length
        :args ::specs/block
        :ret (s/and nat-int?
                    ;; max possible:
                    ;; k-4 is the flag for FAIL.
                    ;; + k-1 for the actual message length
                    ;; This has other restrictions based on
                    ;; the implementation details, but those
                    ;; aren't covered by the spec
                    #(< (+ K/k-1 error-eof) %)))
(defn calculate-message-data-block-length-flags
  [block]
  (let [len (::specs/length block)]
    (bit-or len
            (case (::specs/send-eof block)
              false 0
              ::specs/normal normal-eof
              ::specs/error error-eof))))

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

(defn pick-next-block-to-send
  [state]
  (or (check-for-previous-block-to-resend state)
;;;       357-410: Try sending a new block: (-- DJB)
                  ;; There's goto-fun overlap with resending
                  ;; a previous block -- JRG
      (check-for-new-block-to-send state)))

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

(defn send-ack!
  "Write ACK buffer to parent

Line 608"
  [{{:keys [::specs/->parent]} ::specs/callbacks
    ^ByteBuf send-buf ::specs/send-buf
    :as state}]
  (if send-buf
    (do
      (when-not ->parent
        (throw (ex-info "Missing ->parent callback"
                        {::callbacks (::specs/callbacks state)
                         ::available-keys (keys state)})))
      (->parent send-buf))
    (log/debug "No bytes to send...presumably we just processed a pure ACK")))

(defn prep-send-ack
  "Lines 595-606"
  [{:keys [::specs/current-block-cursor
           ::specs/receive-bytes
           ::specs/receive-eof
           ::specs/receive-total-bytes]
    ^ByteBuf buf ::specs/send-buf
    :as state}
   message-id]
  (when-not receive-bytes
    (throw (ex-info "Missing receive-bytes"
                    {::among (keys state)})))
  ;; never acknowledge a pure acknowledgment --DJB
  ;; I've seen at least one email pointing out that the
  ;; author (Matthew Dempsky...he's the only person I've
  ;; run across who's published any notes about
  ;; the messaging protocol) has a scenario where the
  ;; child just hangs, waiting for an ACK to the ACKs
  ;; it sends 4 times a second.
  (if (not= message-id 0)
    (let [send-buf (Unpooled/buffer send-byte-buf-size)
          u 192]
      ;; XXX: delay acknowledgments  --DJB
      (.writeLong send-buf (quot u 16))
      (.writeInt send-buf message-id)
      (.writeLong send-buf (if (and receive-eof
                                    (= receive-bytes receive-total-bytes))
                             (inc receive-bytes)
                             receive-bytes))
      (assoc state ::specs/send-buf send-buf))
    ;; XXX: incorporate selective acknowledgments --DJB
    state))

(s/fdef extract-message-from-parent
        :args (:state ::specs/state)
        :ret ::specs/state)
(defn extract-message-from-parent
  "Lines 562-593"
  [{:keys [::specs/receive-bytes
           ::specs/receive-written
           ::specs/->child-buffer]
    :as state}]
  ;; 562-574: calculate start/stop bytes
  (let [^ByteBuf receive-buf (last ->child-buffer)
        D (help/read-ushort receive-buf)
        SF (bit-and D (bit-or normal-eof error-eof))
        D (- D SF)]
    (if (and (<= D 1024)
               ;; In the reference implementation,
               ;; len = 16 * (unsigned long long) messagelen[pos]
               ;; (assigned at line 443)
               ;; This next check looks like it really
               ;; amounts to "have we read all the bytes
               ;; in this block from the parent pipe?"
               ;; It doesn't make a lot of sense in this
               ;; approach
               #_(> (+ 48 D) len))
      (let [start-byte (help/read-ulong receive-buf)
            stop-byte (+ D start-byte)]
        ;; of course, flow control would avoid this case -- DJB
        ;; Q: What does that mean? --JRG
        (when (<= stop-byte (+ receive-written (.writableBytes receive-buf)))
          ;; 576-579: SF (StopFlag? deals w/ EOF)
          (let [receive-eof (case SF
                              0 false
                              normal-eof ::specs/normal
                              error-eof ::specs/error)
                receive-total-bytes (if (not= SF 0)
                                      stop-byte)
                ;; It's tempting to use a Pooled buffer here instead.
                ;; That temptation is wrong.
                ;; There's no good reason for this to be direct memory,
                ;; and "the JVM garbage collector...works OK for heap buffers,
                ;; but not direct buffers" (according to netty.io's wiki entry
                ;; about using it as a generic performance library).
                ;; It *is* tempting to retain the original direct
                ;; memory in which it arrived as long as possible. That approach
                ;; would probably make a lot more sense if I were using a JNI
                ;; layer for encryption.
                ;; As it stands, we've already stomped all over the source
                ;; memory long before it got here.
                output-buf (Unpooled/buffer D)]
            ;; 581-588: copy incoming into receivebuf
            (let [min-k (min 0 (- receive-written start-byte))  ; drop bytes we've already written
                  ;; Address at the limit of our buffer size
                  max-rcvd (+ receive-written recv-byte-buf-size)
                  ^Long max-k (min D (- max-rcvd start-byte))
                  delta-k (- max-k min-k)]
              (assert (<= 0 max-k))
              (assert (<= 0 delta-k))
              ;; There are at least a couple of curve balls in the air right here:
              ;; 1. Only write bytes at stream addresses(?)
              ;;    (< receive-written where (+ receive-written receive-buf-size))
              (.skipBytes receive-buf min-k)
              (.readBytes receive-buf output-buf max-k)
              ;; Q: Do I just want to release it, since I'm done with it?
              ;; Bigger Q: Shouldn't I just discard it completely?
              ;; And I've totally dropped the ball with output-buf.
              ;; The longer I look at this function, the fishier it smells.
              (.discardSomeReadBytes receive-buf)
              ;;          set the receivevalid flags
              ;; 2. Update the receive-valid flag associated with each byte as we go
              ;;    The receivevalid array is declared with this comment:
              ;;    1 for byte successfully received; XXX: use buddy structure to speed this up --DJB

              ;; 3. The array of receivevalid flags is used in the loop between lines
              ;;    589-593 to decide how much to increment receive-bytes.
              ;;    It's cleared on line 630, after we've written the bytes to the
              ;;    child pipe.
              ;; I'm fairly certain this is what that for loop amounts to
              (update state ::receive-bytes + (min (- max-rcvd receive-bytes)
                                                   (+ receive-bytes delta-k)))))))
      (do
        (log/warn (str "Gibberish Message packet from parent. D == " D))
        ;; This needs to short-circuit.
        ;; Q: is there a better way to accomplish that than just returning nil?
        state))))

(s/fdef flag-acked-others!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn flag-acked-others!
  "Lines 544-560"
  [{:keys [::specs/->child-buffer]
    :as state}]
  (let [receive-buf (last ->child-buffer)]
    (assert receive-buf (str "Missing receive-buf among\n" (keys state)))
    (let [indexes (map (fn [[startfn stopfn]]
                         [(startfn receive-buf) (stopfn receive-buf)])
                       [[(constantly 0) help/read-ulong]   ;  0-8
                        [help/read-uint help/read-ushort]       ; 16-20
                        [help/read-ushort help/read-ushort]     ; 22-24
                        [help/read-ushort help/read-ushort]     ; 26-28
                        [help/read-ushort help/read-ushort]     ; 30-32
                        [help/read-ushort help/read-ushort]])]   ; 34-36
      (dissoc
       (reduce (fn [{:keys [::stop-byte]
                     :as state}
                    [start stop]]
                 ;; This can't be right. Needs to be based on absolute
                 ;; stream addresses.
                 ;; Q: Doesn't it?
                 ;; A: Yes, definitely
                 (let [start-byte (+ stop-byte start)
                       stop-byte (+ start-byte stop)]
                   (assoc
                    (help/mark-acknowledged! state start-byte stop-byte)
                    ::stop-byte stop-byte)))
               (assoc state ::stop-byte 0)
               indexes)
       ::start-byte))))

(s/fdef recalc-rtt-average
        :args (s/cat :state ::state
                     :rtt ::rtt)
        :ret ::state)
(defn recalc-rtt-average
  "Lines 460-466"
  [{:keys [::specs/rtt-average]
    :as state}
   rtt]
  (if (not= 0 rtt-average)
    (assoc state
           ::n-sec-per-block rtt
           ::rtt-average rtt
           ::rtt-deviation (quot rtt 2)
           ::rtt-highwater rtt
           ::rtt-lowwater rtt)
    state))

(s/fdef jacobson-adjust-block-time
        :args (s/cat :n-sec-per-block ::specs/n-sec-per-block)
        :ret ::specs/n-sec-per-block)
(defn jacobson-adjust-block-time
  "Lines 496-509"
  [n-sec-per-block]
  ;; This next magic number matches the send-byte-buf-size, but that's
  ;; almost definitely just a coincidence
  (if (< n-sec-per-block K/k-128)
    n-sec-per-block
    ;; DJB had this to say.
    ;; As 4 separate comments.
    ;; additive increase: adjust 1/N by a constant c
    ;; rtt-fair additive increase: adjust 1/N by a constant c every nanosecond
    ;; approximation: adjust 1/N by cN every N nanoseconds
    ;; i.e., N <- 1/(1/N + cN) = N/(1 + cN^2) every N nanoseconds
    (if (< n-sec-per-block 16777216)
      (let [u (quot n-sec-per-block K/k-128)]
        (- n-sec-per-block (* u u u)))
      (let [d (double n-sec-per-block)]
        (long (/ d (inc (/ (* d d) 2251799813685248.0))))))))

(s/fdef adjust-rtt-phase
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn adjust-rtt-phase
  "Lines 511-521"
  [{:keys [::specs/n-sec-per-block
           ::specs/recent
           ::specs/rtt-phase
           ::specs/rtt-seen-older-high
           ::specs/rtt-seen-older-low]
    :as state}]
  (if (not rtt-phase)
    (if rtt-seen-older-high
      (assoc state
             ::specs/rtt-phase true
             ::specs/last-edge recent
             ::specs/n-sec-per-block (+ n-sec-per-block
                                        (crypto/random-mod (quot n-sec-per-block 4))))
      state)
    (if rtt-seen-older-low
      (assoc state ::specs/rtt-phase false)
      state)))

(defn jacobson's-retransmission-timeout
  "Jacobson's retransmission timeout calculation: --DJB

  I'm lumping lines 467-527 into here, even though I haven't
  seen the actual paper describing the algorithm. This is the
  basic algorithm that TCP uses pretty much everywhere. -- JRG"
  [{:keys [::last-doubling
           ::last-edge
           ::last-speed-adjustment
           ::n-sec-per-block
           ::recent
           ::rtt
           ::rtt-average
           ::rtt-deviation
           ::rtt-highwater
           ::rtt-lowwater
           ::rtt-seen-recent-high
           ::rtt-seen-recent-low
           ::rtt-timeout]
    :as state}]
  (let [rtt-delta (- rtt-average rtt)
        rtt-average (+ rtt-average (/ rtt-delta 8))
        rtt-delta (if (> 0 rtt-delta)
                    (- rtt-delta)
                    rtt-delta)
        rtt-delta (- rtt-delta rtt-deviation)
        rtt-deviation (+ rtt-deviation (/ rtt-delta 4))
        rtt-timeout (+ rtt-average (* 4 rtt-deviation))
        ;; adjust for delayed acks with anti-spiking: --DJB
        rtt-timeout (+ rtt-timeout (* 8 n-sec-per-block))

        ;; recognizing top and bottom of congestion cycle:  --DJB
        rtt-delta (- rtt rtt-highwater)
        rtt-highwater (+ rtt-highwater (/ rtt-delta K/k-1))
        rtt-delta (- rtt rtt-lowwater)
        rtt-lowwater (+ rtt-lowwater
                        (if (> rtt-delta 0)
                          (/ rtt-delta K/k-8)
                          (/ rtt-delta K/k-div4)))
        rtt-seen-recent-high (> rtt-average (+ rtt-highwater K/ms-5))
        rtt-seen-recent-low (and (not rtt-seen-recent-high)
                                 (< rtt-average rtt-lowwater))]
    (when (>= recent (+ last-speed-adjustment (* 16 n-sec-per-block)))
      (let [n-sec-per-block (if (> (- recent last-speed-adjustment) K/secs-10)
                              (+ K/secs-1 (crypto/random-mod (quot n-sec-per-block 8)))
                              n-sec-per-block)
            n-sec-per-block (jacobson-adjust-block-time n-sec-per-block)
            state (assoc state ::n-sec-per-block n-sec-per-block)
            {:keys [::specs/rtt-seen-recent-high ::specs/rtt-seen-recent-low]
             :as state} (adjust-rtt-phase state)
            state (assoc state
                         ::specs/last-speed-adjustment recent
                         ::specs/n-sec-per-block n-sec-per-block

                         ::specs/rtt-average rtt-average
                         ::specs/rtt-deviation rtt-deviation
                         ::specs/rtt-highwater rtt-highwater
                         ::specs/rtt-lowwater rtt-lowwater
                         ::specs/rtt-timeout rtt-timeout

                         ::specs/seen-older-high rtt-seen-recent-high
                         ::specs/seen-older-low rtt-seen-recent-low
                         ::specs/seen-recent-high false
                         ::specs/seen-recent-low false)
            been-a-minute? (- recent last-edge K/minute-1)]
        (cond
          (and been-a-minute?
               (< recent (+ last-doubling
                            (* 4 n-sec-per-block)
                            (* 64 rtt-timeout)
                            K/ms-5))) state
          (and (not been-a-minute?)
               (< recent (+ last-doubling
                            (* 4 n-sec-per-block)
                            (* 2 rtt-timeout)))) state
          (<= (dec K/k-64) n-sec-per-block) state
          :else (assoc state {::n-sec-per-block (quot n-sec-per-block 2)
                              ::last-doubling recent
                              ::last-edge (if (not= 0 last-edge) recent last-edge)}))))))

(s/fdef flag-acked
        :args (s/cat :state ::specs/state
                     :acked-block ::specs/block)
        :ret ::state)
(defn flag-acked
  "It looks like this is coping with the first sent/ACK'd message from the child

  TODO: Better name
  Lines 458-541"
  [{:keys [::recent]
    :as state}
   {:keys [::time]
    :as acked-block}]
  (let [rtt (- recent time)
        state (recalc-rtt-average state rtt)]
    (jacobson's-retransmission-timeout state)))

(s/fdef handle-comprehensible-child-message
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
(defn handle-comprehensible-child-message
  "handle this message if it's comprehensible: (DJB)

  This seems like the interesting part.
  lines 444-609"
  [{:keys [::specs/blocks
           ::specs/->child-buffer]
    :as state}]
  (let [^ByteBuf msg (first ->child-buffer)
        len (.readableBytes msg)]
    (when (and (>= len min-msg-len)
               (<= len max-msg-len))
      (let [msg-id (help/read-uint msg) ;; won't need this (until later?), but need to update read-index anyway
            ack-id (help/read-uint msg)
            ;; Note that there's something terribly wrong if we
            ;; have multiple blocks with the same message ID.
            ;; Q: Isn't there?
            acked-blocks (filter #(= ack-id (::message-id %))
                                 blocks)
            flagged (-> (reduce flag-acked state acked-blocks)
                          ;; That takes us down to line 544
                          flag-acked-others!)
            extracted (extract-message-from-parent flagged)]
        (if extracted
          (do
            (send-ack! state)
            (dissoc extracted ::specs/send-buf))
          flagged)))))

(s/fdef try-processing-message
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
(defn try-processing-message
  "436-614: try processing a message: --DJB"
  [{:keys [::specs/->child-buffer
           ::specs/receive-bytes
           ::specs/receive-written]
    :as state}]
  (when-not (or (= 0 (count ->child-buffer))  ; any incoming messages to process?
                ;; This next check includes an &&
                ;; to verify that tochild is > 0 (I'm
                ;; pretty sure that's just verifying that
                ;; it's open)
                ;; I think the point of this next check
                ;; is back-pressure:
                ;; If we have pending bytes from the parent that have not
                ;; been written to the child, don't add more.
                (< receive-written receive-bytes))
    ;; 440: sets maxblocklen=1024
    ;; Q: Why was it ever 512?
    ;; Guess: for initial Message part of Initiate packet
    (let [state' (assoc state ::max-byte-length K/k-1)]
      (handle-comprehensible-child-message state))))

(defn forward-to-child
  "From the buffer that parent has filled

  615-632: try sending data to child: --DJB

  Big picture: copy data from receivebuf to the child[1] pipe
  Then zero the receivevalid flags"
  [{:keys [::specs/strm->child
           ::specs/receive-buf]
    :as state}]
  ;; Doesn't seem to be used.
  ;; Which is good. Should be able to just call
  ;; ->child (which is what the try-put!
  ;; would do eventually on some thread) directly.
  ;; This leaves the question "What should happen if
  ;; that blocks?"
  (throw (RuntimeException. "obsolete"))
  ;; If the child's open *and available for output*, write whichever
  ;; bytes are available in receive-buf.
  ;; Those bytes would have pulled in pretty much directly above,
  ;; in read-from-parent! and then ACK'd.

  ;; Note that this probably needs to go through some sort of
  ;; potentially blocking queue. Like, say, a core.async channel.
  ;; Although, really, we need to verify that the queue is
  ;; available for writing before we try (line 616)

  ;; So I probably need something that starts like this:
  (strm/try-put! strm->child receive-buf 0 ::timeout))

;;;
;;;
;;;
;;;  634-643: try closing pipe to child: (DJB)
;;;           Well, maybe. If we're done with it

;;; 444-609 handle this message if it's comprehensible: (DJB)
;;; (in more depth)
;;;         445-450: boilerplate
;;;         452-453: short-circuiting
;;;         455: extract ID
;;;         456-542: loop over range(blocknum)
;;;                  This looks like the "real" Chicago algorithm
;;;         544-560: Call acknowledged() several times
;;;                  This is for several byte ranges in the incoming message
;;;                  0 to the 8-byte offset starting at byte 8
;;;                  Then we have pairs of start/stop offsets
;;;                  where each start is from the previous stop
;;;                  This seems a bit tedious/inefficient, esp. since
;;;                  lines 396-401 seem to ignore everything except
;;;                  the blockid[pos] at position 8 (aka 0) and then
;;;                  positions 46 and 48.
;;;                  Those are really the length at position 38 and initial
;;;                  offset at position 40, thanks to starting the send
;;;                  with length/16 at offset 7.
;;;        589-593: increment the receivebytes count
;;;        595: never acknowledge a pure acknowledgment (DJB)
;;;             This short-circuits if something extracts to 0
;;;             (looks like this is the first of the message structure,
;;;             which would be the message ID)
;;;        597: /* XXX: delay acknowledgments */ (DJB)
;;;        598-608: Looks like this just ACKs everything
;;;                 Evidence:
;;;        606: /* XXX: incorporate selective acknowledgents */ (DJB)

;;; 456-542: Loop over (range blocknum)
;;; (getting into details)

(defn trigger-event-loop!
  "This gets triggered any time there's a write event

  This mainly means that someone called parent-> or child->,
  but also includes periodic timeouts"
  [state-atom]
  ;; It seems as though this should kick off the shebang.
  ;; Realistically, it should do the same sort of work that
  ;; happens at the top of main() in the reference implementation
  ;; to skip working on pieces that couldn't possibly be ready
  ;; yet.
  ;; And this must be thread-safe.
  ;; I'm very tempted to have the caller send a signal to
  ;; a go loop instead.
  ;; I'm also very tempted to just stick state into an agent
  ;; instead of an atom.
  ;; This needs more thought.
  (throw (RuntimeException. "How should this work?")))

(s/fdef start-event-loops!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn start-event-loops!
  "This still needs to set up timers...which are going to be interesting.
;;;          205-259 fork child
"
  [{:keys [::specs/callbacks]
    :as state}]
  ;; At its heart, the reference implementation message event
  ;; loop is driven by a poller.
  ;; That checks for input on:
  ;; fd 8 (from the parent)
  ;; tochild[1] (to child)
  ;; fromchild[0] (from child)
  ;; and a timeout (based on the messaging state).

  ;; I want to keep any sort of deferred/async details
  ;; as well-hidden as possible.
  ;; This is a boundary piece that almost seems tailor-made.
  ;; Although I really do need to figure out what makes sense
  ;; as "buffer size."
  ;; And it might make a lot of sense to spread it farther
  ;; than I'm using it now to try to take advantage of
  ;; the transducer capabilities.
  ;; By the same token, it's very tempting to just use
  ;; a core.async channel instead.
  ;; The only reason I'm not now is that I already have
  ;; access to manifold thanks to aleph, and I don't want
  ;; to restart my JVM to update build.boot to get access
  ;; to core.async.
  (assoc state
         ;; This covers line 260
         ::specs/recent (System/nanoTime)))

(defn trigger-io
  [{:keys [::specs/->child]
    :as state}]
  (-> state
      (assoc ::specs/recent (System/nanoTime))
      maybe-send-block!
      try-processing-message
      ->child
      ;; At the end, there's a block that closes the pipe
      ;; to the child if we're done.
      ;; I think the point is that we'll quit polling on
      ;; that and start short-circuiting out of the blocks
      ;; that might do the send, once we've hit EOF
      ;; Q: is there anything sensible I can do here to
      ;; produce the same effect?
      ))

(defn trigger-from-timer
  [state]
  (trigger-io state))

(defn trigger-from-parent
  "Message block arrived from parent. We have work to do."
  [{{:keys [::specs/->child]} ::specs/callbacks
    :as state}
   buf]
  (when-not ->child
    (throw (ex-info "Missing ->child"
                    {::callbacks (::specs/callbacks state)})))
  ;; This is basically an iteration of the top-level
  ;; event-loop handler from main().
  ;; I can skip the pieces that only relate to reading
  ;; from the child, because I'm using an active callback
  ;; approach, and this was triggered by a block of
  ;; data coming from the parent.
  (let [ready-to-ack (-> state
                         ;; Q: Are the next 2 lines worth their own functions?
                         (update ::specs/->child-buffer conj buf)
                         ;; This one really seems so, since I'm calling it
                         ;; in at least 3 different places now
                         (assoc ::specs/recent (System/nanoTime))
                         ;; This is about sending from the child to parent
                         maybe-send-block!
                         ;; Next obvious piece is the "try receiving messages:"
                         ;; block.
                         ;; But I've already changed the order of operations by
                         ;; doing that up front in parent->, which is what called
                         ;; this.
                         ;; Now that I'm going back through the big-picture items,
                         ;; that decision seems less valid than it did when I was
                         ;; staring at each tree in the forest.
                         ;; It probably doesn't matter, but I've dealt with enough
                         ;; subtleties in the original code that I'm very nervous
                         ;; about that "probably"
                         ;; OTOH, this leaves everything that follows pleasingly
                         ;; duplicated (and ripe for refactoring) with trigger-from-timer
                         ;; and trigger-from-child
                         )]
    (if-let [primed (try-processing-message ready-to-ack)]
      (try
        (let [{:keys [::specs/->child-buffer]} primed
              ^"[Lio.netty.buffer.ByteBuf;" args (into-array ByteBuf ->child-buffer)
              response (Unpooled/copiedBuffer args)]
          (->child primed response)
          ;; 610-614: counters/looping
          (assoc primed
                  ::specs/->child-buffer
                  []))
        (catch RuntimeException ex
          ;; Reference implementation specifically copes with
          ;; EINTR, EWOULDBLOCK, and EAGAIN.
          ;; Any other failure means just closing the child pipe.
          primed))
      (do
        ;; The message from parent to child was garbage.
        ;; Discard.
        ;; Q: Does this make sense?
        ;; It leaves our "global" state updated in a way that left us unable
        ;; to send earlier. That isn't likely to get fixed the next time
        ;; through the event loop.
        ;; (I'm hitting this because I'm sending a gibberish message that
        ;; needs to be discarded)
        (throw (RuntimeException. "How does DJB really handle this discard?"))
        ready-to-ack))))

(defn trigger-from-child
  [state buf]
  (trigger-io
   (if (room-for-child-bytes? state)
     (child-consumer state buf)
     state)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef start!
        :args (s/cat :state ::state-agent)
        :ret ::state-agent)
(defn start!
  ([state-agent timeout]
   (send state-agent start-event-loops!)
   (if (await-for timeout state-agent)
     state-agent
     (throw (ex-info "Starting failed"
                     {::problem (agent-error state-agent)}))))
  ([state-agent]
   (start! state-agent 250)))

(defn halt!
  [state]
  ;; TODO: Surely there's something
  state)

(s/fdef initial-state
        :args (s/cat :parent-callback ::specs/->parent
                     :child-callback ::specs/->child
                     ;; Q: What's the difference to spec that this
                     ;; argument is optional?
                     :want-ping ::specs/want-ping)
        :ret ::state-agent)
(defn initial-state
  ([parent-callback
    child-callback
    want-ping]
   (agent {::specs/->child-buffer []
           ::specs/blocks []
           ::specs/earliest-time 0
           ::specs/last-doubling 0
           ::specs/last-edge 0
           ::specs/last-speed-adjustment 0
           ::specs/max-block-length K/k-div2
           ;; Seems vital, albeit undocumented
           ::specs/n-sec-per-block specs/sec->n-sec
           ::specs/receive-bytes 0
           ::specs/receive-eof false
           ::specs/receive-total-bytes 0
           ::specs/receive-written 0
           ;; In the original, this is a local in main rather than a global
           ;; Q: Is there any difference that might matter to me, other
           ;; than being allocated on the stack instead of the heap?
           ;; (Assuming globals go on the heap. TODO: Look that up)
           ::specs/recent 0
           ::specs/rtt 0
           ::specs/rtt-phase false
           ::specs/rtt-seen-older-high false
           ::specs/rtt-seen-older-low false
           ::specs/rtt-seen-recent-high false
           ::specs/rtt-seen-recent-low false
           ::specs/rtt-timeout specs/sec->n-sec
           ::specs/send-acked 0
           ::specs/send-buf-size send-byte-buf-size
           ::specs/send-bytes 0
           ::specs/send-eof false
           ::specs/send-eof-processed false
           ::specs/send-eof-acked false
           ::specs/send-processed 0
           ::specs/total-blocks 0
           ::specs/total-block-transmissions 0
           ::specs/callbacks {::specs/->child child-callback
                              ::specs/->parent parent-callback}
           ::specs/want-ping want-ping}))
  ([parent-callback child-callback]
   (initial-state parent-callback child-callback false)))

(s/fdef child->
        :args (s/cat :state-agent ::state-agent
                     :buf ::specs/buf)
        :ret ::state-agent)
(defn child->
  "Read bytes from a child buffer...if we have room

The only real question seems to be what happens
when that buffer overflows.

In the original, that buffer is really just an
anonymous pipe between the processes, so there
should be quite a lot of room.

According to the pipe(7) man page, linux provides
16 \"pages\" of buffer space. So 64K, if the page
size is 4K. At least, it has since 2.6.11.

Prior to that, it was limited to 4K.

;;;  319-336: Maybe read bytes from child
"
  [state-agent
   buf]
  ;; I'm torn about send vs. send-off here.
  ;; This very well *could* take a measurable amount
  ;; of time, and we could wind up with a ton of threads
  ;; if there's a lot of data flowing back and forth.
  ;; Note that the client count isn't a direct factor here,
  ;; since each client should receive its own agent.
  ;; This is something to watch and measure.
  ;; Go with send for now, since it's recommended for
  ;; CPU- (as opposed to IO-) bound actions.
  ;; And I don't think there's anything here that
  ;; could block.
  ;; Except for those actual pesky sends to the
  ;; child/parent.
  (send state-agent trigger-from-child buf))

(s/fdef parent->
        :args (s/cat :state ::state-agent
                     :buf ::specs/buf)
        :ret ::state-agent)
(defn parent->
  "Receive a ByteBuf from parent

  411-435: try receiving messages: (DJB)

  The parent is going to call this. It should trigger
  the pieces that naturally fall downstream and lead
  to writing the bytes to the child.

  It's replacing one of the polling triggers that
  set off the main() event loop. Need to account for
  that fundamental strategic change"
  [state-agent
   ^ByteBuf buf]
;;;           From parent (over watch8)
;;;           417-433: for loop from 0-bytes read
;;;                    Copies bytes from incoming message buffer to message[][]
  (let [incoming-size (.readableBytes buf)]
    (when (= 0 incoming-size)
      ;; This is supposed to kill the entire process
      ;; TODO: Be more graceful
      (throw (AssertionError. "Bad Message")))

    ;; Reference implementation is really reading bytes from
    ;; a stream.
    ;; It reads the first byte to get the length of the block,
    ;; pulls the next byte from the stream, calculates the stream
    ;; length, double-checks for failure conditions, and then copies
    ;; the bytes into the last spot in the global message array
    ;; (assuming that array/buffer hasn't filled up waiting for the
    ;; client to process it).

    ;; I'm going to take a simpler and easier approach, at least for
    ;; the first pass.
    ;; Note that I've actually taken 2 approaches that, really, are
    ;; mutually exclusive.
    ;; trigger-from-parent is expecting to have a ::->child-buffer key
    ;; that's really a vector that we can just conj onto.
    (let [{:keys [::specs/->child-buffer]} @state-agent]
      (if (< (count ->child-buffer) max-child-buffer-size)
        (let [previously-buffered-message-bytes (reduce + 0
                                                    (map (fn [^ByteBuf buf]
                                                           (.readableBytes buf))
                                                         ->child-buffer))]
          ;; Probably need to do something with previously-buffered-message-bytes.
          ;; Definitely need to check the number of bytes that have not
          ;; been forwarded along yet.
          ;; However, the reference implementation does not.
          ;; Then again...it's basically a self-enforcing
          ;; 64K buffer, so maybe it's already covered, and I just wasted
          ;; CPU cycles calculating it.
          (if (<= max-msg-len incoming-size)
            ;; See comments in child-> re: send vs. send-off
            (send state-agent  trigger-from-parent buf)
            (do
              (log/warn (str "Child buffer overflow\n"
                             "Incoming message is " incoming-size
                             " / " max-msg-len))
              state-agent)))
        state-agent))))
