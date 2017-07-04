(ns frereth-cp.message
  "Translation of curvecpmessage.c

This is really a generic buffer program

The \"parent\" child/server reads/writes to pipes that this provides,
in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns."
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.crypto :as crypto]
            [manifold.stream :as strm])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def stream-length-limit
  "How many bytes can the stream send before we've exhausted the address space?

(dec (pow 2 60)): this allows > 200 GB/second continuously for a year"
  1152921504606846976)

(def k-div4
  "aka 1/4 k"
  256)

(def k-div2
  "aka 1/2 k"
  512)

(def k-1
  "aka 1k"
  1024)

(def k-2
  "aka 2k"
  2048)

(def k-4
  "aka 4k"
  4096)

(def k-8
  "aka 8k"
  8192)

(def k-64
  "aka 128k"
  65536)

(def k-128
  "aka 128k"
  131072)

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
  k-128)

(def max-outgoing-blocks
  "How many outgoing, non-ACK'd blocks will we buffer?

Corresponds to OUTGOING in the reference implementation.

That includes a comment that it absolutely must be a power of 2.

I think that's because it uses bitwise and for modulo to cope
with the ring buffer semantics, but there may be a deeper motivation."
  128)

(def max-block-length
  512)

;; (dec (pow 2 32))
(def MAX_32_UINT 4294967295)

(def error-eof k-4)
(def normal-eof k-2)

(def max-child-buffer-size
  "Maximum message blocks from parent to child that we'll buffer before dropping

  must be power of 2 -- DJB"
  64)

(def min-msg-len 48)
(def max-msg-len 1088)
(def ms-5
  "5 milliseconds, in nanoseconds"
  5000000)

(def secs-1
  "in nanoseconds"
  specs/sec->n-sec)

(def secs-10
  "in nanoseconds"
  (* secs-1 10))

(def minute-1
  "in nanoseconds"
  (* 60 secs-1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef start-event-loops!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn start-event-loops!
  "
;;;          205-259 fork child
"
  [{:keys [::specs/callbacks]
    :as state}]
  (let [{:keys [::specs/->child ::specs/->parent]} callbacks]
    ;; I think the main idea of this module is that I should set up
    ;; transducing pipelines between child and parent
    ;; That isn't right, though.
    ;; The entire point, really, is to maintain a buffer between the
    ;; two until the blocks in that buffer have been ACK'd
    ;; Although managing the congestion control aspects of that
    ;; buffer definitely play a part
    (throw (RuntimeException. "What should this look like?"))

    ;; This covers line 260
    (assoc state ::specs/recent (System/nanoTime))))

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

(s/fdef child-consumer
        :args (s/cat :state ::specs/state
                     :buf ::specs/buf))
(defn child-consumer
  "Accepts blocks of bytes from the child.

The obvious approach is just to feed ByteBuffers
from this callback to the parent's callback.

That obvious approach completely misses the point that
this is a buffer. We need to hang onto those buffers
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
  [{:keys [::specs/send-bytes]
    :as state}
   buf]
  ;; Q: Need to apply back-pressure if we
  ;; already have ~124K pending?
  ;; (It doesn't seem like it should matter, except
  ;; as an upstream signal that there's a network
  ;; issue)
  (let [block {::buf buf
               ::transmissions 0}
        send-bytes (+ send-bytes (.getReadableBytes buf))]
    (when (>= send-bytes stream-length-limit)
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
           ::specs/last-block-time
           ::specs/last-edge
           ::specs/last-panic
           ::specs/n-sec-per-block
           ::specs/recent
           ::specs/rtt-timeout]
    :as state}]
  (when (and (< recent (+ last-block-time n-sec-per-block))
             (not= 0 earliest-time)
             (>= recent (+ earliest-time rtt-timeout)))
    ;; This gets us to line 344
    ;; It finds the first block that matches earliest-time
    ;; It's going to re-send that block (it *does* exist...right?)
    ;; TODO: Need to verify that nothing fell through the cracks
    ;; But first, it might adjust some of the globals.
    (reduce (fn [{:keys [::block-index]
                  :as acc} block]
              (if (= earliest-time (::specs/time block))
                (reduced
                 (assoc
                  (if (> recent (+ last-panic (* 4 rtt-timeout)))
                    (assoc state
                           ::specs/current-block-cursor [block-index]
                           ::specs/n-sec-per-block (* n-sec-per-block 2)
                           ::specs/last-panic recent
                           ::specs/last-edge recent))))
                (update acc ::block-index inc)))
            (assoc state
                   ::block-index 0)
            blocks)))

(defn check-for-new-block-to-send
  "Q: Is there a new block ready to send?

  357-378:  Sets up a new block to send
  Along w/ related data flags in parallel arrays"
  [{:keys [::specs/blocks
           ::specs/last-block-time
           ::specs/n-sec-per-block
           ::specs/recent
           ::specs/send-acked
           ::specs/send-bytes
           ::specs/send-eof
           ::specs/send-eof-processed
           ::specs/send-processed
           ::specs/want-ping]
    :as state}]
  (when (and (>= recent (+ last-block-time n-sec-per-block))
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
                    #(< (+ k-1 k-4) %)))
(defn calculate-message-data-block-length-flags
  [block]
  (let [len (::specs/length block)]
    (bit-or len
            (case (::specs/send-eof block)
              false 0
              ::specs/normal ::normal-eof
              ::specs/error ::fail-eod))))

(defn pre-calculate-state-after-send
  "This is mostly setting up the buffer to do the send

  Starts with line 380 sendblock:
  Resending old block will goto this

  It's in the middle of a do {} while(0) loop"
  [{:keys [::specs/block-to-send
           ::specs/buf
           ::specs/next-message-id
           ::specs/recent
           ::specs/send-buf
           ::specs/send-buf-size]
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

  ;; This takes me back to requiring ::pos
  (throw (RuntimeException. "More important to update the proper place in ::blocks"))
  (let [next-message-id (let [n' (inc next-message-id)]
                          ;; Stupid unsigned math
                          (if (> n' MAX_32_UINT)
                            1 n'))
        state'
        (-> state
            (update-in [::specs/block-to-send ::specs/transmissions] inc)
            (update-in [::specs/block-to-send ::specs/time recent])
            (assoc-in [::specs/block-to-send ::message-id] next-message-id)
            (assoc ::next-message-id next-message-id))
        {:keys [::specs/block-to-send]} state'
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
              (> k-1 block-length))
      (throw (AssertionError. "illegal block length")))
    ;; We need a prefix byte that tells the other end (/ length 16)
    ;; I'm fairly certain that this extra up-front padding is to set
    ;; up word alignment boundaries so the actual byte copies can proceed
    ;; quickly.
    ;; TODO: Time it without this to see whether it makes any difference.
    (comment)
    (shared/zero-out! buf 0 8)
    ;; This extra length byte is a key part of the reference
    ;; interface.
    ;; Q: Does it make any sense in this context?
    (aset buf 7 (quot u 16))

    (comment
      ;; This is probably the way I need to handle that,
      ;; Since buf really needs to be a ByteBuf
      ;; But I'm jumbling together ByteBuf vs. Byte Array
      ;; (see the various calls to pack! that follow)
      ;; This is broken.
      (.writeBytes buf (byte-array 7))
      (.writeByte buf (quot u 16)))

    (b-t/uint32-pack! buf 8 next-message-id)
    ;; XXX: include any acknowledgments that have piled up (--DJB)
    ;; SUCC/FAIL flag | data block size
    (b-t/uint16-pack! buf 46 (calculate-message-data-block-length-flags block-to-send))
    ;; stream position of the first byte in the data block being sent
    (b-t/uint64-pack! buf 48 (::start-pos block-to-send))
    ;; Copy bytes to the send-buf
    ;; TODO: make this thread-safe.
    ;; Need to save the initial read-index because we aren't ready
    ;; to discard the buffer until it's been ACK'd.
    ;; This is a fairly hefty departure from the reference implementation,
    ;; which is all based around the circular buffer concept.
    ;; I keep telling myself that a ByteBuffer will surely be fast
    ;; enough.
    (.markReaderIndex buf)
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
           ::last-block-time recent
           ::want-ping 0
           ::earliest-time (help/earliest-block-time (::blocks state')))))

(defn block->parent!
  "Actually send the message block to the parent

  Corresponds to line 404 under the sendblock: label"
  [{{:keys [::specs/->parent]} ::specs/callbacks
    :keys [::specs/send-buf]
    :as state}]
  ;; Don't forget the special offset+7
  (->parent (.copy send-buf ))
  (throw (RuntimeException. "sendblock:")))

(defn pick-next-block-to-send
  [state]
  (or (check-for-previous-block-to-resend state)
;;;       357-410: Try sending a new block: (-- DJB)
                  ;; There's goto-fun overlap with resending
                  ;; a previous block -- JRG
      (check-for-new-block-to-send state)))

(defn maybe-send-block
  [state]
  (if-let [state' (pick-next-block-to-send state)]
    (let [state'' (pre-calculate-state-after-send state')]
      (block->parent! state'')
;;;      408: earliestblocktime_compute()
      ;; TODO: Honestly, we could probably shave some time/effort by
      ;; just tracking the earliest block here instead of searching for
      ;; it in check-for-previous-block-to-resend
      (assoc state'' ::earliest-time (help/earliest-block-time (::blocks state''))))
    state))

(defn send-ack!
  "Write ACK buffer to parent

Line 608"
  [{{:keys [::specs/->parent]} ::specs/callbacks
    buf ::specs/buf
    :as state}]
  ;; Q: Is it really this simple/easy?
  (->parent buf))

(defn prep-send-ack
  "Lines 595-606"
  [{:keys [::specs/buf
           ::specs/current-block-cursor
           ::specs/receive-bytes
           ::specs/receive-eof
           ::specs/receive-total-bytes]
    :as state}
   message-id]
  (if (not= message-id)
    (let [u 192]
      ;; XXX: delay acknowledgments  --DJB
      (.writeLong buf (quot u 16))
      (.writeInt buf message-id)
      (.writeLong buf (if (and receive-eof
                               (= receive-bytes receive-total-bytes))
                        (inc receive-bytes)
                        receive-bytes))
      ;; XXX: incorporate selective acknowledgments --DJB
      )
    ;; Don't want to ACK a pure-ACK message with no content
    state))

(s/fdef extract-message-from-parent
        :args (:state ::specs/state)
        :ret ::specs/state)
(defn extract-message-from-parent
  "Lines 562-593"
  [{:keys [::specs/buf]
    :as state}]
  ;; 562-574: calculate start/stop bytes
  (let [D (help/read-ushort buf)
        SF (bit-and D (+ k-2 k-4))
        D (- D SF)]
    (when (and (<= D 1024)
               ;; In the reference implementation,
               ;; len = 16 * (unsigned long long) messagelen[pos]
               ;; (assigned at line 443)
               ;; This next check looks like it really
               ;; amounts to "have we read all the bytes
               ;; in this block from the parent pipe?"
               ;; It doesn't make a lot of sense in this
               ;; approach
               #_(> (+ 48 D) len))
      (let [start-byte (help/read-ulong buf)
            stop-byte (+ D start-byte)]
        ;; of course, flow control would avoid this case -- DJB
        ;; I've just totally painted receivebuf out of the picture.
        ;; Q: How foolish was that?
        (comment (when (<= stop-byte (+ receive-written (count receivebuf)))))
        ;; 576-579: SF (StopFlag? deals w/ EOF)
        (let [receive-eof (case SF
                            0 false
                            k-2 ::specs/normal
                            k-4 ::specs/error)
              receive-total-bytes (if (not= SF 0)
                                    stop-byte)]
          ;; 581-588: copy incoming into receivebuf
          ;;          set the receivevalid flag

          (throw (RuntimeException. "Q: What does receivebuf look like?")))))))

(s/fdef flag-acked-others!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn flag-acked-others!
  "Lines 544-560"
  [{:keys [::specs/buf]
    :as state}]
  (let [indexes (map (fn [startfn stopfn]
                       [(startfn buf) (stopfn buf)])
                     [(constantly 0) help/read-ulong]  ; 0-8
                     [help/read-uint help/read-ushort]       ; 16-20
                     [help/read-ushort help/read-ushort]     ; 22-24
                     [help/read-ushort help/read-ushort]     ; 26-28
                     [help/read-ushort help/read-ushort]     ; 30-32
                     [help/read-ushort help/read-ushort])]   ; 34-36
    ;; TODO: Desperately need to test this out to verify
    ;; that it does what I think
    (reduce (fn [state [start stop]]
              (help/mark-acknowledged state start stop))
            state
            indexes)))

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
  (if (< n-sec-per-block k-128)
    n-sec-per-block
    ;; DJB had this to say.
    ;; As 4 separate comments.
    ;; additive increase: adjust 1/N by a constant c
    ;; rtt-fair additive increase: adjust 1/N by a constant c every nanosecond
    ;; approximation: adjust 1/N by cN every N nanoseconds
    ;; i.e., N <- 1/(1/N + cN) = N/(1 + cN^2) every N nanoseconds
    (if (< n-sec-per-block 16777216)
      (let [u (quot n-sec-per-block k-128)]
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
        rtt-highwater (+ rtt-highwater (/ rtt-delta k-1))
        rtt-delta (- rtt rtt-lowwater)
        rtt-lowwater (+ rtt-lowwater
                        (if (> rtt-delta 0)
                          (/ rtt-delta k-8)
                          (/ rtt-delta k-div4)))
        rtt-seen-recent-high (> rtt-average (+ rtt-highwater ms-5))
        rtt-seen-recent-low (and (not rtt-seen-recent-high)
                                 (< rtt-average rtt-lowwater))]
    (when (>= recent (+ last-speed-adjustment (* 16 n-sec-per-block)))
      (let [n-sec-per-block (if (> (- recent last-speed-adjustment) secs-10)
                              (+ secs-1 (crypto/random-mod (quot n-sec-per-block 8)))
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
            been-a-minute? (- recent last-edge minute-1)]
        (cond
          (and been-a-minute?
               (< recent (+ last-doubling
                            (* 4 n-sec-per-block)
                            (* 64 rtt-timeout)
                            ms-5))) state
          (and (not been-a-minute?)
               (< recent (+ last-doubling
                            (* 4 n-sec-per-block)
                            (* 2 rtt-timeout)))) state
          (<= (dec k-64) n-sec-per-block) state
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
        :ret ::specs/state)
(defn handle-comprehensible-child-message
  "Lots of code in here.

  This seems like the interesting part.
  444-609: handle this message if it's comprehensible: (DJB)"
  [{:keys [::specs/blocks
           ::specs/->child-buffer]
    :as state}]
  (let [msg (first ->child-buffer)
        len (.getReadableBytes msg)]
    (when (and (>= len min-msg-len)
               (<= len max-msg-len))
      (let [msg-id (help/read-uint msg) ;; won't need this (until later?), but need to update read-index anyway
            ack-id (help/read-uint msg)
            ;; Note that there's something terribly wrong if we
            ;; have multiple blocks with the same message ID.
            ;; Q: Isn't there?
            acked-blocks (filter #(= ack-id (::message-id %))
                                 blocks)
            state (-> (partial flag-acked state)
                      (reduce acked-blocks)
                      ;; That takes us down to line 544
                      (flag-acked-others! state)
                      (extract-message-from-parent state)
                      (prep-send-ack state msg-id))]
        (send-ack! state)
        state))))

(s/fdef try-processing-message
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn try-processing-message
  "436-614: try processing a message: --DJB"
  [{:keys [::specs/->child-buffer
           ::specs/receive-bytes
           ::specs/receive-written]
    :as state}]
  (when-not (or (= 0 (count ->child-buffer))
                ;; This next check includes an &&
                ;; to verify that tochild is > 0 (I'm
                ;; pretty sure that's just verifying that
                ;; it's open)
                ;; The meaning of receive-written and
                ;; receive-bytes doesn't seem to mesh
                ;; with the comments about them, based
                ;; on this test.
                ;; Maybe it will make more sense when
                ;; I get more translated over
                (< receive-written receive-bytes))
    ;; 440: sets maxblocklen=1024
    ;; Q: Why was it ever 512?
    ;; Guess: for initial Message part of Initiate packet
    (let [state (assoc state ::max-byte-length k-1)]
      ;; 610-614: counters/looping
      (update
       (handle-comprehensible-child-message state)
       ::specs/->child-buffer
       ;; Q: Do I need to convert the lazy seq this creates
       ;; back to a vec?
       ;; ByteBuf life cycle issues seem like they might lead
       ;; to lots of problems later if I don't.
       #(drop 1 %)))))

(defn forward-to-child
  "From the buffer that parent has filled

  615-632: try sending data to child: --DJB

  Big picture: copy data from receivebuf to the child[1] pipe
  Then zero the receivevalid flags"
  [{:keys [::specs/->child]
    :as callbacks}
   buf]
  ;; There isn't any real buffering in this direction.
  ;; If the child's open, write whichever bytes are available
  ;; in receive-buf.
  ;; Those bytes would have pulled in pretty much directly above,
  ;; in read-from-parent! and then ACK'd.
  ;; So maybe this part isn't a total waste, but there are definitely
  ;; pieces that feel silly.

  ;; At the very most, it seems as though this should amount to
  ;; something like:
  (->child buf)
  ;; But not quite. I *have* just finished a lot of work to
  ;; extract the bits the child cares about
  )

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef start!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn start!
  [state]
  (assoc state :event-loops (start-event-loops! state)))

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
        :ret ::specs/state)
(defn initial-state
  ([parent-callback
     child-callback
    want-ping]
   {::specs/blocks []
    ::specs/earliest-time 0
    ::specs/last-doubling 0
    ::specs/last-edge 0
    ::specs/last-speed-adjustment 0
    ::specs/max-block-length k-div2
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
    ::specs/rtt-seen-recent-lowi false
    ::specs/rtt-timeout specs/sec->n-sec
    ::specs/send-buf (Unpooled/buffer send-byte-buf-size)
    ::specs/send-buf-size send-byte-buf-size
    ::specs/send-eof false
    ::specs/send-eof-processed false
    ::specs/send-eof-acked false
    ::specs/total-blocks 0
    ::specs/total-block-transmissions 0
    ::specs/callbacks {::specs/child child-callback
                       ::specs/parent parent-callback}
    ::specs/want-ping want-ping})
  ([parent-callback child-callback]
   (initial-state parent-callback child-callback false)))

(s/fdef child->
        :args (s/cat :state ::specs/state
                     :buf ::specs/buf))
(defn child->
  "Read bytes from a child buffer...if we have room

This is upside down: the API should be that
child makes a callback.

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
  [state
   buf]
  (let [send-bytes (::send-bytes state)]
    ;; Line 322: This also needs to account for send-acked
    ;; For whatever reason, DJB picked this as the end-point to refuse to read
    ;; more child data before we hit send-byte-buf-size.
    ;; Presumably that reason remains valid

    ;; Q: Is that an important part of the algorithm, or is
    ;; it "just" dealing with the fact that we have a circular
    ;; buffer with parts that have not yet been GC'd?
    ;; And is it possible to tease apart that distinction?

    (when (< (+ send-bytes k-4) send-byte-buf-size)
      (let [available-buffer-space (- send-byte-buf-size)
            buffer (.readBytes buf available-buffer-space)]
        (child-> state buffer)))))

(s/fdef parent->
        :args (s/cat :state ::specs/state
                     :buf ::specs/buf)
        :ret ::specs/state)
(defn parent->
  "Receive a ByteBuf from parent

  411-435: try receiving messages: (DJB)

  It seems like this is probably inside-out now.

  The parent is going to call this. It should trigger
  the pieces that naturally fall downstream and lead
  to writing the bytes to the child.

  It's replacing one of the polling triggers that
  set off the main() event loop. Need to adjust for
  that fundamental strategic change
  "
  [{:keys [::specs/->child-buffer]
    :as state}
   ^ByteBuf buf]
;;;           From parent (over watch8)
;;;           417-433: for loop from 0-bytes read
;;;                    Copies bytes from incoming message buffer to message[][]
  (when (= 0 (.readableBytes buf))
    ;; Yes, this is supposed to kill the entire process
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
  ;; the first pass
  (if (< max-child-buffer-size (count ->child-buffer))
    ;; Q: Do I need anything else?
    (update state ::->child-buffer conj buf)
    (do
      (log/warn "Child buffer overflow")
      state)))
