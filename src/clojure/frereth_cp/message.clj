(ns frereth-cp.message
  "Translation of curvecpmessage.c

This is really a generic buffer program

The \"parent\" child/server reads/writes to pipes that this provides,
in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns."
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.specs :as specs]
            [manifold.stream :as strm]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

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
  131072)

(def stream-length-limit
  "How many bytes can the stream send before we've exhausted the address space?

(dec (pow 2 60)): this allows > 200 GB/second continuously for a year"
  1152921504606846976)

(def k-4
  "a.k.a. 4k

For whatever reason, DJB picked this as the end-point to refuse to read
more child data before we hit send-byte-buf-size.

Presumably that reason was good"
  4096)

(def n-sec-per-block
  "This *is* mutable

Seems vital, but undocumented"
  specs/sec->n-sec)

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
  [{:keys [::specs/event-streams]
    :as state}]
  (let [{:keys [::specs/child ::specs/parent]} event-streams]
    ;; I think the main idea is that I should set up transducing
    ;; pipelines between child and parent
    ;; That isn't right, though.
    ;; The entire point,really, is to maintain a buffer between the
    ;; two until the blocks in that buffer have been ACK'd
    ;; Although managing the congestion control aspects of that
    ;; buffer definitely play a part
    (throw (RuntimeException. "What should this look like?"))
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
  "Pulls blocks of bytes from the child.

The obvious approach is just to feed ByteBuffers
from the child stream to the parent stream.

The obvious approach completely misses the point that
this is a buffer. We need to hang onto those buffers
here until they've been ACK'd.
"
  [{:keys [::specs/event-streams]
    :as state}
   buf]
  ;; Q: Need to apply back-pressure if we
  ;; already have ~124K pending?
  ;; (It doesn't seem like it should matter, except
  ;; as an upstream signal that there's a network
  ;; issue)
  (let [block {::buf buf
               ::transmissions 0}
        send-bytes (+ (::send-bytes state) (.getReadableBytes buf))]
    (when (>= send-bytes stream-length-limit)
      ;; Want to be sure standard error handlers don't catch
      ;; this...it needs to force a fresh handshake.
      (throw (AssertionError. "End of stream")))
    (-> state
        (update ::blocks conj block)
        (assoc ::send-bytes send-bytes)
;;;  337: update recent
        (assoc  ::recent (System/nanoTime)))))

(s/fdef possibly-add-child-bytes
        :args (s/cat :state ::specs/state
                     :buf ::specs/buf))
(defn possibly-add-child-bytes
  "Read bytes from a child buffer...if we have room

;;;  319-336: Maybe read bytes from child
"
  [state
   buf]
  (let [send-bytes (::send-bytes state)]
    ;; Line 322: This also needs to account for send-acked
    ;; Q: Is that an important part of the algorithm, or is
    ;; it "just" dealing with the fact that we have a circular
    ;; buffer with parts that have not yet been GC'd?
    ;; And is it possible to tease apart that distinction?
    (when (< (+ send-bytes k-4) send-byte-buf-size)
      (let [available-buffer-space (- send-byte-buf-size)
            buffer (.readBytes buf available-buffer-space)]
        (child-consumer state buffer)))))

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
  [{:keys [::specs/recent
           ::specs/earliest-time
           ::specs/last-block-time
           ::specs/rtt-timeout]
    :as state}]
  (when (and (< recent (+ last-block-time n-sec-per-block))
             (not= earliest-time)
             (>= recent (+ earliest-time rtt-timeout)))
    ;; This gets us to line 344
    ;; It finds the first block that matches earliest-time
    ;; It's going to re-send that block
    ;; But first, it might adjust some of the globals.
    (throw (RuntimeException. "There are some interesting details here"))))

;;;  357-410: Try sending a new block: (DJB)
;;;      357-378:  Sets up a new block to send
;;;                Along w/ related data flags in parallel arrays
;;;    380 sendblock:
;;;        Resending old block will goto this
;;;        It's in the middle of a do {} while(0) loop
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

(defn pick-next-block-to-send
  [state]
  (let [state' (check-for-previous-block-to-resend state)]
    (throw (RuntimeException. "keep going"))))

;;;      408: earliestblocktime_compute()

;;;  411-435: try receiving messages: (DJB)
;;;           From parent (over watch8)
;;;           417-433: for loop from 0-bytes read
;;;                    Copies bytes from incoming message buffer to message[][]

;;;  436-614: try processing a message: (DJB)
;;;           Lots of code in here.
;;;           This seems like the interesting part
;;;           440: sets maxblocklen=1024
;;;                Q: Why was it ever 512?
;;;                Guess: for initial Message part of Initiate packet
;;;          444-609: handle this message if it's comprehensible: (DJB)
;;;          610-614: counters/looping

;;;  615-632: try sending data to child: (DJB)
;;;           Big picture: copy data from receivebuf to the child[1] pipe
;;;           Then zero the receivevalid flags
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
;;;        562-574: calculate start/stop bytes
;;;        576-579: SF (StopFlag? deals w/ EOF)
;;;        581-588: copy incoming into receivebuf
;;;                 set the receivevalid flag
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

(s/fdef initial-state
        :args (s/cat :parent ::specs/parent
                     :child ::specs/child)
        :ret ::specs/state)
(defn initial-state
  [parent-stream
   child-stream]
  {::specs/blocks []
   ::specs/earliest-time 0
   ;; In the original, this is a local in main rather than a global
   ;; Q: Is there any difference that might matter to me, other
   ;; than being allocated on the stack instead of the heap?
   ;; (Assuming globals go on the heap. TODO: Look that up)
   ::specs/recent 0
   ::specs/rtt-timeout specs/sec->n-sec
   ::specs/send-eof false
   ::specs/send-eof-processed false
   ::specs/send-eof-acked false
   ::specs/total-blocks 0
   ::specs/total-block-transmissions 0
   ::specs/event-streams {::specs/child child-stream
                          ::specs/parent parent-stream}})
