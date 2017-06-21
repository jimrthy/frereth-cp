(ns frereth-cp.message
  "Translation of curvecpmessage.c

This is really a generic buffer program

The \"parent\" child/server reads/writes to pipes that this provides,
in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns."
  (:require [clojure.spec.alpha :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def incoming
  "Number of blocks in inbound queue

  Must be a power of 2"
  64)

(def outgoing
  "Number of blocks in outbound queue

Must be a power of 2"
  128)

(def outgoing-1
  "Decremented size of outbound queue

Used w/ bitwise-and to calculate modulo and wrap circular index

Because this is used more often than outgoing"
  (dec outgoing))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;; number of bytes in each block
;;; Corresponds to blocklen
(s/def ::length int?)

;;; Position of a block's first byte within the stream
;;; Corresponds to blockpos
(s/def ::start-pos int?)

;;; Time of last message sending this block
;;; 0 means ACK'd
;;; It seems like this would make more sense
;;; as an unsigned.
;;; But the reference specifically defines it as
;;; a long long.
;;; (Corresponds to the blocktime array)
(s/def ::time int?)

(s/def ::block (s/keys :req [::length
                             ::start-pos
                             ::time]))
(s/def ::blocks (s/and (s/coll-of ::block)
                       ;; Actually, the length must be a power of 2
                       ;; TODO: Improve this spec!
                       ;; (Reference implementation uses 128)
                       #(= (rem (count %) 2) 0)))

;;; Index into the start of a circular queue
;;; Q: Is this a good idea?
(s/def ::block-first int?)

;; Number of outgoing blocks being tracked
(s/def ::block-num integer?)

;; If nonzero: minimum of active ::time values
(s/def ::earliest-time integer?)

(s/def ::state (s/keys ::req [::block-first
                              ::block-num
                              ::blocks
                              ::earliest-time]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef earliest-block-time
        :args (s/coll-of ::block)
        :ret nat-int?)
(defn earliest-block-time
  "Calculate the earliest time

Based on earliestblocktime_compute, in lines 138-154
"
  [blocks]
  ;;; Comment from DJB:
  ;;; XXX: use priority queue
  (min (map ::time blocks)))

;;;; 155-185: acknowledged(start, stop)
(s/fdef acknowledged
        :args (s/cat :state ::state
                     :start int?
                     :stop int?)
        :ret ::state)
(defn mark-acknowledged
  "Mark blocks between positions start and stop as ACK'd

Based [cleverly] on acknowledged, running from lines 155-185"
  [{:keys [::block-first
           ::block-num
           ::blocks]
    :as state}
   start
   stop]
  (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
    (let [pre-acked (map (fn [n]
                           (let [pos (bit-and (+ block-first n) outgoing-1)]
                             ;; This raises the spectacle of a huge open question:
                             ;; do I want to bother with the trappings of a circular
                             ;; buffer?
                             ;; It seems likely to reduce GC somewhat, but nowhere
                             ;; near what I could achieve even just building everything
                             ;; on byte-arrays.
                             ;; Which simply is not going to happen until there's
                             ;; convincing evidence that it's worthwhile.
                             ;; (It probably is, but not for a first pass, even though
                             ;; that's a more accurate translation).
                             ))
                     (range block-num))]
      (throw (RuntimeException. "Translate the rest"))
;;;           168-176: Updates globals for adjacent blocks that
;;;                    have been ACK'd
;;;                    This includes some counters that seem important:
;;;                        blocknum
;;;                        sendacked
;;;                        sendbytes
;;;                        sendprocessed
;;;                        blockfirst
;;;           177-182: Possibly set sendeofacked flag
;;;           183: earliestblocktime_compute()
      )
    ;;; No change
    state))

;;;; Q: what else is in the reference implementation?
;;;; A:

;;;; 186-654 main
;;;          186-204 boilerplate
;;;          205-259 fork child
;;;          260-263 set up some globals
;;;          264-645 main event loop
;;;          645-651 wait on children to exit
;;;          652-653 exit codes

;;;; 264-645 main event loop
;;;  263-269: exit if done
;;;  271-306: Decide what and when to poll, based on global state
;;;  307-318: Poll for incoming data
;;;  319-336: Maybe read bytes from child
;;;  337: update recent
;;;  339-356: Try re-sending an old block: (DJB)
;;;           Picks out the oldest block that's waiting for an ACK
;;;           If it's older than (+ lastpanic (* 4 rtt_timeout))
;;;              Double nsecperblock
;;;              Update trigger times
;;;           goto sendblock

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
