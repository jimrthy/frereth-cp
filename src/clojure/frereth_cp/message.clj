(ns frereth-cp.message
  "Translation of curvecpmessage.c

This is really a generic buffer program

The \"parent\" child/server reads/writes to pipes that this provides,
in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns."
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.specs :as specs]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal


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

(defn initial-state
  ;; TODO: This should probably just be public
  []
  {::specs/blocks []
   ::specs/earliest-time 0
   ::specs/send-eof false
   ::specs/send-eof-processed false
   ::specs/send-eof-acked false
   ::specs/total-blocks 0
   ::specs/total-block-transmissions 0})
