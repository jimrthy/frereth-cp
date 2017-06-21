(ns frereth-cp.message
  "Translation of curvecpmessage.c

This is really a generic buffer program

The \"parent\" child/server reads/writes to pipes that this provides,
in a specific (and apparently undocumented) communications protocol.

  This, in turn, reads/writes data from/to a child that it spawns."
  (:require [clojure.spec.alpha :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;; number of bytes in each block
;;; Corresponds to blocklen
(s/def ::length int?)

;;; Position of a block's first byte within the stream
;;; Corresponds to blockpos
(s/def ::start-pos int?)

;;; Looks like a count:
;;; How many times has this block been sent?
;;; Corresponds to blocktransmissions[]
(s/def ::transmissions int?)

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
                             ::time
                             ::transmissions]))
(s/def ::blocks (s/and (s/coll-of ::block)
                       ;; Actually, the length must be a power of 2
                       ;; TODO: Improve this spec!
                       ;; (Reference implementation uses 128)
                       #(= (rem (count %) 2) 0)))

;; If nonzero: minimum of active ::time values
(s/def ::earliest-time int?)

;; Number of initial bytes sent and fully acknowledged
(s/def ::send-acked int?)
;; Number of additional bytes to send (i.e. haven't been sent yet)
(s/def ::send-bytes int?)
;; within sendbytes, number of bytes absorbed into blocks
(s/def ::send-processed int?)
;; Those 3 really swirld around the sendbuf array/circular queue
;; For this pass, at least, I'm trying to avoid anything along those lines

;; 2048 for normal EOF after sendbytes
;; 4096 for error after sendbytes
;; Dual-purposing a magic constant bit for both the
;; over-wire communications flag and the
;; internal behavioral flow-controller
;; chafes.
;; TODO: Don't.
(s/def ::send-eof #{false ::normal ::error})
(s/def ::send-eof-processed boolean?)
(s/def ::send-eof-acked boolean?)

;; Totally undocumented (so far)
(s/def ::total-blocks int?)
(s/def ::total-block-transmissions int?)

(s/def ::state (s/keys ::req [::blocks
                              ::earliest-time
                              ::send-eof
                              ::send-eof-processed
                              ::send-eof-acked
                              ::total-blocks
                              ::total-block-transmissions]))

(defn initial-state
  ;; TODO: This should probably just be public
  []
  {::blocks []
   ::earliest-time 0
   ::send-eof false
   ::send-eof-processed false
   ::send-eof-acked false
   ::total-blocks 0
   ::total-block-transmissions 0})

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
  [{:keys [::blocks
           ::send-acked
           ::send-bytes
           ::send-processed
           ::send-eof
           ::send-eof-acked
           ::total-block-transmissions
           ::total-blocks]
    :as state}
   start
   stop]
  (if (not= start stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
    (let [acked (reduce (fn [{:keys [::n]
                              :as acc}
                             block]
                          (let [start-pos (::start-pos block)]
                            (if (<= start
                                    start-pos
                                    (+ start-pos (::length block))
                                    stop)
                              (-> acc
                                  (assoc-in [::blocks n ::time] 0)
                                  (update ::total-blocks inc)
                                  (update ::total-block-transmissions + (::transmissions block)))
                              (update acc ::n inc))))
                        (assoc state ::n 0)
                        blocks)]
      ;; To match the next block, the main point is to discard
      ;; the first sequence of blocks that have been ACK'd
      ;; drop-while seems obvious
      ;; However, we also need to update send-acked, send-bytes, and send-processed
;;;           168-176: Updates globals for adjacent blocks that
;;;                    have been ACK'd
;;;                    This includes some counters that seem important:
;;;                        blocknum
;;;                        sendacked
;;;                        sendbytes
;;;                        sendprocessed
;;;                        blockfirst
      (let [[to-drop to-keep] (split-with #(= 0 (::time %)) acked)
            dropped-block-lengths (apply + (map ::length to-drop))
            state (update state ::send-acked + dropped-block-lengths)
            state (update state ::send-bytes - dropped-block-lengths)
            state (update state ::send-processed - dropped-block-lengths)
;;;           177-182: Possibly set sendeofacked flag
            state (or (when (and send-eof
                                 (= start 0)
                                 (> stop (+ (::send-acked state)
                                            (::send-bytes state)))
                                 (not send-eof-acked))
                        (update state ::send-eof-acked true))
                      state)]
;;;           183: earliestblocktime_compute()
        (assoc state ::earliest-time (earliest-block-time blocks))))
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
