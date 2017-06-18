(ns frereth-cp.message
  "Translation of curvecpmessage.c

This is really a generic buffer program

The \"parent\" child/server reads/writes to pipes that this provides,
in a specific (and apparently undocumented) communications protocol.

This, in turn, reads/writes data from/to a child that it spawns.

At least, that's the impression I'm getting based on my
preliminary first few pages of the file I'm getting ready to
translate.

And then immediately after that, I think I hit the Chicago
congestion control algorithm")

;;;; Q: what's in the reference implementation?
;;;; A:
;;;; 1-66 boilerplate
;;;; 67-137 global declarations
;;;; 138-154: earliestblocktime_compute
;;;           Looks like it's finding a min
;;;; 155-185: acknowledged(start, stop)
;;;           159-167: Flag these blocks as sent
;;;                    Marks blocks between start and stop as ACK'd
;;;                    Updates totalblocktransmissions and totalblocks
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
;;;      357-378:  ???
;;;    380 sendblock:
;;;        Resending old block will goto this
;;;        It's in the middle of a do {} while(0) loop
;;;      382-406:  ???
;;;      408: earliestblocktime_compute()
;;;  411-435: try receiving messages: (DJB)
;;;  436-614: try processing a message: (DJB)
;;;  615-632: try sending data to child: (DJB)
;;;  634-643: try closing pipe to child: (DJB)
