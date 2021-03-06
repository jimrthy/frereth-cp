(ns frereth.cp.message.specs
  "Common specs that are shared among message namespaces"
  (:require [clojure.spec.alpha :as s]
            [frereth.cp.message.constants :as K]
            [frereth.cp.shared
             [constants :as K-shared]
             [specs :as shared-specs]]
            [frereth.cp.shared.util :as util]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import [clojure.lang BigInt IDeref]
           io.netty.buffer.ByteBuf
           [java.io InputStream OutputStream]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::ackd? boolean?)

(s/def ::big-int (s/or :int int?
                       :big-int #(instance? BigInt %)))

;; This is really a ::shared.specs/byte-buf.
;; TODO: Eliminate the duplication.
;; Have anything/everything that references this switch
;; to that instead.

;; N.B. blocklen, in the reference, really corresponds
;; to the .readableBytes of a ByteBuf
;; Q: Does ByteBuf make sense?
;; A: Probably not. Look into switching to plain
;; byte arrays
;; FIXME: Make this go away
(s/def ::buf ::shared-specs/byte-buf)

;;; Just something human-readable to help me track which log
;;; messages go where during intertwined tests.
;;; Though it certainly isn't a bad idea in general
(s/def ::message-loop-name string?)
;; Used for building the message-loop-name when the
;; server is ready to spawn a new child
(s/def ::message-loop-name-base string?)

;;; Used for sending requests to the message-buffering
;;; Actor (Q: is that still a thing?)
(s/def ::stream strm/stream?)
;; TODO: Need better names
;; This is the pipe that the child writes to for sending data
(s/def ::from-child #(instance? OutputStream %))
;; This is the pipe that we read for buffering that data
(s/def ::child-out #(instance? InputStream %))
;; Q: What's this for?
(s/def ::to-child-done? #(instance? IDeref %))
(s/def ::from-parent-trigger #(strm/sink? %))
;; These are the equivalent of the OS pipes that
;; the reference implementation uses to pipe data in
;; and out of the child.
;; Note that they're totally distinct from the buffers
;; used internally.
(s/def ::pipe-from-child-size nat-int?)
(s/def ::pipe-to-child-size nat-int?)
;; Q: Do we have access to anything more specific/general/useful?
(s/def ::child-output-loop #(instance? java.util.concurrent.Future %))
(s/def ::child-input-loop #(instance? java.util.concurrent.Future %))

(s/def ::message-id int?)

;; This is defined as a long long in the reference
;; implementation.
;; Try to avoid expanding it to a BigInt.
;; This in the number
;; of nanoseconds to wait between each block that goes
;; out.
;; It's more nuanced than that, but that's the basic
;; point/idea
(s/def ::n-sec-per-block nat-int?)

;; This maps to a bitflag to send over the wire:
;; 2048 for normal EOF after sendbytes
;; 4096 for error after sendbytes
;; TODO: Refactor-rename these to ::eof-normal and ::eof-error
;; And possibly even ::eof-false.
;; This version is just confusing.
(s/def ::eof-flag #{::false ::normal ::error})
(s/def ::receive-eof ::eof-flag)
;; In the reference implementation, this gets changed from 0 (aka ::false) when
;; reading from the fromchild[0] pipe returns either 0 (normal EOF) or <0 (error).
;; A lot of logic depends on this flag, and its close relatives
;; <s>::send-eof-processed</s> to-parent/send-eof-buffered?
;; and ::send-eof-ackd
(s/def ::send-eof ::eof-flag)

(s/def ::bs-or-eof (s/or :bytes bytes?
                         :keyword ::eof-flag))

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

;;; Looks like a count:
;;; How many times has this block been sent?
;;; Corresponds to blocktransmissions[]
(s/def ::transmissions int?)

;; This is really block from the child
(s/def ::block (s/keys :req [::ackd?
                             ;; I have a problem here.
                             ;; On EOF, this gets set to nil.
                             ;; I *could* set the top-level spec
                             ;; to be nilable, but that violates the
                             ;; basic point.
                             ;; I could also add something like a
                             ;; ::maybe-buf spec right above this
                             ;; (that was my first inclination),
                             ;; but then I'd have to track it down
                             ;; and rename it everywhere.
                             ;; Best option that comes to mind immediately:
                             ;; track down where the EOF buffer is getting
                             ;; created and adjust it to add the empty buf.
                             ::buf
                             ;; It's pointless to include this in every message.
                             ;; We only need 1.
                             ;; TODO: Make this optional and eliminate it from all but the
                             ;; last
                             ::send-eof
                             ::start-pos
                             ::time
                             ::transmissions]
                       :opt [::message-id]))
(s/def ::blocks (s/and (s/coll-of ::block)))

;; Blocks from child that have been sent to parent, but not acknowledged
(s/def ::un-ackd-blocks ::blocks)
;; Blocks from child that we haven't forwarded along to parent
(s/def ::un-sent-blocks ::blocks)
;; Which queue contains the next block to send?
(s/def ::next-block-queue #{::un-ackd-blocks ::un-sent-blocks})

;; The ID of a message which was just ACK'd
;; TODO: For consistency, rename this to ackd-message
;; Or even ackd-msg-id
(s/def ::acked-message ::message-id)
;; This is really an 8-byte unsigned int
;; So this spec might be completely broken
;; (due to "negative" numbers wrapping out to a bigint)
(s/def ::unsigned-long (s/and nat-int?
                              #(<= % K-shared/max-64-uint)))
(s/def ::ack-length-1 ::unsigned-long)
(s/def ::ack-gap-1->2 (s/and nat-int?
                             #(<= % K-shared/max-32-uint)))
(s/def ::unsigned-short (s/and nat-int?
                               #(<= % K-shared/max-16-uint)))
(s/def ::ack-length-2 ::unsigned-short)
(s/def ::ack-gap-2->3 ::unsigned-short)
(s/def ::ack-length-3 ::unsigned-short)
(s/def ::ack-gap-3->4 ::unsigned-short)
(s/def ::ack-length-4 ::unsigned-short)
(s/def ::ack-gap-4->5 ::unsigned-short)
(s/def ::ack-length-5 ::unsigned-short)
(s/def ::ack-gap-5->6 ::unsigned-short)
(s/def ::ack-length-6 ::unsigned-short)
(s/def ::size-and-flags ::unsigned-short)
(s/def ::start-byte ::unsigned-long)
;; This represents an actual deserialized message
;; from the parent.
;; Using ::packet as the key for this spec was
;; an unfortunate choice.
;; Since the distinction between packets and
;; messages (especially considering message
;; packets) is already confusing.
;; FIXME: Switch to a better choice.
(s/def ::packet (s/keys :req [::message-id
                              ::acked-message
                              ::ack-length-1
                              ::ack-gap-1->2
                              ::ack-length-2
                              ::ack-gap-2->3
                              ::ack-length-3
                              ::ack-gap-3->4
                              ::ack-length-4
                              ::ack-gap-4->5
                              ::ack-length-5
                              ::ack-gap-5->6
                              ::ack-length-6
                              ::size-and-flags
                              ::start-byte
                              ::buf]))
;; A byte-array that we're going to send as an ACK
;; Q: Is this worth spec'ing more thoroughly?
(s/def ::ack-body bytes?)

;; If nonzero: minimum of active ::time values
;; Corresponds to earliestblocktime in original
;; This had 2 purposes there
;; 1) signal that there are blocks to resend to parent
;; 2) baseline for poll timeout. Just do that resend
;;    because input hasn't arrived quickly enough to
;;    trigger it.
;; Q: Does this serve any useful purpose any longer?
(s/def ::earliest-time nat-int?)
;; Corresponds to lastblocktime in original
;; Undocumented, but it looks like the value of recent
;; at the end of the previous send to parent
(s/def ::last-block-time int?)

;; Undocumented in reference implementation.
;; Starts out at 512, then switches to 1024 as soon as
;; we can start processing a message that goes to the
;; child.
;; This really needs to be a state flag:
;; While a client is sending Initiate packets, waiting
;; for an initial message back from the server, it has fewer
;; bytes available for the payload portion of each
;; packet.
;; TODO: Convert this to a promise that we can use
;; to just control that directly without the obscurity
;; that this creates.
(s/def ::max-block-length nat-int?)
;; This is really a promise that is fulfilled when the
;; server sends a response packet back.
;; As implemented, an ACK works fine.
;; Until that point, the client is limited to sending Initiate
;; packets, which means the child is limited to 640-byte
;; message blocks.
(s/def ::client-waiting-on-response #(instance? IDeref %))

;; circular queue beyond receivewritten; size must be power of 2 --DJB
;; This doesn't really make sense in a clojure/netty world --JRG
;; Q: Can I just make it go away?
(s/def ::receive-buf ::buf)
;; Seq of byte arrays that are ready to write to the child.
(s/def ::->child-buffer (s/coll-of bytes?))
;; Raw byte array that just arrived from the parent.
;; Needs to be parsed into a ::packet so the bytes in
;; the message stream can be moved to ::->child-buffer
;; This arrived over the wire. So should be
;; ByteBuf instances.
;; But we've had to decrypt them, which meant converting to
;; byte arrays.
;; So it's wasteful to temporarily convert them back, since
;; they really need to proceed to the child as either byte
;; arrays or possibly clojure vectors of bytes.
;; (I'm still torn about that detail)
(s/def ::parent->buffer bytes?)

;; total number of bytes in stream, if receiveeof --DJB
(s/def ::receive-total-bytes int?)
;; within receivebytes, number of bytes given to child -- DJB
(s/def ::receive-written nat-int?)

;; Highest stream address
;; When you add a byte to the stream, it starts here.
;; Note that this is dual-purpose:

;; For outgoing:
;; In the reference implementation, this is
;; sendacked + sendbytes

;; For incoming:
;; number of initial bytes fully received --DJB
;; i.e. the address in the stream that has been
;; buffered up to send to the child
(s/def ::strm-hwm int?)
;; The number of bytes that have been received
;; without gaps.
;; Actually, this is probably the real point
;; behind receivebytes in the original.
;; Note that there *is* an important, albeit
;; subtle, distinction, between this and
;; ::receive-written.
;; This gets updated when the gap-buffer
;; that's ready to write to the child has its
;; holes filled.
;; That gets updated when the bytes are written
;; to the pipe that connects to the child's callback.
;; Q: Is this distinction worth the confusion?
;; At the very least, it seems like it would reduce
;; that to shove this, ::receive-written, and
;; ::strm-hwm into another nested map.
(s/def ::contiguous-stream-count nat-int?)

;; For a gap-buffer entry, what is the starting address?
(s/def ::strm-strt-addr nat-int?)
;; For a gap-buffer entry, what is the stop address?
(s/def ::strm-stop-addr nat-int?)
(s/def ::gap-buffer-key (s/tuple ::strm-strt-addr ::strm-stop-addr))
;; Note that this is really a sorted-map
(s/def ::gap-buffer (s/map-of ::gap-buffer-key ::buf))

(s/def ::monitor-id (s/or :uuid uuid?
                          :keyword keyword?
                          :string string?))
;;; These next 5 really swirld around the sendbuf array/circular queue
;; Need something to act as the array that backs the circular buffer.
;; This seems dubious, but I have to start somewhere
(s/def ::send-buf bytes?)
;; This is really the maximum length that we're willing to allocate
;; to this buffer
(s/def ::send-buf-size nat-int?)
;; Number of bytes sent and fully acknowledged
;; Corresponds to sendacked in reference
;; This name just makes more sense to me.
(s/def ::ackd-addr int?)

;; Once ::send-eof is set (which means that the stream from the
;; child is closed), we keep things running until the server
;; ACKs that it has received the EOF message.
;; It does this with an ACK that encompasses the entire stream,
;; from 0 past the end of stream (represented by sendacked+sendbytes,
;; on line 177).
;; Once we've received that signal, we can set this.
(s/def ::send-eof-acked boolean?)

;; How many blocks has the client ACK'd?
(s/def ::total-blocks nat-int?)
;; How many times have we transmitted blocks to the client?
;; (Gets updated in a lump when a block gets ACK'd)
(s/def ::total-block-transmissions nat-int?)

;; The return value is actually a vital piece of the puzzle.
;; Need an indicator about what happened to the bytes we
;; just tried to send.
;; I *could* throw exceptions to achieve similar effects
;; for cases where (for example) buffers are full,
;; and it seems like it would probably make sense, since
;; these calls really *are* all about crossing system
;; boundaries and side-effects.
;; But that approach still feels very dubious.
;; And making those return values completely unconstrained
;; seems like a terrible idea.
;; TODO: Decide how I want to handle this (a set of
;; keywords seems most likely)
(s/def ::callback (s/fspec :args (s/cat :buf bytes?)
                           :ret any?))
(s/def ::->child ::callback)
(s/def ::->parent ::callback)

(s/def ::executor #(instance? java.util.concurrent.ExecutorService %))

;; This is the last time we checked the clock, in nanoseconds
(s/def ::recent nat-int?)
;; deferred for next event-loop trigger
(s/def ::next-action dfrd/deferred?)
;; These feed off recent, but are basically undocumented
(s/def ::last-doubling int?)
(s/def ::last-edge int?)
(s/def ::last-panic int?)

;;; Bits that are (somehow) vital to the flow-control algorithm
(s/def ::rtt ::big-int)
(s/def ::rtt-average ::big-int)
(s/def ::rtt-deviation ::big-int)
(s/def ::rtt-highwater ::big-int)
(s/def ::rtt-lowwater ::big-int)
;; These next 5 are defined as long long in the reference,
;; but they seem to be used as bool
(s/def ::rtt-phase boolean?)
(s/def ::rtt-seen-older-high boolean?)
(s/def ::rtt-seen-older-low boolean?)
(s/def ::rtt-seen-recent-high boolean?)
(s/def ::rtt-seen-recent-low boolean?)
(s/def ::rtt-timeout ::big-int)
(s/def ::last-speed-adjustment ::big-int)

;; These correspond with wantping values
;; 0, 2, and 1, respectively.
;; i.e. -s, -c, and -C parameters
;; to the message program.
;; -s : part of a server (0)
;; -c : client that starts after the server (2)
;; -C : client that starts before the server (1)
(s/def ::want-ping #{::false ::immediate ::second-1})

;; Q: Does it make sense to split this up?
;; That seems to be begging for trouble, although
;; nothing but ::blocks should involve much memory usage.
;; Then again, remember the lesson about conj'ing
;; hundreds of seqs.

;; Note that there are at least 3 completely different
;; pieces of state here:
;; 1. Traffic shaping
(s/def ::flow-control (s/keys :req [::client-waiting-on-response
                                    ::last-doubling
                                    ::last-edge
                                    ::last-speed-adjustment
                                    ::n-sec-per-block
                                    ::rtt
                                    ::rtt-average
                                    ;; Q: Does rtt-delta belong in here?
                                    ::rtt-deviation
                                    ::rtt-highwater
                                    ::rtt-lowwater
                                    ::rtt-phase
                                    ::rtt-seen-older-high
                                    ::rtt-seen-older-low
                                    ::rtt-seen-recent-high
                                    ::rtt-seen-recent-low
                                    ::rtt-timeout]
                              :opt [::next-action]))

;; 2. Buffers of bytes from the parent that we have not
;;    yet managed to write to the child
(s/def ::incoming (s/keys :req [::->child-buffer
                                ::contiguous-stream-count
                                ::gap-buffer
                                ::pipe-to-child-size
                                ::receive-eof
                                ::receive-total-bytes
                                ::receive-written
                                ::strm-hwm]
                          :opt [::packet
                                ::parent->buffer]))

;; 3. Buffers of bytes that we received from the child
;;    but the parent has not yet ACK'd
(s/def ::outgoing (s/keys :req [::ackd-addr
                                ::earliest-time  ; Q: Any point to this?
                                ::last-block-time
                                ;; FIXME: Move this to flow-control
                                ::last-panic
                                ::max-block-length
                                ::next-message-id
                                ::pipe-from-child-size
                                ;; Q: Does this field make any sense at all?
                                ;; (It's a hard-coded constant that doesn't
                                ;; seem likely to ever change)
                                ::send-buf-size
                                ::send-eof
                                ::send-eof-acked
                                ::strm-hwm
                                ::total-blocks
                                ::total-block-transmissions
                                ;; These next 2 are the core of this piece.
                                ;; Everything else is really to support them
                                ::un-ackd-blocks
                                ::un-sent-blocks
                                ::want-ping]
                          :opt [::next-block-queue
                                ::monitor-id
                                ::send-buf]))

(s/def ::state (s/keys :req [::flow-control
                             ::incoming
                             ::outgoing

                             ::weald/state
                             ::message-loop-name

                             ;; Q: Does this make more sense anywhere else?
                             ;; Nested under ::flow-control seems like a better
                             ;; choice.
                             ::recent]))

;;; Black box that holds the pieces I need for doing I/O.
;;; If this were an OOP environment, I'd stick these parts
;;; into private members.
;;; The main restriction around these is that they're all
;;; about side-effects. So you probably don't want to try
;;; to validate this.
(s/def ::io-handle (s/keys :req [::->child  ;; callbacks here
                                 ::->parent
                                 ;; PipedIn/OutputStream pairs
                                 ;; TODO: Need better names
                                 ::from-child
                                 ::child-out

                                 ::to-child-done?
                                 ::from-parent-trigger

                                 ::executor
                                 ::weald/logger
                                 ;; This really doesn't belong in here,
                                 ;; but there are at least a couple of places
                                 ;; where I don't have a choice: I need to
                                 ;; log things in places where I do not have
                                 ;; access to ::state (c.f. comments re:
                                 ;; state-wrapper directly above).
                                 ;; This is really only useful for the outer
                                 ;; fringe portions that are interacting
                                 ;; with the outside world.
                                 ;; Which actually fits perfectly, since
                                 ;; that's exactly what the io-handle is
                                 ;; supposed to be for.
                                 ;; Just use with extreme caution.
                                 ::weald/state-atom

                                 ;; This seems redundant.
                                 ;; Q: How often will I have an io-handle
                                 ;; without state?
                                 ;; A: The state's actually quite mutable
                                 ;; and gets updated pretty much every
                                 ;; time the message loop gets triggered.
                                 ;; So anything I stored in here would be
                                 ;; obsolete almost immediately.
                                 ;; So it's good to have this sort of
                                 ;; explicit corollary between the two.
                                 ::message-loop-name]
                           :opt [::child-input-loop
                                 ::child-output-loop
                                 ::pipe-from-child-size]))

;; This is a function, called for side effects, that really starts
;; the "bottom-level" child which is the part that clients using
;; this library actually care about.
;; It would make the API nicer if this could return the
;; ->child callback.
;; But that presents a chicken/egg problem.
;; We can't build an ::io-handle without the ::->child.
;; Well, we *could*. But it would mean additional state
;; and an extra deref for every arriving message.
;; Maybe avoiding the deref is premature optimization,
;; but avoiding the extra state seems like an excellent idea.
;; Then again, this may just push the state management problem
;; out to the child.
;; So the jury's still out.
;; That actually seems to have worked out fairly well, so
;; this particular debate seems to be settled.

;; It would be nice for this to return a ::weald/state.
;; The down-side to that idea is that this is a callback
;; supplied by the client, and that should be totally
;; independent of our logging.
(s/def ::child-spawner! (s/fspec :args (s/cat :io-handle ::io-handle)
                                 :ret any?))
