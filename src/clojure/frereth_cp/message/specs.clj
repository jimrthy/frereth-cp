(ns frereth-cp.message.specs
  "Common specs that are shared among message namespaces"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.constants :as K]
            [frereth-cp.shared.constants :as K-shared]
            [frereth-cp.util :as util]
            [manifold.deferred :as dfrd])
  (:import clojure.lang.BigInt
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::big-int #(instance? BigInt %))
(s/def ::buf #(instance? ByteBuf %))

;;; Just something human-readable to help me track which log
;;; messages go where during intertwined tests.
;;; Though it certainly isn't a bad idea in general
(s/def ::message-loop-name string?)

;;; number of bytes in each block
;;; Corresponds to blocklen
(s/def ::length int?)

(s/def ::message-id int?)

;; This is defined as a long long in the reference
;; implementation.
;; Try to avoid expanding it to a BigInt.
(s/def ::n-sec-per-block int?)

;; This maps to a bitflag to send over the wire:
;; 2048 for normal EOF after sendbytes
;; 4096 for error after sendbytes
(s/def ::eof-flag #{false ::normal ::error})
(s/def ::receive-eof ::eof-flag)
(s/def ::send-eof ::eof-flag)

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
(s/def ::block (s/keys :req [::buf
                             ;; We already have length in ::buf, under .getReadableBytes.
                             ;; It would save space and be less error prone to just use
                             ;; that.
                             ;; By the same token, it would almost definitely be more efficient
                             ;; to swittch ::buf to a ByteArray.
                             ;; So keeping this here helps loosen the coupling and makes
                             ;; things more flexible if/when someone does decide to make that
                             ;; switch.
                             ::length
                             ::message-id
                             ::send-eof
                             ::start-pos
                             ::time
                             ::transmissions]))
;; I'd prefer to implement this as a set instead of a vector.
;; Q: what then happens when ::buf changes?
;; Honestly, it should probably be a priority queue that's
;; sorted by ::time.
(s/def ::blocks (s/and (s/coll-of ::block)
                       #(= (rem (count %) 2) 0)))

;; Blocks from child that have been sent to parent, but not acknowledged
(s/def ::un-ackd-blocks ::blocks)
;; Blocks from child that we haven't forwarded along to parent
(s/def ::un-sent-blocks ::blocks)
;; Which queue contains the next block to send?
(s/def ::next-block-queue #{::un-ackd-blocks ::un-sent-blocks})

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
;; This represents an actual message from the parent
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

;; If nonzero: minimum of active ::time values
;; Corresponds to earliestblocktime in original
(s/def ::earliest-time int?)
;; Corresponds to lastblocktime in original
;; Undocumented, but it looks like the value of recent
;; at the end of the previous send to parent
(s/def ::last-block-time int?)

;; Undocumented.
;; Starts out at 512, then switches to 1024 as soon as
;; we can start processing a message that goes to the
;; child.
;; I think I got this tangled up and am actually doing
;; that little dance with some other field.
(s/def ::max-block-length nat-int?)

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
;; number of initial bytes fully received --DJB
;; This is actually the number of bytes that have been
;; buffered up to forward along to the child.
;; Which means that (after we've buffered the initial
;; message) it's 1 greater than the stream address (which
;; is 0-based)
;; TODO: Rename this to high-water-mark
(s/def ::receive-bytes nat-int?)
;; total number of bytes in stream, if receiveeof --DJB
(s/def ::receive-total-bytes int?)
;; within receivebytes, number of bytes given to child -- DJB
(s/def ::receive-written nat-int?)

(s/def ::strm-strt-addr nat-int?)
(s/def ::strm-stop-addr nat-int?)
(s/def ::gap-buffer-key (s/tuple ::strm-strt-addr ::strm-stop-addr))
(s/def ::gap-buffer (s/map-of ::gap-buffer-key ::buf))

;;; These next 5 really swirld around the sendbuf array/circular queue
;; Need something to act as the array that backs the circular buffer.
;; This seems dubious, but I have to start somewhere
(s/def ::send-buf ::buf)
;; This is really the maximum length that we're willing to allocate
;; to this buffer
(s/def ::send-buf-size nat-int?)
;; Number of initial bytes sent and fully acknowledged
(s/def ::send-acked int?)
;; Number of additional bytes to send (i.e. haven't been sent yet)
(s/def ::send-bytes int?)
;; within sendbytes, number of bytes absorbed into blocks
(s/def ::send-processed int?)

(s/def ::send-eof-acked boolean?)
(s/def ::send-eof-processed boolean?)

;; Totally undocumented (so far)
(s/def ::total-blocks int?)
(s/def ::total-block-transmissions int?)

(s/def ::callback (s/fspec :args (s/cat :buf bytes?)
                           :ret boolean?))
(s/def ::->child ::callback)
(s/def ::child-> ::callback)
(s/def ::->parent ::callback)
(s/def ::parent-> ::callback)

;; This is the last time we checked the clock, in nanoseconds
(s/def ::recent int?)
;; deferred for triggering I/O on a timer
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
(s/def ::schedule-pool (s/nilable #(instance? overtone.at_at.MutablePool %)))

;; These correspond with values
;; 0, 2, and 1, respectively.
;; i.e. -s, -c, and -C parameters
;; to the message program.
;; -s : part of a server
;; -c : client that starts after the server
;; -C : client that starts before the server
(s/def ::want-ping #{false ::immediate ::second-1})

;; Q: Does it make sense to split this up?
;; That seems to be begging for trouble, although
;; nothing but ::blocks should involve much memory usage.
;; Then again, remember the lesson about conj'ing
;; hundreds of seqs.

;; Note that there are at least 3 completely different
;; pieces of state here:
;; 1. Traffic shaping
(s/def ::flow-control (s/keys :req [::last-doubling
                                    ::last-edge
                                    ::last-speed-adjustment
                                    ::n-sec-per-block
                                    ::next-action
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
                                    ::rtt-timeout
                                    ::schedule-pool]))

;; 2. Buffers of bytes from the parent that we have not
;;    yet managed to write to the child
(s/def ::incoming (s/keys :req [::->child  ; callback
                                ::->child-buffer
                                ::gap-buffer
                                ::receive-bytes
                                ::receive-eof
                                ::receive-total-bytes
                                ::receive-written]
                          :opt [::packet
                                ::parent->buffer]))

;; 3. Buffers of bytes that we received from the child
;;    but the parent has not yet ACK'd
(s/def ::outgoing (s/keys :req [::earliest-time  ; Q: Any point to this?
                                ::last-block-time
                                ::last-panic
                                ::max-block-length
                                ::next-message-id
                                ::->parent
                                ::send-acked
                                ;; Q: Does this field make any sense at all?
                                ;; (It's a hard-coded constant that doesn't
                                ;; seem likely to ever change)
                                ::send-buf-size
                                ::send-bytes
                                ::send-eof
                                ::send-eof-acked
                                ::send-eof-processed
                                ::send-processed
                                ::total-blocks
                                ::total-block-transmissions
                                ;; These next 2 are the core of this piece.
                                ;; Everything else is really to support them
                                ::un-ackd-blocks
                                ::un-sent-blocks
                                ::want-ping]
                          :opt [::next-block-queue
                                ::send-buf]))

;; TODO: These really need a better namespace
(s/def ::state (s/keys :req [::flow-control
                             ::incoming
                             ::outgoing

                             ::message-loop-name

                             ;; Q: Does this make more sense anywhere else?
                             ::recent]))

(s/def ::state-agent (s/and #(instance? clojure.lang.Agent %)
                            #(s/valid? ::state (deref %))))
