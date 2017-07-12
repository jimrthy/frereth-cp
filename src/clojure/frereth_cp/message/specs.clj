(ns frereth-cp.message.specs
  "Common specs that are shared among message namespaces"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.constants :as K]
            [frereth-cp.shared.constants :as K-shared]
            [frereth-cp.util :as util])
  (:import clojure.lang.BigInt
           io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def sec->n-sec
  "Starting point for several values"
  1000000000)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::big-int #(instance? BigInt %))
(s/def ::buf #(instance? ByteBuf %))

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
;; Q: If I try to convert this to a set, what happens
;; when ::buf changes?
(s/def ::blocks (s/and (s/coll-of ::block)
                       #(= (rem (count %) 2) 0)))
;; How to find the current ::block inside a ::state
(s/def ::current-block-cursor (s/coll-of (s/or :vec-index nat-int?
                                               :map-key keyword?)))

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
(s/def ::max-block-length nat-int?)

;; circular queue beyond receivewritten; size must be power of 2 --DJB
(s/def ::receive-buf ::buf)
;; number of initial bytes fully received --DJB
(s/def ::receive-bytes nat-int?)
;; total number of bytes in stream, if receiveeof --DJB
(s/def ::receive-total-bytes int?)
;; within receivebytes, number of bytes given to child -- DJB
(s/def ::receive-written nat-int?)

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

(s/def ::callback (s/fspec :args (s/cat :buf ::buf)
                           :ret boolean?))
(s/def ::->child ::callback)
(s/def ::child-> ::callback)
(s/def ::->parent ::callback)
(s/def ::parent-> ::callback)
(s/def ::callbacks (s/keys :req [::->child
                                 ::->parent]))

;; This is the last time we checked the clock, in nanoseconds
(s/def ::recent int?)
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

(s/def ::want-ping #{false ::immediate ::second-1})

;; Q: Does it make sense to split this up?
;; That seems to be begging for trouble, although
;; nothing but ::blocks should involve much memory usage.
;; Then again, remember the lesson about conj'ing
;; hundreds of seqs
;; TODO: These really need a better namespace
(s/def ::state (s/keys :req [::blocks
                             ::earliest-time
                             ::last-block-time
                             ::last-doubling
                             ::last-edge
                             ::last-panic
                             ::last-speed-adjustment
                             ::max-block-length
                             ::n-sec-per-block
                             ::next-message-id
                             ::->child-buffer
                             ::receive-bytes
                             ::receive-eof
                             ::receive-total-bytes
                             ::receive-written
                             ::recent
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
                             ::send-acked
                             ;; Q: Does this field make any sense at all?
                             ::send-buf-size
                             ::send-bytes
                             ::send-eof
                             ::send-eof-processed
                             ::send-eof-acked
                             ::send-processed
                             ::total-blocks
                             ::total-block-transmissions
                             ::want-ping]
                       :opt [::callbacks
                             ::current-block-cursor
                             ::packet
                             ;; Q: Do I want anything to do with this?
                             ::receive-buf
                             ::send-buf]))
