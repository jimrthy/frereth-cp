(ns frereth-cp.message.specs
  "Common specs that are shared among message namespaces"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.util :as util])
  (:import io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def sec->n-sec
  "Starting point for several values"
  1000000000)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::buf #(instance? ByteBuf %))

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

;;; Looks like a count:
;;; How many times has this block been sent?
;;; Corresponds to blocktransmissions[]
(s/def ::transmissions int?)

(s/def ::block (s/keys :req [::buf
                             ::length
                             ::start-pos
                             ::time
                             ::transmissions]))
(s/def ::blocks (s/and (s/coll-of ::block)
                       ;; Actually, the length must be a power of 2
                       ;; TODO: Improve this spec!
                       ;; (Reference implementation uses 128)
                       #(= (rem (count %) 2) 0)))

;; If nonzero: minimum of active ::time values
;; Corresponds to earliestblocktime in original
(s/def ::earliest-time int?)
;; Corresponds to lastblocktime in original
;; Undocumented, but it looks like the value of recent
;; at the end of the previous send to parent
(s/def ::last-block-time int?)

;;; These next 3 really swirld around the sendbuf array/circular queue
;; Number of initial bytes sent and fully acknowledged
(s/def ::send-acked int?)
;; Number of additional bytes to send (i.e. haven't been sent yet)
(s/def ::send-bytes int?)
;; within sendbytes, number of bytes absorbed into blocks
(s/def ::send-processed int?)

;; These keys map to flags to send over the wire:
;; 2048 for normal EOF after sendbytes
;; 4096 for error after sendbytes
(s/def ::send-eof #{false ::normal ::error})
(s/def ::send-eof-acked boolean?)
(s/def ::send-eof-processed boolean?)

;; Totally undocumented (so far)
(s/def ::total-blocks int?)
(s/def ::total-block-transmissions int?)

;; I *know* I've spec'd out manifold.stream around here somewhere
;; TODO: Use that for these next two
(s/def ::stream any?)
(s/def ::child ::stream)
(s/def ::parent ::stream)
(s/def ::event-streams (s/keys :req [::child ::parent]))

;; This is the last time we checked the clock, in nanoseconds
(s/def ::recent int?)
;; These feed off recent, but are basically undocumented
(s/def ::last-panic int?)
(s/def ::last-edge int?)

;;; Bits that are (somehow) vital to the flow-control algorithm
(s/def ::rtt-timeout int?)

;; Q: Does it make sense to split this up?
;; That seems to be begging for trouble, although
;; nothing but ::blocks should involve much memory usage.
;; Then again, remember the lesson about conj'ing
;; hundreds of seqs
(s/def ::state (s/keys :req [::blocks
                             ::earliest-time
                             ::last-block-time
                             ::last-edge
                             ::last-panic
                             ::n-sec-per-block
                             ::recent
                             ::rtt-timeout
                             ::send-bytes
                             ::send-eof
                             ::send-eof-processed
                             ::send-eof-acked
                             ::total-blocks
                             ::total-block-transmissions]
                       :opt [::event-streams]))
