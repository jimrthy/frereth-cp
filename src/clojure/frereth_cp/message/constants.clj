(ns frereth-cp.message.constants
  (:require [frereth-cp.shared.constants :as K]))

(def ^:const stream-length-limit
  "How many bytes can the stream send before we've exhausted the address space?

(dec (pow 2 60)): this allows > 200 GB/second continuously for a year"
  1152921504606846976)

;;; FIXME: move these to shared.constants

(def ^:const k-div8
  "aka 1/8 k"
  ;; or (pow 2 7)
  128)

(def ^:const k-div4
  "aka 1/4 k"
  256)
(def ^:const k-div4f
  256.0)

(def ^:const k-div2
  "aka 1/2 k"
  512)

(def ^:const k-1
  "aka 1k"
  1024)
(def ^:const k-1f 1024.0)

(def ^:const k-2
  "aka 2k"
  2048)

(def ^:const k-4
  "aka 4k"
  4096)

(def ^:const k-8
  "aka 8k"
  8192)
(def ^:const k-8f
  8192.0)

(def ^:const k-16
  "aka 16k"
  16384)

(def ^:const k-64
  "aka 128k"
  65536)

(def ^:const k-128
  "aka 128k"
  131072)

(def ^:const m-16
  "aka 16m, or 16M, or 16Mi"
  16777216)

;; (dec (pow 2 32))
;; TODO: Eliminate this duplication
(def ^:const max-32-uint-obsolete K/max-32-uint)

(def ms-5
  "5 milliseconds, in nanoseconds

  This almost definitely belongs in shared.constansts,
  assuming it isn't there already"
  5000000)

(def ^:const sec->n-sec
  "Starting point for several values"
  ;; 1,000,000,000
  (long 1000000000))

(def ^:const secs-1
  "in nanoseconds"
  sec->n-sec)

(def ^:const secs-10
  "in nanoseconds"
  (* secs-1 10))

(def ^:const minute-1
  "in nanoseconds"
  (* 60 secs-1))

(def ^:const eof-error k-4)
(def ^:const eof-normal k-2)

(def ^:const recv-byte-buf-size
  "How many bytes from the parent will we buffer to send to the child?"
  k-128)

(def ^:const send-byte-buf-size
  "How many child bytes will we buffer to send?"
  ;; Don't want this too big, to avoid buffer bloat effects.

  ;; At the same time, it seems likely that the optimum will
  ;; vary from one application to the next.

  ;; Start with the default.

  ;; The reference implementation notes that this absolutely
  ;; must be a power of 2. Pretty sure that's because it involves
  ;; a circular buffer and uses bitwise ands for quick/cheap
  ;; modulo arithmetic.
  k-128)

(def ^:const header-length 48)
(def ^:const min-msg-len 48)
;; Note that this is really the max message packet length
;; The actual payload is limited to 1024 bytes
(def ^:const max-msg-len 1088)
(def ^:const min-padding-length 16)

(def ^:const max-outgoing-blocks
  "How many outgoing, non-ACK'd blocks will we buffer?

Corresponds to OUTGOING in the reference implementation.

That includes a comment that it absolutely must be a power of 2.

I think that's because it uses bitwise and for modulo to cope
with the ring buffer semantics, but there may be a deeper motivation."
  128)

(def ^:const max-bytes-in-initiate-message
  ;; Note that, really, this could be 640.
  ;; I don't know why the reference implementation
  ;; keeps it at 512.
  k-div2)

(def ^:const standard-max-block-length k-1)
