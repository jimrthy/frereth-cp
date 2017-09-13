(ns frereth-cp.message.constants
  (:require [frereth-cp.shared.constants :as K]))

(def stream-length-limit
  "How many bytes can the stream send before we've exhausted the address space?

(dec (pow 2 60)): this allows > 200 GB/second continuously for a year"
  1152921504606846976)

;; These seem like they'd make more sense under shared.constants

(def k-div4
  "aka 1/4 k"
  256)

(def k-div2
  "aka 1/2 k"
  512)

(def k-1
  "aka 1k"
  1024)

(def k-2
  "aka 2k"
  2048)

(def k-4
  "aka 4k"
  4096)

(def k-8
  "aka 8k"
  8192)

(def k-16
  "aka 16k"
  16384)

(def k-64
  "aka 128k"
  65536)

(def k-128
  "aka 128k"
  131072)

;; (dec (pow 2 32))
;; TODO: Eliminate this duplication
(def max-32-uint K/max-32-uint)

(def ms-5
  "5 milliseconds, in nanoseconds

  This almost definitely belongs in shared.constansts,
  assuming it isn't there already"
  5000000)

(def ^:const sec->n-sec
  "Starting point for several values"
  ;; 1,000,000,000
  1000000000 )

(def ^:const secs-1
  "in nanoseconds"
  sec->n-sec)

(def secs-10
  "in nanoseconds"
  (* secs-1 10))

(def minute-1
  "in nanoseconds"
  (* 60 secs-1))

(def error-eof k-4)
(def normal-eof k-2)

(def recv-byte-buf-size
  "How many bytes from the parent will we buffer to send to the child?"
  k-128)

(def send-byte-buf-size
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

(def max-outgoing-blocks
  "How many outgoing, non-ACK'd blocks will we buffer?

Corresponds to OUTGOING in the reference implementation.

That includes a comment that it absolutely must be a power of 2.

I think that's because it uses bitwise and for modulo to cope
with the ring buffer semantics, but there may be a deeper motivation."
  128)

(def initial-max-block-length
  k-div2)

(def standard-max-block-length k-1)
