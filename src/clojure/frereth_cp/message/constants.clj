(ns frereth-cp.message.constants
  (:require [frereth-cp.message.specs :as specs]))

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

(def k-64
  "aka 128k"
  65536)

(def k-128
  "aka 128k"
  131072)

;; (dec (pow 2 32))
(def MAX_32_UINT 4294967295)

(def ms-5
  "5 milliseconds, in nanoseconds

  This almost definitely belongs in shared.constansts,
  assuming it isn't there already"
  5000000)

(def secs-1
  "in nanoseconds"
  specs/sec->n-sec)

(def secs-10
  "in nanoseconds"
  (* secs-1 10))

(def minute-1
  "in nanoseconds"
  (* 60 secs-1))
