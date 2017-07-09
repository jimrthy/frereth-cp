(ns frereth-cp.message.from-child
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs])
  (:import [io.netty.buffer ByteBuf]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn room-for-child-bytes?
  "Does send-buf have enough space left for a message from child?"
  [{:keys [::specs/send-bytes]
    :as state}]
  ;; Line 322: This also needs to account for send-acked
  ;; For whatever reason, DJB picked this as the end-point to refuse to read
  ;; more child data before we hit send-byte-buf-size.
  ;; Presumably that reason remains valid

  ;; Q: Is that an important part of the algorithm, or is
  ;; it "just" dealing with the fact that we have a circular
  ;; buffer with parts that have not yet been GC'd?
  ;; And is it possible to tease apart that distinction?
  (< (+ send-bytes K/k-4) K/send-byte-buf-size))

(s/fdef child-consumer
        :args (s/cat :state ::specs/state
                     :buf ::specs/buf))
(defn child-consumer
  "Accepts buffers of bytes from the child.

  Lines 319-337

The obvious approach is just to feed ByteBuffers
from this callback to the parent's callback.

That obvious approach completely misses the point that
this ns is a buffer. We need to hang onto those buffers
here until they've been ACK'd.

This approach was really designed as an event that
would be triggered when an event arrives on a stream.
Or maybe as part of an event loop that polls various
streams for available events.

It really should just be a plain function call.
I think this is really what I have planned for
the ::child-> key under state.

TODO: Untangle the strands and get this usable.
"
  [{:keys [::specs/send-acked
           ::specs/send-bytes]
    :as state}
   ^ByteBuf buf]
  ;; Q: Need to apply back-pressure if we
  ;; already have ~124K pending?
  ;; (It doesn't seem like it should matter, except
  ;; as an upstream signal that there's a network
  ;; issue)
  (let [;; In the original, this is the offset into the circular
        ;; buf where we're going to start writing incoming bytes.
        pos (+ (rem send-acked K/send-byte-buf-size) send-bytes)
        available-buffer-space (- K/send-byte-buf-size pos)
        bytes-to-read (min available-buffer-space (.readableBytes buf))
        send-bytes (+ send-bytes bytes-to-read)
        block {::buf buf
               ::transmissions 0}]
    (when (>= send-bytes K/stream-length-limit)
      ;; Want to be sure standard error handlers don't catch
      ;; this...it needs to force a fresh handshake.
      (throw (AssertionError. "End of stream")))
    (-> state
        (update ::blocks conj block)
        (assoc ::send-bytes send-bytes
;;;  337: update recent
               ::recent (System/nanoTime)))))
