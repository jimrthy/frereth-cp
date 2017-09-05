(ns frereth-cp.message.from-child
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn room-for-child-bytes?
  "Does send-buf have enough space left for a message from child?"
  [{{:keys [::specs/send-bytes]} ::specs/outgoing
    :as state}]
  ;; Line 322: This also needs to account for send-acked
  ;; For whatever reason, DJB picked this (-4K) as the
  ;; end-point to refuse to read
  ;; more child data before we hit send-byte-buf-size.
  ;; Presumably that reason remains valid.
  ;; (Although it seems like it would make more sense to
  ;; look at the actual message that we're considering...
  ;; I'm just not quite ready to make that particular
  ;; break with his implementation)

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

  Lines 319-337"
  ;; The obvious approach is just to feed ByteBuffers
  ;; from this callback to the parent's callback.

  ;; That obvious approach completely misses the point that
  ;; this ns is a buffer. We need to hang onto those buffers
  ;; here until they've been ACK'd.
  [{{:keys [::specs/send-acked
            ::specs/send-bytes]} ::specs/outgoing
    :as state}
   ;; Child should neither know nor care that netty is involved,
   ;; so a ByteBuf really isn't appropriate here.
   ;; Much better to just just accept a byte array.
   ;; A clojure vector of bytes would generally be better than that.
   ;; A clojure object that we could just serialize to either
   ;; EDN, transit, or Fressian seems
   ;; like it would be best.
   ;; Of course, we should allow the byte array for apps that
   ;; want/need to do their own serialization.
   ;; And it's important to remember that, like TCP, this is meant
   ;; to be a streaming protocol.
   ;; So the higher-level options don't make sense at this level.
   ;; Though it seems like it would be nice to generally be able
   ;; to just hand the message to a serializer and have it handle
   ;; the streaming.
   ^bytes array-o-bytes]
  ;; Note that back-pressure gets applied if we
  ;; already have ~124K pending because caller started
  ;; dropping packets)
  ;; (It doesn't seem like it should matter, except
  ;; as an upstream signal that there's some kind of
  ;; problem)
  (let [buf (Unpooled/wrappedBuffer array-o-bytes)
        ;; In the original, this is the offset into the circular
        ;; buf where we're going to start writing incoming bytes.
        pos (+ (rem send-acked K/send-byte-buf-size) send-bytes)
        available-buffer-space (- K/send-byte-buf-size pos)
        bytes-to-read (min available-buffer-space (count array-o-bytes))
        send-bytes (+ send-bytes bytes-to-read)
        block {::specs/buf buf
               ::specs/transmissions 0}]
    (when (>= send-bytes K/stream-length-limit)
      ;; Want to be sure standard error handlers don't catch
      ;; this...it needs to force a fresh handshake.
      (throw (AssertionError. "End of stream")))
    (-> state
        (update-in [::specs/outgoing ::specs/blocks] conj block)
        (assoc-in [::specs/outgoing ::specs/send-bytes] send-bytes)
;;;  337: update recent
        (assoc ::specs/recent (System/nanoTime)))))
