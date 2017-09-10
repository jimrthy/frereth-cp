(ns frereth-cp.message.from-child
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
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

(defn build-block-descriptions
  "For cases where a child sends a byte array that's too large"
  [^ByteBuf buf max-block-length]
  (let [cap (.capacity buf)
        block-count (int (Math/ceil (/ cap max-block-length)))]
    (map (fn [n]
           (let [length (if (< n (dec block-count))
                          max-block-length
                          (rem cap max-block-length))]
             {::specs/buf (.slice buf (* n max-block-length) length)
              ;; Q: Is there any good justification for tracking this twice?
              ::specs/length length
              ;; TODO: Add a signal for marking this true
              ::specs/send-eof false
              ::specs/transmissions 0
              ::specs/time (System/nanoTime)
              ;; Q: What should these actually be?
              ::specs/start-pos 0}))
         (range block-count))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn room-for-child-bytes?
  "Does send-buf have enough space left for a message from child?"
  [{{:keys [::specs/send-bytes
            ::specs/max-block-length]} ::specs/outgoing
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
                     :array-o-bytes bytes?))
(defn child-consumer
  "Accepts a byte-array from the child.

  Lines 319-337"
  ;; The obvious approach is just to feed ByteBuffers
  ;; from this callback to the parent's callback.

  ;; That obvious approach completely misses the point that
  ;; this namespace is about buffering. We need to hang onto
  ;; those buffers here until they've been ACK'd.
  [{{:keys [::specs/max-block-length
            ::specs/send-acked
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
  (log/debug "Adding another message block(s) to"
             (get-in state [::specs/outgoing ::specs/blocks]))
  ;; Note that back-pressure gets applied if we
  ;; already have ~124K pending because caller started
  ;; dropping packets.
  ;; (It doesn't seem like it should matter, except
  ;; as an upstream signal that there's some kind of
  ;; problem)
  (let [buf-size (count array-o-bytes)
        ;; Q: Use Pooled direct buffers instead?
        ;; A: Direct buffers wouldn't make any sense.
        ;; After we get done with all the slicing and
        ;; dicing that needs to happen to get the bytes
        ;; to the parent, they still need to be translated
        ;; back into byte arrays so they can be encrypted.
        ;; Pooled buffers might make sense, except that
        ;; we're starting from a byte array. So it would
        ;; be silly to copy it.
        buf (Unpooled/wrappedBuffer array-o-bytes)
        ;; This lets people downstream know that there are
        ;; bytes available
        _ (.writerIndex buf buf-size)
        ;; In the original, this is the offset into the circular
        ;; buf where we're going to start writing incoming bytes.
        pos (+ (rem send-acked K/send-byte-buf-size) send-bytes)
        available-buffer-space (- K/send-byte-buf-size pos)
        ;; I'm pretty sure this concept throws a major
        ;; wrench into my gears.
        ;; I don't remember handling this sort of buffering
        ;; at all.
        ;; Q: If I drop the extra bytes, how do I inform the
        ;; client?
        bytes-to-read (min available-buffer-space buf-size)
        ;; This no longer matches the reality where I'm basically
        ;; ignoring buffer limits
        send-bytes (+ send-bytes bytes-to-read)
        blocks (build-block-descriptions buf max-block-length)]
    (log/debug "Blocks to add:" (count blocks))
    (when (>= send-bytes K/stream-length-limit)
      ;; Want to be sure standard error handlers don't catch
      ;; this...it needs to force a fresh handshake.
      (throw (AssertionError. "End of stream")))
    (-> state
        (update ::specs/outgoing (fn [cur]
                                   (-> cur
                                       (update ::specs/blocks (comp vec concat) blocks)
                                       (assoc ::specs/send-bytes send-bytes))))
;;;  337: update recent
        (assoc ::specs/recent (System/nanoTime)))))
