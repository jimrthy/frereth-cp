(ns frereth-cp.message.from-child
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.util :as utils])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef build-individual-block
        :args (s/cat :buf ::specs/buf
                     :length ::specs/length
                     :start-pos ::specs/start-pos))
(defn build-individual-block
  [buf length start-pos]
  {::specs/ackd? false
   ::specs/buf buf
   ;; Q: Is there any good justification for tracking this
   ;; both here and in the buf?
   ;; A: No.
   ;; TODO: Make this go away.
   ::specs/length length
   ;; TODO: Add a signal for marking this true
   ;; (It probably needs to involve a close! function
   ;; in the message ns)
   ::specs/send-eof ::specs/false
   ::specs/transmissions 0
   ::specs/time (System/nanoTime)
   ;; There's the possibility of using a Nagle
   ;; algorithm later to consolidate smaller blocks,
   ;; so maybe it doesn't make sense to mess with it here.
   ::specs/start-pos start-pos})
(comment
  ;; This seems to be ridiculously slow.
  ;; TODO: Check the timing. Maybe it speeds up as the JIT
  ;; warms up
  (time (doseq i (range 1000)
               (build-individual-block ::garbage 256 (* 256 i))))
  (do
    ;; These numbers seem far too small
    (doseq i (range 1000)
           (build-individual-block ::garbage 256 (* 256 i)))
    (time (doseq i (range 1000)
                 (build-individual-block ::garbage 256 (* 256 i)))))
  )

(s/fdef build-block-descriptions
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :strm-hwm ::specs/strm-hwm
                     :buf ::specs/buf
                     :max-block-length ::specs/max-block-length)
        :ret ::specs/blocks)
(defn build-block-descriptions
  "For cases where a child sends a byte array that's too large"
  [message-loop-name
   strm-hwm
   ^ByteBuf buf
   max-block-length]
  {:pre [#(< 0 max-block-length)]}
  ;; If max-block-length is < 1024, then we're a client that has not
  ;; yet received a response to its Initiate packet. Which could arrive
  ;; at any time.
  ;; Really want to pull as many bytes as we can from the array, then
  ;; put it back (at the head of the queue, which is problematic)
  ;; to be read again during the
  ;; next iteration (when we might have received an ACK that will let
  ;; us double up on the bandwidth usage).
  ;; This takes me back to an older implementation where I add bytes
  ;; to a ByteBuf and notify handlers that more bytes are available.
  ;; Or to the reference implementation's ring buffers.
  (let [cap (.capacity buf)
        remainder (mod cap max-block-length)
        block-count (int (Math/ceil (/ cap max-block-length)))]
    (log/debug (utils/pre-log message-loop-name)
               (str "Building "
                    block-count
                    " "
                    max-block-length
                    "-byte buffer slice(s) from "
                    buf))
    (if (< 1 block-count)
      (let [result
            ;; Building a single block takes ~8 ms, which seems quite a bit longer than it should.
            ;; Building 17 blocks is taking 13 milliseconds.
            ;; That's ridiculous.
            ;; Especially since this is setting up a lazy seq...is *that* what's taking so long?
            ;; TODO: Compare with using (reduce), possibly on a transient
            ;; (or ztellman's proteus?)
            ;; Maybe it evens out when we're looking at larger data
            ;; FIXME: Switch to using reducibles
            (map (fn [n]
                   (let [length (if (< n (dec block-count))
                                  max-block-length
                                  ;; Final block is probably smaller than the rest,
                                  ;; except when I've been writing nice clean test
                                  ;; cases that wind up setting it up to be 0 bytes
                                  ;; long without this next check.
                                  (if (not= 0 remainder)
                                    remainder
                                    max-block-length))
                         slice (.slice buf (* n max-block-length) length)]
                     (build-individual-block slice length (+ strm-hwm (* n max-block-length)))))
                 (range block-count))]
        ;; Make sure that releasing an individual slice
        ;; doesn't release the entire thing
        ;; Q: How long does this take?
        ;; (surely it isn't very long...right?)
        (.retain buf (dec block-count))
        result)
      [(build-individual-block buf cap strm-hwm)])))

(s/fdef count-buffered-bytes
        :args (s/cat :blocks ::specs/blocks)
        :ret nat-int?)
(defn count-buffered-bytes
  [blocks]
  (reduce (fn [acc block]
            (+ acc
               (let [^ByteBuf buf (::specs/buf block)]
                 ( .readableBytes buf))))
          0
          blocks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef buffer-size
        :args (s/cat :outgoing ::specs/outgoing)
        :ret nat-int?)
(defn buffer-size
  [{:keys [::specs/un-ackd-blocks
           ::specs/un-sent-blocks]
    :as outgoing}]
  "How many bytes are currently waiting in send buffers?"
  (reduce +
          (map count-buffered-bytes [un-ackd-blocks
                                     un-sent-blocks])))

(s/fdef room-for-child-bytes?
        :args (s/cat :state ::specs/state)
        :ret boolean?)
(defn room-for-child-bytes?
  ;; The reference implementation doesn't take the size of
  ;; the incoming message into account
  ;; Q: Do I want to?
  "Does send-buf have enough space left for a message from child?"
  [{{:keys [::specs/ackd-addr
            ::specs/strm-hwm]} ::specs/outgoing
    :as state}]
  {:pre [ackd-addr
         strm-hwm]}
  ;; Line 322: This also needs to account for acked-addr
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
  (let [send-bytes (- strm-hwm ackd-addr)]
    (< (+ send-bytes K/k-4) K/send-byte-buf-size)))

(s/fdef blocks-not-sent?
        :args (s/cat :state ::specs/state)
        :ret boolean?)
(defn blocks-not-sent?
  "Are there pending blocks from the child that haven't been sent once?"
  [{{:keys [::specs/un-sent-blocks]} ::specs/outgoing
    :as state}]
  (< 0 (count un-sent-blocks)))

(s/fdef consume-from-child
        ;; TODO: This is screaming for generative testing
        :args (s/cat :state ::specs/state
                     :array-o-bytes bytes?)
        :ret ::specs/state)
(defn consume-from-child
  "Accepts a byte-array from the child.

  Lines 319-337"
  ;; The obvious approach is just to feed ByteBuffers
  ;; from this callback to the parent's callback.

  ;; That obvious approach completely misses the point that
  ;; this namespace is about buffering. We need to hang onto
  ;; those buffers here until they've been ACK'd.
  [{{:keys [::specs/ackd-addr
            ::specs/max-block-length
            ::specs/strm-hwm
            ::specs/un-sent-blocks]} ::specs/outgoing
    :keys [::specs/message-loop-name]
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
  (let [prelog (utils/pre-log message-loop-name)]
    (log/debug prelog
               (str "Adding new message block(s) to "
                    ;; TODO: Might be worth logging the actual contents
                    ;; when it's time to trace
                    (count un-sent-blocks)
                    " unsent others"))
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
          ;; The writer index indicates the space that's
          ;; available for reading.
          ;; Needing to do this feels wrong.
          ;; Honestly, I'm relying on functionality
          ;; that doesn't seem to be quite documented.
          ;; It almost seems as though I really should be
          ;; setting up a new [pooled] buffer and reading
          ;; array-o-bytes into it instead.
          ;; That also seems a lot more wasteful.
          _ (.writerIndex buf buf-size)
          ;; In the original, this is the offset into the circular
          ;; buf where we're going to start writing incoming bytes.
          pos (rem (inc strm-hwm) K/send-byte-buf-size)
          available-buffer-space (- K/send-byte-buf-size pos)
          ;; I'm pretty sure this concept throws a major
          ;; wrench into my gears.
          ;; I don't remember handling this sort of buffering
          ;; at all.
          ;; Q: If I drop the extra bytes, how do I inform the
          ;; client?
          bytes-to-read (min available-buffer-space buf-size)
          ;; Major(?) issue with this approach:
          ;; If the client child starts by writing (for example), 16K bytes
          ;; all at once, we'll break that into 32 blocks to send.
          ;; After the server responds with the first message packet (which
          ;; is probably the ACK), the available message size increases
          ;; significantly.
          ;; This seems like a good reason to rethink the big picture
          ;; strategy I'm using here.
          blocks (build-block-descriptions message-loop-name strm-hwm buf max-block-length)]
      ;; Q: What are the odds that calling pretty here accounts for
      ;; the huge timing delays I'm seeing between this log message
      ;; and the one at the top of build-block-descriptions?
      (log/debug prelog
                 (str (count blocks)
                      " Block(s) to add:\n"
                      (utils/pretty blocks)))
      (when (>= (- strm-hwm ackd-addr) K/stream-length-limit)
        ;; Want to be sure standard error handlers don't catch
        ;; this...it needs to force a fresh handshake.
        ;; Note that this check has major problems:
        ;; This is the number of bytes we have buffered
        ;; that have not yet been ACK'd.
        ;; We really should have quit reading from the child
        ;; long before this due to buffer overflows.
        ;; OTOH, the spec *does* define this as the end
        ;; of the stream.
        ;; So, when ackd-addr gets here (or possibly
        ;; strm-hwm), we're done.
        ;; TODO: Revisit this.
        (throw (AssertionError. "End of stream")))
      (-> state
          (update-in [::specs/outgoing ::specs/un-sent-blocks]
                     (fn [cur]
                       ;; un-sent-blocks is a PersistentQueue.
                       ;; Can't just concat.
                       (reduce (fn [acc block]
                                 (conj acc block))
                               cur
                               blocks)))
          (update-in [::specs/outgoing ::specs/strm-hwm] + bytes-to-read)))))
