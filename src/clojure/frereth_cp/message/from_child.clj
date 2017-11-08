(ns frereth-cp.message.from-child
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K-shared]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           [io.netty.buffer ByteBuf Unpooled]
           [java.io
            IOException
            InputStream]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef build-individual-block
        :args (s/cat :buf ::specs/buf
                     :start-pos ::specs/start-pos))
(defn build-individual-block
  [buf start-pos]
  {::specs/ackd? false
   ::specs/buf buf
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
                 (build-individual-block ::garbage 256 (* 256 i))))))

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
  ;; This has been through multiple incarnations.
  ;; Most started with the assumption that we know how
  ;; big the block size is here.
  ;; That's a terrible assumption.
  ;; For one thing, it's annoying to feed that into
  ;; here.
  ;; For another, it's really part of global state.
  ;; Isolate that part and trust that callers knew
  ;; what they were doing and sent us a properly-sized
  ;; buffer.

  ;; Actually, given that restriction, this function
  ;; is pointless.
  (throw (RuntimeException. "obsolete"))
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
                     (build-individual-block slice (+ strm-hwm (* n max-block-length)))))
                 (range block-count))]
        ;; Make sure that releasing an individual slice
        ;; doesn't release the entire thing
        ;; Q: How long does this take?
        ;; (surely it isn't very long...right?)
        (.retain buf (dec block-count))
        result)
      [(build-individual-block buf strm-hwm)])))

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

(s/fdef read-next-bytes-from-child!
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :child-out ::specs/child-out
                     :prefix bytes?
                     :available-bytes nat-int?
                     :max-to-read nat-int?)
        :ret (s/or :open bytes?
                   :eof ::specs/eof-flag))
(defn read-next-bytes-from-child!
  ([message-loop-name
    ^InputStream child-out
    prefix
    available-bytes
    max-to-read]
   (let [prelog (utils/pre-log message-loop-name)
         prefix-gap (count prefix)]
     (log/debug prelog (str
                        "Trying to read "
                        available-bytes
                        "/"
                        max-to-read
                        " bytes from child and append them to "
                        (count prefix)
                        " that we've already received"))
     (if (not= 0 available-bytes)
       ;; Simplest scenario: we have bytes waiting to be consumed
       (let [bytes-to-read (min available-bytes max-to-read)
             bytes-read (byte-array (+ bytes-to-read prefix-gap))
             _ (log/debug prelog "Reading" bytes-to-read "from child. Should not block")
             n (.read child-out bytes-read prefix-gap bytes-to-read)]
         (log/debug prelog "Read" n "bytes")
         (if (not= n bytes-to-read)
           (do
             ;; If this happens frequently, the buffer's probably too small.
             (log/warn prelog (str "Tried to read "
                                   bytes-to-read
                                   " bytes from the child.\nGot "
                                   n
                                   " instead.\n"))
             (let [actual-result (byte-array (+ prefix-gap n))]
               (b-t/byte-copy! actual-result 0 prefix-gap prefix)
               (b-t/byte-copy! actual-result prefix-gap n bytes-read)
               actual-result))
           (do
             (b-t/byte-copy! bytes-read 0 prefix-gap prefix)
             bytes-read)))
       (try
         ;; More often, we should spend all our time waiting.
         (let [_ (log/debug prelog "Blocking until we get a byte from the child")
               next-prefix (.read child-out)]
           ;; My echo test is never returning from that.
           ;; Which, really, should mean that the PipedInputStream never gets closed.
           ;; Aside from the fact that the child is never echoing any bytes
           ;; back.
           ;; Actually, it never seems to receive any bytes.
           (log/debug prelog (str "Read a byte from child ("
                                  next-prefix
                                  "). Q: Are there more?"))
           (if (= next-prefix -1)
             ;; EOF
             (if (< 0 prefix-gap)
               (do
                 (log/info "Reached EOF. Have"
                           prefix-gap
                           "bytes buffered to send first")
                 ;; Q: Does it make sense to handle it this way?
                 ;; It would be nice to just attach the EOF flag to
                 ;; the bytes we're getting ready to send along.
                 ;; That would mean having this return a data
                 ;; structure that includes both the byte array
                 ;; and the flag.
                 ;; For now, if we had a prefix, just return that
                 ;; and pretend that everything's normal.
                 ;; We'll get the EOF signal soon enough.
                 prefix)
               ::specs/normal))
           (let [bytes-remaining (.available child-out)]
             (log/info prelog bytes-remaining "more bytes waiting to be read")
             (if (< 0 bytes-remaining)
               ;; Assume this means the client just sent us a sizeable
               ;; chunk.
               ;; Go ahead and recurse.
               ;; This could perform poorly if we hit a race condition
               ;; and the child's writing a single byte at a time
               ;; as fast as we can loop, but the maximum buffer size
               ;; should protect us from that being a real problem,
               ;; and it seems like a fairly unlikely scenario.
               ;; At this layer, we have to assume that our child
               ;; code (which is really the library consumer) isn't
               ;; deliberately malicious to its own performance.
               (let [combined-prefix (byte-array (inc prefix-gap))]
                 (log/debug prelog
                            "Getting ready to copy"
                            prefix-gap
                            "bytes from"
                            prefix
                            "into a new combined-prefix byte-array")
                 (aset-byte combined-prefix
                            prefix-gap
                            (b-t/possibly-2s-complement-8 next-prefix))
                 ;; This next part seems pretty awful.
                 ;; If nothing else, prefix should usually be empty
                 ;; here.
                 ;; TODO: profile and validate my intuition about this
                 (b-t/byte-copy! combined-prefix 0 prefix-gap prefix)
                 ;; TODO: Ditch the try/catch so I can just switch back
                 ;; to using recur here
                 (read-next-bytes-from-child! message-loop-name
                                              child-out
                                              combined-prefix
                                              bytes-remaining
                                              (dec max-to-read)))
               (byte-array prefix))))
         (catch RuntimeException ex
           (log/error ex "Reading from child failed"))))))
  ([message-loop-name
    child-out
    available-bytes
    max-to-read]
   (read-next-bytes-from-child! message-loop-name
                                child-out
                                []
                                available-bytes
                                max-to-read)))

(s/fdef build-byte-consumer
        ;; TODO: This is screaming for generative testing
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :array-o-bytes bytes?)
        :ret ::specs/state)
(defn build-byte-consumer
  "Accepts a byte-array from the child."
  ;; Lines 319-337
  ;; The obvious approach is just to feed ByteBuffers
  ;; from this callback to the parent's callback.

  ;; That obvious approach completely misses the point that
  ;; this namespace is about buffering. We need to hang onto
  ;; those buffers here until they've been ACK'd.
  [message-loop-name
   ^bytes array-o-bytes]
  (let [prelog (utils/pre-log message-loop-name)]
    ;; Note that back-pressure no longer gets applied if we
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
          ;; Doing a memcpy also seems a lot more wasteful.
          _ (.writerIndex buf buf-size)
          block (build-individual-block message-loop-name buf)]
      (log/debug prelog
                 buf-size
                 "-byte Block to add")
      (fn [{{:keys [::specs/ackd-addr
                    ::specs/max-block-length
                    ::specs/strm-hwm
                    ::specs/un-sent-blocks]} ::specs/outgoing
            :keys [::specs/message-loop-name]
            :as state}]
        (let [nested-prelog (utils/pre-log message-loop-name)]
          (log/debug nested-prelog
                     (str "Adding new message block(s) to "
                          ;; TODO: Might be worth logging the actual contents
                          ;; when it's time to trace
                          (count un-sent-blocks)
                          " unsent others from a thunk built by\n"
                          prelog))
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
                         conj
                         block)
              (update-in [::specs/outgoing ::specs/strm-hwm] + buf-size)))

        (throw (RuntimeException. "How much work can we do elsewhere?"))))))

(s/fdef forward-bytes-from-child!
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :stream ::specs/stream
                     :array-o-bytes (s/or :message bytes?
                                          :eof ::specs/eof-flag))
        :fn #(= (:ret %) (-> % :args :array-o-bytes))
        :ret (s/or :message bytes?
                   :eof ::specs/eof-flag))
(defn forward-bytes-from-child!
  [message-loop-name
   stream
   array-o-bytes]
  ;; This seems overly convoluted.
  ;; message/child-> writes bytes to a PipedOutputStream.
  ;; start-child-monitor! has an event loop that centers around
  ;; process-next-bytes-from-child!
  ;; That calls read-next-bytes-from-child!, which pulls bytes
  ;; from the associated PipedInputStream, then calls
  ;; forward-bytes-from-child!
  ;; This, in turn, tries to put those bytes onto the manifold
  ;; stream that feeds into the main i/o loop. This winds up
  ;; calling message/trigger-from-child which, in turn,
  ;; starts setting up the real buffering that checks for
  ;; room (which needed to happen before we accepted them in
  ;; the first place) followed by calling consume-from-child.
  ;; That converts the incoming bytes to a block description
  ;; and adds it to the un-sent-blocks queue.

  ;; I can do better than this.
  ;; Instead of forwarding the bytes directly for the i/o
  ;; loop to process, pass along something (a monad?) that
  ;; describes what the i/o loop should do (this should really
  ;; amount to adding bytes to the outbound queue and then trying
  ;; to send them)
  (let [prelog (utils/pre-log message-loop-name)
        callback (build-byte-consumer message-loop-name array-o-bytes)]
    ;; FIXME: Build a partial function that the main ioloop can
    ;; call in order to really put the new message buffers onto
    ;; its un-sent-quueue.
    ;; Send that instead of the raw bytes.
    (log/debug prelog
               "Received"
               (count array-o-bytes)
               "bytes from child. Trying to forward them to the main i/o loop")
    ;; Here's an annoying detail:
    ;; I *do* want to block here, at least for a while.
    ;; Then we do to get these bytes added to the
    ;; (now invisible) state buffer that's managed
    ;; by that main event loop.
    ;; And then that event loop should try to send
    ;; it along to the parent, if it's been long enough
    ;; since the last bunch of bytes.
    ;; There's a definite balancing act in splitting
    ;; work between these 2 threads.
    ;; I want to pull bytes from the child as fast as
    ;; possible, but there isn't any point if the main
    ;; ioloop is bogged down handling fiddly state management
    ;; details that would make more sense in this thread.

    ;; FIXME: Ditch the magic numbers
    (let [blocker (dfrd/deferred)
          submitted (strm/try-put! stream
                                   [::specs/child-> callback blocker]
                                   10000)]
      (dfrd/on-realized submitted
                        (fn [success]
                          (log/debug
                           (utils/pre-log message-loop-name)
                           "Bytes from child successfully posted to main i/o loop triggered from\n"
                           prelog))
                        (fn [failure]
                          (log/error
                           failure
                           (utils/pre-log message-loop-name)
                           "Failed to add bytes from child to main i/o loop triggered from\n"
                           prelog)))
      ;; message-test pretty much duplicates this in try-multiple-sends
      ;; TODO: eliminate the duplication
      (loop [n 6]
        (let [waiting
              (deref blocker 10000 ::timed-out)]
          (if (= waiting ::timed-out)
            (do
              (log/warn prelog "Timeout number" (- 7 n) "waiting to buffer bytes from child")
              (if (< 0 n)
                (recur (dec n))
                ::specs/error))
            (do
              (if (bytes? array-o-bytes)
                (log/debug prelog
                           (count array-o-bytes)
                           "bytes from child processed by main i/o loop")
                (log/warn prelog "Got some EOF signal:" array-o-bytes))
              array-o-bytes)))))))

(s/fdef room-for-child-bytes?
        :args (s/cat :state ::specs/state)
        :ret boolean?)
(defn room-for-child-bytes?
  ;; The reference implementation doesn't take the size of
  ;; the incoming message into account here.
  ;; It doesn't need to.
  ;; It pulls bytes out of a pipe, up to max-block-length
  ;; at a time.
  ;; Q: Do I want to?
  ;; A: I have to. If it tries to send too much in one
  ;; shot, that's going to overflow the buffer.
  ;; The easy approach is to just let the client buffer as many
  ;; bytes as it likes, but then it doesn't have any way to learn
  ;; that the network's down until memory's full.
  "Does send-buf have enough space left for any message from child?"
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

(s/fdef process-next-bytes-from-child!
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :child-out ::specs/child-out
                     :stream ::specs/stream
                     :max-to-read int?)
        :ret (s/or :message bytes?
                   :eof ::specs/eof-flag))
(defn process-next-bytes-from-child!
  [message-loop-name
   ^InputStream child-out
   stream
   max-to-read]
  (let [prelog (utils/pre-log message-loop-name)
        available-bytes (.available child-out)
        ;; note that this may also be the EOF flag
        array-o-bytes
        (try
          (read-next-bytes-from-child! message-loop-name
                                       child-out
                                       available-bytes
                                       max-to-read)
          (catch RuntimeException ex
            (log/error ex prelog)
            ::specs/error))]
    ;; In order to do this, we have to query for state.
    ;; Which is obnoxious.
    ;; *And* we need to watch for buffer space to
    ;; open up so we can proceed.
    ;; But this really is the best place to apply
    ;; back-pressure.
    (log/warn prelog
              (str "Need to check room-for-child-bytes?"
                   " before calling read-next-bytes-from-child!"))
    (forward-bytes-from-child! message-loop-name
                              stream
                              array-o-bytes)))

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

(s/fdef blocks-not-sent?
        :args (s/cat :state ::specs/state)
        :ret boolean?)
(defn blocks-not-sent?
  "Are there pending blocks from the child that haven't been sent once?"
  [{{:keys [::specs/un-sent-blocks]} ::specs/outgoing
    :as state}]
  (< 0 (count un-sent-blocks)))

(s/fdef start-child-monitor!
        :args (s/cat :initial-state ::specs/state
                     :io-handle ::specs/io-handle)
        :ret ::specs/child-output-loop)
(defn start-child-monitor!
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/client-waiting-on-response]
     :as flow-control} ::specs/flow-control
    :as initial-state}
   {:keys [::specs/child-out
           ::specs/stream]
    :as io-handle}]
  {:pre [message-loop-name]}
  ;; TODO: This needs pretty hefty automated tests
  (let [prelog (utils/pre-log message-loop-name)]
    (log/info prelog "Starting the child-monitor thread")
    (dfrd/future
      (let [prelog (utils/pre-log message-loop-name)
            eof? (atom false)]
        (try
          (loop []
            (log/debug prelog "Top of client-waiting-on-initial-response loop")
            (when (not (realized? client-waiting-on-response))
              (let [eof'?
                    (process-next-bytes-from-child! message-loop-name
                                                    child-out
                                                    stream
                                                    K/max-bytes-in-initiate-message)]
                (if (bytes? eof'?)
                  (recur)  ; regular message. Keep going
                  (swap! eof? not)))))
          (while (not @eof?)
            (log/debug prelog "Top of main child-read loop")
            ;; This next call never seems to return.
            (let [eof'?
                  (process-next-bytes-from-child! message-loop-name
                                                  child-out
                                                  stream
                                                  K/standard-max-block-length)]
              (when eof'?
                (swap! eof? not))))
          (log/info prelog "Child monitor exiting")
          (catch IOException ex
            ;; TODO: Need to send an EOF signal to main ioloop so
            ;; it can notify the parent (or quit, as the case may be)
            (log/error ex
                       prelog
                       "TODO: Not Implemented. This should only happen when child closes pipe")
            (throw (RuntimeException. ex)))
          (catch ExceptionInfo ex
            (log/error ex prelog "FIXME: Add details from calling .getData"))
          (catch Exception ex
            (log/error ex "Bady unexpected exception")))))))
