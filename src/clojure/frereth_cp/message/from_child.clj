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
  [buf]
  {::specs/ackd? false
   ::specs/buf buf
   ;; TODO: Add a signal for marking this true
   ;; (It probably needs to involve a close! function
   ;; in the message ns)
   ::specs/send-eof ::specs/false
   ::specs/transmissions 0
   ::specs/time (System/nanoTime)})
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
                        "Trying to pull "
                        available-bytes
                        "/"
                        max-to-read
                        " bytes from child and append them to "
                        (count prefix)
                        " that we've already pulled"))
     (if (not= 0 available-bytes)
       ;; Simplest scenario: we have bytes waiting to be consumed
       (let [bytes-to-read (min available-bytes max-to-read)
             bytes-read (byte-array (+ bytes-to-read prefix-gap))
             _ (log/debug prelog "Reading" bytes-to-read " byte(s) from child. Should not block")
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
         (log/debug prelog "Blocking until we get a byte from the child")
         (let [next-prefix (.read child-out)]
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
                 (log/info prelog
                           "Reached EOF. Have"
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
               (do
                 (log/warn prelog "Signalling normal EOF")
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
                 (byte-array prefix)))))
         ;; TODO: Tighten these up. If a .read call throws an exception,
         ;; then OK.
         ;; If something else has a problem, that's really a different story.
         (catch IOException ex
           (log/warn ex
                     prelog
                     "EOF")
           ::specs/normal)
         (catch RuntimeException ex
           (log/error ex
                      prelog
                      "Reading from child failed")
           ::specs/error)))))
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
                     :array-o-bytes (s/or :message bytes?
                                          :eof ::specs/eof-flag))
        :ret (s/fspec :args (s/cat :state ::specs/state)
                      :ret ::specs/state))
(defn build-byte-consumer
  "Accepts a byte-array from the child."
  ;; Lines 319-337
  ;; The obvious approach is just to feed ByteBuffers
  ;; from this callback to the parent's callback.

  ;; That obvious approach completely misses the point that
  ;; this namespace is about buffering. We need to hang onto
  ;; those buffers here until they've been ACK'd.
  [message-loop-name
   ;; TODO: This needs a better name.
   ;; Under normal operating conditions, it *is*
   ;; a byte-array.
   ;; But then we hit EOF, and it gets repurposed.
   ;; Actually, that kind of says it all.
   ;; TODO: Add an EOF flag here so we don't have
   ;; to do that repurposing.
   array-o-bytes]
  (let [prelog (utils/pre-log message-loop-name)
        eof? (keyword? array-o-bytes)
        buf-size (if eof?
                   0
                   (count array-o-bytes))
        repr (if eof?
               (str "EOF: " array-o-bytes)
               (str buf-size "-byte array"))
        block
        (if (keyword? array-o-bytes)
          (assoc
           (build-individual-block (Unpooled/wrappedBuffer (byte-array 0)))
           ::specs/send-eof array-o-bytes)
          ;; Note that back-pressure no longer gets applied if we
          ;; already have ~124K pending because caller started
          ;; dropping packets.
          ;; (It doesn't seem like it should matter, except
          ;; as an upstream signal that there's some kind of
          ;; problem)
          (let [^bytes actual array-o-bytes
                ;; Q: Use Pooled direct buffers instead?
                ;; A: Direct buffers wouldn't make any sense.
                ;; After we get done with all the slicing and
                ;; dicing that needs to happen to get the bytes
                ;; to the parent, they still need to be translated
                ;; back into byte arrays so they can be encrypted.
                ;; Pooled buffers might make sense, except that
                ;; we're starting from a byte array. So it would
                ;; be silly to copy it.
                buf (Unpooled/wrappedBuffer actual)]
            ;; The writer index indicates the space that's
            ;; available for reading.
            ;; Needing to do this feels wrong.
            ;; Honestly, I'm relying on functionality
            ;; that doesn't seem to be quite documented.
            ;; It almost seems as though I really should be
            ;; setting up a new [pooled] buffer and reading
            ;; array-o-bytes into it instead.
            ;; Doing a memcpy also seems a lot more wasteful.
            (.writerIndex buf buf-size)
            (log/debug prelog
                       (str buf-size
                            "-byte Block to add"))
            (build-individual-block buf)))]
    ;; The main point to logging this is to correlate the
    ;; incoming byte-array with the outgoing ByteBuf identifiers
    (log/debug prelog (str "Prepping thunk for "
                           array-o-bytes
                           " baked into block description:\n"
                           block))
    (fn [{{:keys [::specs/ackd-addr
                  ::specs/max-block-length
                  ::specs/strm-hwm
                  ::specs/un-sent-blocks]
           :as outgoing} ::specs/outgoing
          :keys [::specs/message-loop-name]
          :as state}]
      (let [nested-prelog (utils/pre-log message-loop-name)
            ;; There's the possibility of using a Nagle
            ;; algorithm later to consolidate smaller blocks,
            ;; so maybe it doesn't make sense to mess with it here.
            block (assoc block ::specs/start-pos strm-hwm)]
        (log/debug nested-prelog
                   (str "Adding new message block built around "
                        repr
                        " to "
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
          ;; Actually, no it doesn't.
          ;; This may be a bug in the reference implementation.
          ;; Or my basic translation.
          ;; End of stream is when the address hits stream-length-limit.
          ;; It seems like it would make more sense to
          ;; a) force-close the child output
          ;; b) wait for ACK
          ;; c) then exit
          ;; So, when ackd-addr gets here (or possibly
          ;; strm-hwm), we're done.
          ;; TODO: Revisit this.
          (throw (AssertionError. "End of stream")))
        (let [result (update state
                             ::specs/outgoing
                             (fn [cur]
                               (log/debug (str nested-prelog
                                               "Updating outgoing\n"
                                               cur
                                               "\nby addinging "
                                               buf-size
                                               " to "
                                               strm-hwm))
                               (let [result
                                     (-> cur
                                         (update ::specs/un-sent-blocks
                                                 conj
                                                 block)
                                         (update ::specs/strm-hwm + buf-size))]
                                 (if eof?
                                   (assoc result
                                          ::specs/send-eof array-o-bytes
                                          ;; This seems redundant, since we're
                                          ;; setting send-eof at the same time.
                                          ;; TODO: Just eliminate this.
                                          ;; Anything that checks for it can
                                          ;; just check for (not= send-eof ::specs/false)
                                          ;; instead.
                                          ::specs/send-eof-processed true)
                                   result))))]
          result)))))

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
  (let [prelog (utils/pre-log message-loop-name)
        callback (build-byte-consumer message-loop-name array-o-bytes)]
    (log/debug prelog
               (str
                "Received "
                (if (bytes? array-o-bytes)
                  (count array-o-bytes)
                  array-o-bytes)
                " bytes(?) from child"
                (if (bytes? array-o-bytes)
                  (str " in " array-o-bytes)
                  "")
                ". Trying to forward them to the main i/o loop"))
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
    (if-not (strm/closed? stream)
      ;; FIXME: Ditch the magic numbers
      (let [blocker (dfrd/deferred)
            submitted (strm/try-put! stream
                                     [::specs/child-> callback blocker]
                                     10000 ::timed-out)]
        (dfrd/on-realized submitted
                          (fn [success]
                            (log/debug
                             (utils/pre-log message-loop-name)
                             (str array-o-bytes
                                  " from child successfully ("
                                  success
                                  ") posted to main i/o loop triggered from\n"
                                  prelog)))
                          (fn [failure]
                            (log/error
                             failure
                             (utils/pre-log message-loop-name)
                             (str "Failed to add bytes "
                                  array-o-bytes
                                  " ("
                                  failure
                                  ") from child to main i/o loop triggered from\n"
                                  prelog))))
        ;; message-test pretty much duplicates this in try-multiple-sends
        ;; TODO: eliminate the duplication
        (loop [n 10]
          (if-not (strm/closed? stream)
            (do
              (log/debug prelog
                         "Waiting for ACK that bytes have been buffered. Attempts left:"
                         n)
              (let [waiting
                    (deref blocker 10000 ::timed-out)]
                (if (= waiting ::timed-out)
                  (do  ;; Timed out
                    (log/warn prelog "Timeout number" (- 7 n) "waiting to buffer bytes from child")
                    (if (< 0 n)
                      (recur (dec n))
                      ::specs/error))
                  (do  ;; Bytes buffered
                    (if (bytes? array-o-bytes)
                      (log/debug prelog
                                 (count array-o-bytes)
                                 "bytes from child processed by main i/o loop")
                      (log/warn prelog "Got some EOF signal:" array-o-bytes))
                    ;; Q: Does returning this really gain me anything?
                    ;; It seems like it would be simpler (for the sake of callers)
                    ;; to just return nil on success, or one of the ::specs/eof-flag
                    ;; set when it's time to stop.
                    ;; I was doing it that way at one point.
                    ;; Q: Why did I switch?
                    array-o-bytes))))
            (log/warn prelog
                      "Destination stream closed waiting to put"
                      array-o-bytes))))
      (do
        (log/warn prelog
                  "Destination stream closed. Discarding message\n"
                  array-o-bytes)
        ;; Q: Is there any way to recover from this?
        ::specs/error))))

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
    (when (keyword? array-o-bytes)
      (log/warn prelog "EOF flag. Closing the PipedInputStream")
      ;; It's tempting to make this a function in the top-level
      ;; message ns, like child-close!
      ;; But then I'd need to manage a circular dependency to
      ;; call it from here.
      ;; I don't like the tight coupling this creates with
      ;; the implementation details, but it
      ;; isn't all *that* bad. It's not like I call this from
      ;; all over the place.
      ;; It's a little tempting to refactor this into its
      ;; own function, but that just seems silly.
      (.close child-out))
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
                  (do
                    (log/warn prelog
                              "EOF signal" eof'?
                              "before we ever heard back from serve")
                    (swap! eof? not))))))
          (while (not @eof?)
            (log/debug prelog "Top of main child-read loop")
            (let [eof'?
                  (process-next-bytes-from-child! message-loop-name
                                                  child-out
                                                  stream
                                                  K/standard-max-block-length)]
              (when-not (bytes? eof'?)
                (when (nil? eof'?)
                  (throw (ex-info "What just happened?"
                                  {::context prelog})))
                (log/warn prelog "EOF signal received:" eof'?)
                (swap! eof? not))))
          (log/warn prelog "Child monitor exiting")
          (catch IOException ex
            ;; TODO: Need to send an EOF signal to main ioloop so
            ;; it can notify the parent (or quit, as the case may be)
            (log/error ex
                       prelog
                       "TODO: Not Implemented. This should only happen when child closes pipe")
            ;; Q: Do I need to forward along...which EOF signal would be appropriate here?
            ;; I haven't seen this happen yet, which seems suspicious.
            (throw (RuntimeException. ex)))
          (catch ExceptionInfo ex
            (log/error ex
                       prelog
                       (utils/pretty (.getData ex))))
          (catch Exception ex
            (log/error ex "Bady unexpected exception")))))))
