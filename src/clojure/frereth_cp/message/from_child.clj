(ns frereth-cp.message.from-child
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K-shared]
            [frereth-cp.shared.logging :as log2]
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
        :ret ::specs/bs-or-eof)
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
         ;; Q: Could I use something like Reactive, or even Java Streams,
         ;; to eliminate all the logic involved in managing this?
         (let [next-prefix (.read child-out)]
           ;; My echo test is never returning from that.
           ;; Which, really, should mean that the PipedInputStream never gets closed.
           ;; Aside from the fact that the child is never echoing any bytes
           ;; back.
           ;; Actually, it never seems to receive any bytes.
           (log/debug prelog (str "Read a byte from child ("
                                  next-prefix
                                  "). Q: Are there more?"))
           ;; That returns an unsigned byte.
           ;; Or -1 for EOF
           (if (not= next-prefix -1)
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
                 (byte-array prefix)))
             (if (< 0 prefix-gap)  ;; EOF
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
                 ::specs/normal))))
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
                     :bs-or-eof ::specs/bs-or-eof)
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
   bs-or-eof]
  (let [prelog (utils/pre-log message-loop-name)
        eof? (keyword? bs-or-eof)
        buf-size (if eof?
                   0
                   (count bs-or-eof))
        repr (if eof?
               (str "EOF: " bs-or-eof)
               (str buf-size "-byte array"))
        block
        (if (keyword? bs-or-eof)
          (assoc
           (build-individual-block (Unpooled/wrappedBuffer (byte-array 0)))
           ::specs/send-eof bs-or-eof)
          ;; Note that back-pressure no longer gets applied if we
          ;; already have ~124K pending because caller started
          ;; dropping packets.
          ;; (It doesn't seem like it should matter, except
          ;; as an upstream signal that there's some kind of
          ;; problem)
          (let [^bytes actual bs-or-eof
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
                           bs-or-eof
                           " baked into block description:\n"
                           block))
    ;; TODO: Refactor this into a top-level function
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
                                   ;; It's tempting to update :sent-eof-processed
                                   ;; here also.
                                   ;; That temptation is a mistake.
                                   ;; The reference implementation:
                                   ;; 1. Sets up FDs for polling at the top of its main loop
                                   ;; 2. Tries to pull data from the child
                                   ;;    If child closed pipe, set send-eof
                                   ;; [We're currently here]
                                   ;; 3. Skips everything else that's sending-related
                                   ;;    *if* both send-eof and send-eof-processed
                                   ;; 4. Sets send-eof-processed
                                   ;; just before
                                   ;; 5. Actually doing the send.
                                   ;; send-eof-processed has caused me enough
                                   ;; pain that I've eliminated it.
                                   (assoc result
                                          ::specs/send-eof bs-or-eof)
                                   result))))]
          result)))))

(s/fdef try-multiple-sends
        :args (s/cat :stream ::specs/stream
                     :bs-or-eof ::specs/bs-or-eof
                     :blocker dfrd/deferrable?
                     :attempts nat-int?
                     :timeout nat-int?)
        :ret ::specs/bs-or-eof)
(defn try-multiple-sends
  "The parameters are weird because I refactored it out of a lexical closure"
  [stream
   ;; TODO: Refactor-rename this to bs-or-eof
   bs-or-eof
   blocker
   prelog attempts timeout]
  ;; message-test pretty much duplicates this in try-multiple-sends
  ;; TODO: eliminate the duplication
  (loop [n attempts]
    (if-not (strm/closed? stream)
      (do
        (log/debug prelog
                   "Waiting for ACK that bytes have been buffered. Attempts left:"
                   n)
        (let [waiting
              (deref blocker timeout ::timed-out)]
          (if (= waiting ::timed-out)
            (do  ;; Timed out
              (log/warn prelog
                        "Timeout number"
                        (- (inc attempts) n)
                        "waiting to buffer bytes from child")
              (if (< 0 n)
                (recur (dec n))
                ::specs/error))
            (do  ;; Bytes buffered
              (if (bytes? bs-or-eof)
                (log/debug prelog
                           (count bs-or-eof)
                           "bytes from child processed by main i/o loop")
                (log/warn prelog "Got some EOF signal:" bs-or-eof))
              ;; Q: Does returning this really gain me anything?
              ;; It seems like it would be simpler (for the sake of callers)
              ;; to just return nil on success, or one of the ::specs/eof-flag
              ;; set when it's time to stop.
              ;; I was doing it that way at one point.
              ;; Q: Why did I switch?
              bs-or-eof))))
      (do
        (log/warn prelog
                  "Destination stream closed waiting to put"
                  bs-or-eof)
        ::specs/error))))

(s/fdef forward-bytes-from-child!
        :args (s/cat :message-loop-name ::specs/message-loop-name
                     :stream ::specs/stream
                     :bs-or-eof ::specs/bs-or-eof)
        :fn #(= (:ret %) (-> % :args :array-o-bytes))
        :ret (s/or :message bytes?
                   :eof ::specs/eof-flag))
(defn forward-bytes-from-child!
  [message-loop-name
   stream
   bs-or-eof]
  (let [prelog (utils/pre-log message-loop-name)
        callback (build-byte-consumer message-loop-name bs-or-eof)]
    ;; I think it looks as though I have a deadlock here.
    ;; It seems like I need to return from this in order to get
    ;; back to the main ioloop to pull the message that I'm
    ;; queuing.
    ;; Except that it works until I start shutting everything
    ;; down.
    ;; At the end of the handshake test:
    ;; 1. Client sends EOF to server
    ;; 2. Server's child receives that and sends its own EOF packet
    ;; 3. That EOF packet gets to try-multiple-sends
    ;; And then processing stops until the test ends.
    (comment (throw (RuntimeException. "What's going wrong with this?")))
    (log/debug prelog
               (str
                "Received "
                (if (bytes? bs-or-eof)
                  (count bs-or-eof)
                  bs-or-eof)
                " bytes(?) from child"
                (if (bytes? bs-or-eof)
                  (str " in " bs-or-eof)
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
            timeout 10000
            submitted (strm/try-put! stream
                                     [::specs/child-> callback blocker]
                                     timeout ::timed-out)]
        (dfrd/on-realized submitted
                          (fn [success]
                            (log/debug
                             (utils/pre-log message-loop-name)
                             (str bs-or-eof
                                  " from child successfully ("
                                  success
                                  ") posted to main i/o loop triggered from\n"
                                  prelog)))
                          (fn [failure]
                            (log/error
                             failure
                             (utils/pre-log message-loop-name)
                             (str "Failed to add bytes "
                                  bs-or-eof
                                  " ("
                                  failure
                                  ") from child to main i/o loop triggered from\n"
                                  prelog))))
        (try-multiple-sends stream bs-or-eof blocker prelog 10 timeout))
      (do
        (log/warn prelog
                  "Destination stream closed. Discarding message\n"
                  bs-or-eof)
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
        bs-or-eof
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
    (when (keyword? bs-or-eof)
      (log/warn prelog "EOF flag. Closing the PipedInputStream")
      ;; It's a little tempting to refactor this into its
      ;; own function, but that just seems silly.
      (.close child-out))
    (forward-bytes-from-child! message-loop-name
                               stream
                               bs-or-eof)))

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
        ;; The monitor-id seems like it might be useful
        ;; for the caller to know
        ;; TODO: Go ahead and send that back
        :ret ::specs/child-output-loop)
(defn start-child-monitor!
  [{:keys [::specs/message-loop-name]
    {:keys [::specs/client-waiting-on-response]
     :as flow-control} ::specs/flow-control
    log-state ::log2/state
    :as initial-state}
   {:keys [::log2/logger
           ::specs/child-out
           ::specs/stream]
    :as io-handle}]
  {:pre [message-loop-name]}
  ;; TODO: This needs pretty hefty automated tests
  ;; Although the bigger integration-style tests I
  ;; do have probably exercise it well enough.
  (let [;; This really should be based on time-stamp
        ;; (type 1)
        ;; Or maybe a Type 5, based on SHA
        ;; The built-in Type 1, based on MD5, would probably
        ;; work fine...it's not like we're trying to be
        ;; cryptographically secure with this.
        ;; For now, just go with what's easy.
        monitor-id (utils/random-uuid)
        ;; There are really 2 options for handling multiple children
        ;; 1. Each gets its own child-monitor loop
        ;; 2. Each gets its own PipedI/OStream pair.
        ;; Option 1 definitely seems easier/simpler.
        ;; And probably more resource-intensive.
        ;; Start with that approach, but keep an eye on it.
        ;; Then again, having multiple threads processing messages
        ;; in parallel may work better than a single thread trying
        ;; to handle all of them.
        state (update initial-state
                      ::log2/state
                      #(log2/info %
                                  ::start-child-monitor!
                                  "Starting the child-monitor thread"
                                  {::specs/monitor-id monitor-id}))
        state (assoc-in state [::specs/outgoing ::specs/monitor-id] monitor-id)]
    ;; TODO: This probably needs to run on an executor specifically
    ;; dedicated to this sort of thing (probably shared with to-parent)
    (dfrd/future
      (let [prelog (utils/pre-log message-loop-name)
            eof? (atom false)]
        (try
          (let [state
                (loop [state state]
                  (let [state (update state
                                      ::log2/state
                                      #(log2/flush-logs! logger (log2/debug
                                                                 %
                                                                 ::start-child-monitor!
                                                                 "Top of client-waiting-on-initial-response loop")))]
                    (if (not (realized? client-waiting-on-response))
                      (let [msg-or-eof'?
                            ;; TODO: This also needs access to log-state
                            ;; And it needs to return the updated log-state
                            ;; Actually, it should also return a set of
                            ;; side-effects to run
                            (process-next-bytes-from-child! message-loop-name
                                                            child-out
                                                            stream
                                                            K/max-bytes-in-initiate-message)
                            state (update state
                                          ::log2/state
                                          #(log2/flush-logs! logger %))]
                        (log/debug "----------------------------------------\n"
                                   "Received something from child:"
                                   msg-or-eof'?
                                   "\n"
                                   (utils/pretty state))
                        (if (bytes? msg-or-eof'?)
                          (recur state)  ; regular message. Keep going
                          (let [state (update state
                                              ::log2/state
                                              #(log2/warn %
                                                          ::child-monitor-loop
                                                          "EOF signalled before we ever heard back from server"
                                                          {::specs/eof-flag msg-or-eof'?
                                                           ::specs/monitor-id monitor-id}))]
                            (swap! eof? not)
                            state)))
                      state)))
                state (loop [state state]
                        (when (not @eof?)
                          (let [state (update state
                                              ::log2/state
                                              #(log2/debug %
                                                           ::child-monitor-loop
                                                           "Top of main child-read loop"
                                                           {::specs/monitor-id monitor-id}))
                                eof'?
                                (process-next-bytes-from-child! message-loop-name
                                                                child-out
                                                                stream
                                                                K/standard-max-block-length)
                                state (update state
                                              ::log2/state
                                              #(log2/flush-logs! logger %))]
                            (if (bytes? eof'?)
                              (recur state)
                              (let [state (update state
                                                  ::log2/state
                                                  #(log2/warn %
                                                              ::child-monitor-loop
                                                              "EOF signal received"
                                                              {::specs/eof-flag eof'?
                                                               ::specs/monitor-id monitor-id}))]
                                (when (nil? eof'?)
                                  (throw (ex-info "What just happened?"
                                                  {::specs/monitor-id monitor-id})))
                                (swap! eof? not)
                                state)))))
                state (update state
                              ::log2/state
                              #(log2/warn %
                                          ::child-monitor-loop
                                          "Child monitor exiting"
                                          {::specs/monitor-id monitor-id}))]
            (log2/flush-logs! logger state))
          (catch IOException ex
            ;; TODO: Need to send an EOF signal to main ioloop so
            ;; it can notify the parent (or quit, as the case may be)
            (log2/flush-logs! logger
                              (log2/exception (::log2/state state)
                                              ex
                                              ::start-child-monitor!
                                              "TODO: Not Implemented. This should only happen when child closes pipe"))
            ;; Q: Do I need to forward along...which EOF signal would be appropriate here?
            (throw (RuntimeException. ex "Not Implemented")))
          (catch ExceptionInfo ex
            ;; Problems with this approach:
            ;; 1. Any logs queued before the exception was thrown got lost
            ;;    (and they're the ones we *really* care about)
            ;; 2. The clock's going to be totally out of whack
            (log2/flush-logs! logger
                              (log2/exception (::log2/state state)
                                              ex
                                              ::start-child-monitor!
                                              ""
                                              (.getData ex))))
          (catch Exception ex
            (log2/flush-logs! logger
                              (log2/exception (::log2/state state)
                                              ex
                                              ::start-child-monitor!
                                              "Badly unexpected exception"))))))))
