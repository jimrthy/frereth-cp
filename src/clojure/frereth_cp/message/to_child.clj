(ns frereth-cp.message.to-child
  "Looks like this may not be needed at all

  Pretty much everything that might have been interesting really
  seems to belong in from-parent.

  Or in the callback that got handed to message as part of its constructor.

  Although there *is* the bit about closing the pipe to the child at
  the bottom of each event loop."
  (:require [clojure.pprint :refer (cl-format)]
            [clojure.spec.alpha :as s]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            ;; TODO: Refactor-rename this to log
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd])
  (:import clojure.lang.ExceptionInfo
           [io.netty.buffer ByteBuf]
           java.io.IOException))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic numbers

(def callback-threshold-warning
  "Warn if calling back to child w/ incoming message takes too long (in milliseconds)"
  20)
(def callback-threshold-error
  "Signal error if calling back to child w/ incoming message takes much too long (in milliseconds)"
  200)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef pop-map-first
        :args (s/cat :hm map?)
        :fn (fn [{:keys [:args :ret]}]
              (let [{:keys [:hm]} args]
                (= (dec (count hm))
                   (count ret))))
        :ret map?)
(defn pop-map-first
  "Really for a sorted-map"
  [associative]
  (dissoc associative (first (keys associative))))

;; The caller needs to verify that the gap-buffer's start
;; is <= strm-hwm.
;; Well, it does, because it can short-circuit a reduce
;; if that's the case.
;; It seems like it would be nice to be able to spec that
;; here for the sake of generative testing.
;; I think I can get away with s/and, though I'll probably
;; be forced to get fancy with the generator
;; TODO: Ask about how.
(s/fdef consolidate-message-block
        :args (s/cat :state ::specs/state
                     :gap-buffer ::specs/gap-buffer)
        :ret ::specs/state)
(defn consolidate-message-block
  "Move the parts of the gap-buffer that are ready to write to child

  Really only meant as a helper refactored out of consolidate-gap-buffer"
  ;; @param message-loop-name: Help us track which is doing what
  ;; @param incoming: Really an accumulator inside a reduce
  ;; @param k-v-pair: Incoming message block. Tuple of (start-stop tuple) => bytes
  ;; @return modified accumulator
  [{{:keys [::specs/->child-buffer
             ::specs/gap-buffer
             ::specs/contiguous-stream-count]
     :as incoming} ::specs/incoming
    :keys [::specs/message-loop-name]
    log-state ::log2/state
    :as state}
   k-v-pair]
  (let [prelog (utils/pre-log message-loop-name)
        [[start stop] ^ByteBuf buf] k-v-pair
        ;; Important note re: the logic that's about to hit:
        ;; start, strm-hwm, and stop are all absolute stream
        ;; addresses.
        ;; If we've received 1 byte, the strm-hwm is at 0.
        ;; If start is 0 or 1, then we might have some overlap.
        ;; As long as stop is somewhere past strm-hwm.
        log-state (log2/debug log-state
                              ::consolidate-message-block
                              (str "Does " start "-" stop " close a hole in "
                                   gap-buffer " after "
                                   contiguous-stream-count
                                   " contiguous bytes?"))]
    ;; For now, this top-level if check is redundant.
    ;; I'd rather be safe and trust the JIT than remove it
    ;; under the assumption that callers will be correct.
    ;; Even though I'm the only caller at the moment, this
    ;; is a detail I don't trust myself to not botch at
    ;; some future time..
    (if (<= start contiguous-stream-count)
      ;; Q: Did a previous message overwrite this message block?
      (if (> stop contiguous-stream-count)
        ;; Consolidate this message block
        (do
          (when (< start contiguous-stream-count)
            (let [bytes-to-skip (- contiguous-stream-count start)
                  log-state (log2/info log-state
                                       ::consolidate-message-block
                                       (str "Skipping "
                                            bytes-to-skip
                                            " previously received bytes in "
                                            buf))]
              (.skipBytes buf bytes-to-skip)
              (let [log-state
                    (log2/debug log-state
                                ::consolidate-message-block
                                (str "Consolidating entry 1/"
                                     (count (::specs/gap-buffer
                                             incoming))))]
                (-> state
                    (update ::specs/incoming
                            (fn [cur]
                              (-> cur
                                  (update ::specs/gap-buffer pop-map-first)
                                  ;; There doesn't seem to be any good reason to hang
                                  ;; onto buf here. It's helpful for debugging,
                                  ;; but I need byte-arrays downstream.
                                  ;; There's an open question about where it makes
                                  ;; sense to copy the bytes over
                                  ;; (and release the buffer)
                                  (update ::specs/->child-buffer conj buf)
                                  ;; Microbenchmarks and common sense indicate that
                                  ;; assoc is significantly faster than update
                                  (assoc ::specs/contiguous-stream-count stop))))
                    (assoc ::log2/state log-state))))))
        (let [log-state
              (log2/debug log-state
                          ::consolidate-message-block
                          "Dropping previously consolidated block")
              to-drop (val (first gap-buffer))
              log-state (when-not keyword? to-drop
                                  (try
                                    (.release to-drop)
                                    log-state
                                    (catch RuntimeException ex
                                      (log2/exception log-state
                                                      ex
                                                      "Failed to release"
                                                      to-drop))))]
          (-> state
              (update-in [::specs/incoming ::specs/gap-buffer] pop-map-first)
              (assoc ::log2/state log-state))))
      ;; Gap starts past the end of the stream.
      (do
        (reduced state)))))

(s/fdef consolidate-gap-buffer
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn consolidate-gap-buffer
  [{{:keys [::specs/gap-buffer]
     :as incoming} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}]
  (when-not gap-buffer
    (throw (ex-info "Missing gap-buffer"
                    {::incoming incoming
                     ::message-loop message-loop-name
                     ::incoming-keys (keys incoming)})))
  (reduce (fn [{{:keys [::specs/contiguous-stream-count]
                 :as incoming} ::specs/incoming
                :as acc}
               buffer-entry]
            {:pre [acc]}
            (assert contiguous-stream-count
                    (str (utils/pre-log message-loop-name)
                         "Missing contiguous-stream-count among: "
                         (keys acc)
                         "\nin:\n"
                         acc
                         "\na"
                         (class acc)))
            (let [[[start stop] buf] buffer-entry]
              ;; Q: Have we [possibly] filled an existing gap?
              (if (<= start contiguous-stream-count)
                (consolidate-message-block acc buffer-entry)
                ;; Start is past the contiguous end.
                ;; That means there's another gap. Move on.
                (reduced acc))))
          ;; TODO: Experiment with using a transient or proteus for this
          state
          gap-buffer))

(s/fdef read-bytes-from-parent!
        :args (s/cat :io-handle ::specs/io-handle
                     :log-state ::log2/state
                     :buffer bytes?)
        :ret (s/keys :req  [::log2/state
                            ::specs/bs-or-eof]))
(defn read-bytes-from-parent!
  "Parent wrote bytes to its outbuffer. Read them."
  [{:keys [::specs/child-in
           ::specs/message-loop-name]
    :as io-handle}
   my-log-state
   #^bytes buffer]
  {:pre [buffer
         child-in]}
  (let [bytes-available (.available child-in)
        max-n (count buffer)]
    (if (< 0 bytes-available)
      ;; TODO: This should happen in a dfrd/future that allows
      ;; us to yield control without actually blocking a thread.
      (let [n (.read child-in buffer 0 (min bytes-available
                                            max-n))
            _ (throw (RuntimeException. "start back here"))
            ;; The problem with getting the parent's clock time
            ;; here is that it makes the pipe stateful, due
            ;; to buffering.
            ;; All the code that I ganked away by writing things
            ;; this way really needs to come back.
            ;; I need to read (e.g.) a 4-byte int for the byte count,
            ;; 8 bytes (or so) for the clock time, and then read
            ;; until I have all the bytes for this message.
            ;; And then recur.
            ;; I *could* just stick this into an atom that's
            ;; available via io-handle.
            ;; That feels like a terrible option, but it may be
            ;; my best bet.
            my-log-state (log2/error my-log-state
                                     ::read-bytes-from-parent!
                                     "Need the sender's lamport clock")]
        (if (<= 0 n)
          ;; Can't just return buffer: we don't
          ;; have a good way to tell the caller
          ;; how many bytes we just received
          ;; Although, since it's a mutable byte-array,
          ;; we could just return that count
          ;; (yuck!)
          (let [holder (byte-array n)
                my-log-state (log2/debug my-log-state
                                         ::read-bytes-from-parent!
                                         (str n
                                              "bytes received from parent"))]
            (b-t/byte-copy! holder 0 n buffer)
            holder)
          {::log2/state my-log-state
           ::specs/bs-or-eof ::specs/normal}))
      (let [my-log-state
            (log2/info my-log-state
                       ::read-bytes-from-parent!
                       "No bytes available for child. Blocking Parent Monitor")]
        ;; Q: Do I really need to work with this "read single byte to unblock
        ;; and then seem how many more are available" nonsense?
        ;; I think I implemented it originally because writers weren't
        ;; calling .flush, so this would buffer until full.
        ;; TODO: Experiment with this and see how well this works using
        ;; the easier approach.
        (let [byte1 (try (.read child-in)
                         (catch IOException ex
                           ::specs/normal))
              bytes-available (.available child-in)]
          (assert bytes-available)
          (let [my-log-state (log2/info my-log-state
                                        ::read-bytes-from-parent!
                                        "Parent Monitor thread unblocked")
                result
                (cond (neg? byte1) (let [my-log-state
                                         (log2/warn my-log-state
                                                    ::read-bytes-from-parent!
                                                    "Parent monitor received EOF")]
                                     ;; The part that writes to our paired Pipe
                                     ;; closed its half.
                                     ;; Do the same for sanitation.
                                     (.close child-in)
                                     {::log2/state my-log-state
                                      ::specs/bs-or-eof ::specs/normal})
                      (keyword? byte1) {::log2/state my-log-state
                                        ::specs/bs-or-eof byte1}
                      (< 0 bytes-available)
                      (let [my-log-state
                            (log2/debug my-log-state
                                        ::read-bytes-from-parent!
                                        "Trying to read"
                                        {::bytes-available bytes-available
                                         ::src child-in
                                         ::dst buffer
                                         ::dst-size (count buffer)})]
                        ;; Have to account for the initial unblocking byte
                        (let [n (.read child-in buffer 0 (min bytes-available
                                                              (dec max-n)))]
                          (if (<= 0 n)
                            (let [holder (byte-array (inc n))
                                  my-log-state (log2/debug my-log-state
                                                           ::read-bytes-from-parent!
                                                           (str
                                                            (inc n)
                                                            "bytes received from parent after initial"
                                                            byte1))]
                              (aset-byte holder 0 (b-t/possibly-2s-complement-8 byte1))
                              (b-t/byte-copy! holder 1 n buffer)
                              {::log2/state my-log-state
                               ::specs/bs-or-eof holder}))))
                      :else (byte-array [byte1]))]
            (when (keyword? result)
              ;; We got this because the connected PipedOutputStream closed.
              (.close child-in))
            {::specs/bs-or-eof result
             ::log2/state my-log-state}))))))

(s/fdef write-bytes-to-child-pipe!
        :args (s/cat :to-child ::specs/to-child
                     :state ::specs/state
                     :buf ::specs/buf)
        :ret ::specs/state)
(defn write-bytes-to-child-pipe!
  "Forward the byte-array inside the buffer"
  [to-child
   {log-state ::log2/state
    :as state}
   ^ByteBuf buf]
  ;; This was really just refactored out of the middle of a reduce call,
  ;; so it's a bit ugly as a stand-alone function.
  (try
    ;; It's tempting to special-case this to avoid the
    ;; copy, if we have a buffer that's backed by a byte-array.
    ;; But that winds up sending along extra data that we don't
    ;; want, like the header and pieces that we should have
    ;; skipped due to gap buffering
    (let [bs (byte-array (.readableBytes buf))
          n (count bs)]
      (.readBytes buf bs)
      (let [log-state (log2/info log-state
                                 ::write-bytes-to-child-pipe!
                                 (str "Signalling child's input loop with"
                                      n
                                      "bytes"))
            log-state
            ;; This wall of comments and the associated
            ;; timing check aren't exactly rotten, but the actual
            ;; callback that provokes them has moved into its
            ;; own personal ioloop.
            ;; TODO: Synchronize these.

            ;; Problems in the provided callback are
            ;; very different than problems at this level.
            ;; The former should probably fail immediately.
            ;; The latter should probably fail even more
            ;; catastrophically, and be even more obvious.

            ;; Problems in the client code using this library
            ;; are bad, and I should help the devs who wrote
            ;; that code find their bugs. At the same time, there
            ;; could very well be multiple clients using this
            ;; library at the same time. One misbehaving
            ;; client shouldn't cause problems for the rest.

            ;; The flip side of this is that problems *here*
            ;; indicate a bug that affects everyone using the
            ;; library. The sooner those can be nailed down,
            ;; the happier it will be for everyone.
            (try
              ;; TODO: Switch back to
              ;; using milliseconds here because it's supposedly
              ;; *much* faster than nanoTime, and this resolution
              ;; seems plenty granular
              (let [start-time (System/nanoTime)]
                ;; There's a major difference between this and
                ;; the equivalent in ->parent:
                ;; We don't care if that succeeds.
                ;; Half the point to buffering everything
                ;; in this "package" is so we can resend failures.
                ;; At this point, we've already adjusted the
                ;; buffer states and sent the ACK back to the
                ;; other side. If this fails, things have broken
                ;; badly.
                ;; Actually, that points to a fairly ugly flaw
                ;; in this implementation.
                ;; TODO: Rearrange the logic. This part needs to
                ;; succeed before the rest of those things happen.
                (.write to-child bs 0 (count bs))
                (let [end-time (System/nanoTime)
                      delta (- end-time start-time)
                      msg (cl-format nil "Triggering child took ~:d ns" delta)]
                  (let [log-state
                        (if (< (* 1000000 callback-threshold-warning) delta)
                          (if (< (* 1000000 callback-threshold-error) delta)
                            (log2/error log-state
                                        ::write-bytes-to-child-pipe!
                                        msg)
                            (log2/warn log-state
                                       ::write-bytes-to-child-pipe!
                                       msg))
                          (log2/debug log-state
                                      ::write-bytes-to-child-pipe!
                                      msg))])))
              (catch RuntimeException ex
                ;; It's very tempting to just re-raise this exception,
                ;; especially if I'm inside an agent.
                ;; For now, just log and swallow it.
                (log2/exception log-state
                                ex
                                ::write-bytes-to-child-pipe!
                                "Failure in child callback.")))
            ;; And drop the consolidated blocks
            log-state (log2/debug log-state
                                  ::write-bytes-to-child-pipe!
                                  "Dropping block we just finished sending to child")]
        (.release buf)
        (-> state
            (update-in
             ;; Yes, this is already a vector
             ;; Q: Could I save any time by using a PersistentQueue
             ;; instead?
             [::specs/incoming ::specs/->child-buffer]
             (comp vec rest))
            ;; Actually, if this tracks the bytes that were
            ;; really and truly sent to the child, this shouldn't
            ;; update until that callback returns inside that child's
            ;; private ioloop.
            ;; That gets quite a bit more finicky.
            ;; TODO: Consider my options.
            (update-in [::specs/incoming ::specs/receive-written] + n)
            (assoc ::log2/state log-state))))
    (catch RuntimeException ex
      ;; Reference implementation specifically copes with
      ;; EINTR, EWOULDBLOCK, and EAGAIN.
      ;; Any other failure means just closing the child pipe.
      ;; This is the reason that ->child-buffer has to be a
      ;; seq.
      ;; It's very tempting to just combine the arrays and
      ;; send them all as a single ByteBuf.
      ;; But that tightly couples children to this implementation
      ;; detail.
      ;; It's more tempting to merge the byte arrays into a
      ;; single vector of bytes, but the performance implications
      ;; of that don't seem worth imposing.
      (reduced (update state
                       ::log2/state
                       log2/exception
                       ex
                       ::write-bytes-to-child-pipe!
                       "Failed to forward message to child")))))

(s/fdef possibly-close-pipe!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state
                     :log-state ::log2/state)
        :ret ::specs/state)
(defn possibly-close-pipe!
  "Maybe signal child that it won't receive anything else"
  [{:keys [::specs/to-child
           ::specs/to-child-done?]
    :as io-handle}
   {{:keys [::specs/contiguous-stream-count
            ::specs/receive-eof
            ::specs/receive-total-bytes
            ::specs/receive-written]
     :as incoming} ::specs/incoming
    log-state ::log2/state
    :as state}]
  (let [log-state
        (log2/debug log-state
                    ::possibly-close-pipe!
                    "Process EOF?"
                    incoming)]
    (if (not= ::specs/false receive-eof)
      (if (= receive-written receive-total-bytes)
        (let [log-state
              (log2/info log-state
                         ::possibly-close-pipe!
                         "Have received everything other side will send")
              log-state (if-not to-child
                          (log2/error log-state
                                      ::possibly-close-pipe!
                                      "Missing to-child, so we can't close it")
                          log-state)
              log-state (try
                          (deliver to-child-done? true)
                          (.close to-child)
                          log-state
                          (catch RuntimeException ex
                            (log2/exception log-state
                                            ex
                                            ::possibly-close-pipe!
                                            "Trying to close to-child failed")))
              log-state (log2/warn log-state
                                   ::possibly-close-pipe!
                                   "EOF flag received."
                                   (select-keys incoming
                                                [::specs/contiguous-stream-count
                                                 ::specs/receive-eof
                                                 ::specs/receive-total-bytes
                                                 ::specs/receive-written]))]
          (assoc state
                 ::log2/state log-state)))
      state)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef build-gap-buffer
        :ret ::specs/gap-buffer)
(defn build-gap-buffer
  []
  (sorted-map))

(s/fdef start-parent-monitor!
        :args (s/cat :io-handle ::specs/io-handler
                     :parent-log ::log2/state
                     :callback (s/fspec :args (s/cat :log-state ::log2/state
                                                     :message ::specs/bs-or-eof)
                                        :ret ::log2/state))
        :ret ::specs/child-input-loop)
(defn start-parent-monitor!
  "This is probably a reasonable default for many/most use cases"
  ;; I *do* want to provide the option to write your own, though.
  ;; Maybe I should add an optional parameter: if you don't provide
  ;; this, it will default to calling this.
  [{:keys [::log2/logger
           ::specs/message-loop-name
           ::specs/child-in]
    :as io-handle}
   parent-log
   cb]
  (dfrd/future
    (let [prelog (utils/pre-log message-loop-name)
          my-logs (log2/init (::log2/lamport parent-log))
          buffer (byte-array K/standard-max-block-length)
          my-logs (log2/info my-logs
                             ::parent-monitor-loop
                             "Starting the loop watching for bytes the parent has sent toward the child")]
      (try
        (loop [my-logs my-logs]
          (let [{:keys [::log2/state
                        ::specs/bs-or-eof]} (read-bytes-from-parent! io-handle my-logs buffer)
                start-time (System/nanoTime)
                my-logs (log2/debug my-logs ::parent-monitor-loop "Triggering child callback")]
            (try
              (let [my-logs
                    ;; The rest of this function is really just support and error
                    ;; handling for the actual point, right here
                    (-> my-logs
                        (cb bs-or-eof)
                        (log2/error ::parent-monitor-loop
                                    "FIXME: Need to get this synced back to main ioloop"))]
                (throw (RuntimeException. "So. What should happen to updated-log-state?")))
              (catch ExceptionInfo ex
                (let [my-logs
                      (log2/exception my-logs
                                      ex
                                      ::parent-monitor-loop
                                      (str "At least we can log something interesting with this")
                                      (.getData ex))]
                  (log2/flush-logs! logger my-logs))
                (assert (not ex) "Child callback failed"))
              (catch Exception ex
                (let [my-logs (log2/error my-logs
                                          ex
                                          ::parent-monitor-loop
                                          "This is not acceptable behavior at all")]
                  (log2/flush-logs! logger my-logs))
                (assert (not ex) (str prelog
                                      "Child callback failed"))))
            (let [end-time (System/nanoTime)
                  msg (cl-format nil
                                 "Child callback took ~:d nanoseconds"
                                 (- end-time start-time))
                  my-logs (log2/debug my-logs ::parent-monitor-loop msg)
                  my-logs (log2/flush-logs! logger my-logs)]
              (when (bytes? bs-or-eof)
                (recur my-logs)))))
        (let [my-logs
              (log2/warn my-logs ::parent-monitor-loop "exited")]
          (log2/flush-logs! logger my-logs))
        (catch IOException ex
          (let [my-logs
                (log2/warn my-logs
                           ::parent-monitor-loop
                           "This should happen because the stream from parent closed"
                           {::problem ex})]
            (log2/flush-logs! logger my-logs)))
        (catch Exception ex
          (let [my-logs
                (log2/exception my-logs
                                ex
                                ::parent-monitor-loop
                                "Parent Monitor failed unexpectedly")]))))))

(s/fdef forward!
        :args (s/cat :io-handle ::specs/io-handle
                     :primed ::specs/state)
  :ret ::specs/state)
(defn forward!
  "Try sending data to child:"
  ;; lines 615-632
  [{:keys [::specs/from-parent
           ::specs/to-child]
    :as io-handle}
   {:keys [::specs/message-loop-name]
    original-incoming ::specs/incoming
    :as state}]
  (let [{{:keys [::specs/receive-eof]
          :as consolidated-incoming} ::specs/incoming
         log-state ::log2/state
         :as consolidated} (consolidate-gap-buffer state)
        ->child-buffer (::specs/->child-buffer consolidated-incoming)
        block-count (count ->child-buffer)
        log-state (log2/debug log-state
                              ::forward!
                              "Consolidated block(s) ready to go to child."
                              {::block-count block-count
                               ::specs/receive-eof receive-eof})]
    (if (< 0 block-count)
      (let [result (reduce (partial write-bytes-to-child-pipe!
                                    to-child)
                           (assoc consolidated ::log2/state log-state)
                           ->child-buffer)]
        (possibly-close-pipe! io-handle result))
      (let [result (update consolidated
                           ::log2/state
                           log2/warn
                           ::forward!
                           "0 bytes to forward to child")]
        (possibly-close-pipe! io-handle result)))
    ;; 610-614: counters/looping
    ;; (doesn't really apply to this implementation)
    ))
