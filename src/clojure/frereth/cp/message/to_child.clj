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
            [frereth-cp.util :as utils]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import clojure.lang.ExceptionInfo
           [io.netty.buffer ByteBuf]
           java.io.IOException))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::callback
  (s/fspec :args (s/cat :log-state ::weald/state
                        :message ::specs/bs-or-eof)
           :ret ::weald/state))

(s/def ::result-writer dfrd/deferrable?)

(s/def ::cb-trigger (s/keys :req [::result-writer
                                  ::weald/state
                                  ::specs/bs-or-eof]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic numbers

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
  ;; It seems as though pop should do this, but a map
  ;; does not implement IPersistentStack.
  "Pop first entry from a map. Only makes sense if sorted"
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
    log-state ::weald/state
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
        log-state (log/debug log-state
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
        (let [log-state
              (if (< start contiguous-stream-count)
                (let [bytes-to-skip (- contiguous-stream-count start)
                      log-state (log/info log-state
                                          ::consolidate-message-block
                                          (str "Skipping "
                                               bytes-to-skip
                                               " previously received bytes in "
                                               buf))]
                  (.skipBytes buf bytes-to-skip)
                  log-state)
                log-state)
              log-state (log/debug log-state
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
              (assoc ::weald/state log-state)))
        (let [log-state
              (log/debug log-state
                         ::consolidate-message-block
                         "Dropping previously consolidated block")
              to-drop (val (first gap-buffer))
              log-state (if-not (keyword? to-drop)
                          (try
                            (.release to-drop)
                            log-state
                            (catch RuntimeException ex
                              (log/exception log-state
                                             ex
                                             "Failed to release"
                                             to-drop)))
                          log-state)]
          (-> state
              (update-in [::specs/incoming ::specs/gap-buffer] pop-map-first)
              (assoc ::weald/state log-state))))
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

(s/fdef trigger-from-parent!
        :args (s/cat :io-handle ::specs/io-handle
                     :buffer bytes?
                     :cb ::callback
                     :my-logs ::weald/entries
                     :trigger (s/keys :req [::weald/lamport]))
        :ret any?)
(defn trigger-from-parent!
  "Stream handler for coping with bytes sent by parent"
  [{:keys [::weald/logger
           ::specs/message-loop-name]
    :as io-handle}
   buffer
   cb
   {:keys [::result-writer
           ::specs/bs-or-eof]
    my-logs ::weald/state
    :as trigger}]
  (let [my-logs
        (try
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
          (let [start-time (System/currentTimeMillis)
                my-logs
                (try
                  (as-> (log/debug my-logs
                                   ::parent-monitor-loop
                                   "Triggering child callback")
                      my-logs
                    (try
                      ;; The rest of this function is really just support and error
                      ;; handling for the actual point, right here
                      ;; TODO: Come up with something meaningful for the return value
                      ;; and handle any problems gracefully.
                      (cb bs-or-eof)
                       my-logs
                      (catch ExceptionInfo ex
                        (log/exception my-logs
                                       ex
                                       "Failed"
                                       (.getData ex)))
                      (catch Exception ex
                        (log/exception my-logs
                                       ex
                                       ::parent-monitor-loop
                                       "Low-level failure"))))
                  (catch ExceptionInfo ex
                    (log/exception my-logs
                                   ex
                                   ::parent-monitor-loop
                                   (str "At least we can log something interesting with this")
                                   (.getData ex))
                    (log/flush-logs! logger my-logs)
                    (assert (not ex) "Child callback failed"))
                  (catch Exception ex
                    (let [my-logs (log/error my-logs
                                             ex
                                             ::parent-monitor-loop
                                             "This is not acceptable behavior at all")
                          prelog (utils/pre-log message-loop-name)]
                      (log/flush-logs! logger my-logs)
                      (assert (not ex) (str prelog
                                            "Child callback failed")))))]
            (let [end-time (System/currentTimeMillis)
                  msg (cl-format nil
                                 "Child callback took ~:d millisecond(s)"
                                 (- end-time start-time))]
              (log/debug my-logs ::parent-monitor-loop msg)))
          (catch Exception ex
            ;; This really shouldn't be possible
            (log/exception my-logs
                           ex
                           ::parent-monitor-loop
                           "Redundant error handler")))]
    (when result-writer
      (deliver result-writer my-logs))))

(s/fdef write-bytes-to-child-stream!
        :args (s/cat :to-child ::specs/to-child
                     :state ::specs/state
                     :buf ::specs/buf)
        :ret ::specs/state)
(defn write-bytes-to-child-stream!
  "Forward the byte-array inside the buffer"
  [parent-trigger
   {log-state ::weald/state
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
      (let [{:keys [::weald/lamport]
             :as log-state} (log/info log-state
                                      ::write-bytes-to-child-stream!
                                      (str "Signalling child's input loop with "
                                           n
                                           " bytes"))
            log-state
            (try
              (let [start-time (System/currentTimeMillis)]
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
                (let [succeeded (dfrd/deferred)
                      ;; It would be nice to set up a deferred chain
                      ;; so this doesn't block a thread.
                      ;; TODO: Think about it.
                      ;; Q: Is this worth using an executor?
                      ;; (and how tough to reach one?)
                      triggered @(strm/put! parent-trigger
                                            {::result-writer succeeded
                                             ::weald/state log-state
                                             ::specs/bs-or-eof bs})
                      log-state @succeeded
                      end-time (System/currentTimeMillis)
                      delta (- end-time start-time)
                      msg (cl-format nil "Triggering child took ~:d ms" delta)]
                  (if (< (* 1000000 callback-threshold-warning) delta)
                    (if (< (* 1000000 callback-threshold-error) delta)
                      (log/error log-state
                                 ::write-bytes-to-child-stream!
                                 msg)
                      (log/warn log-state
                                ::write-bytes-to-child-stream!
                                msg))
                    (log/debug log-state
                               ::write-bytes-to-child-stream!
                               msg))))
              (catch RuntimeException ex
                ;; It's very tempting to just re-raise this exception,
                ;; especially if I'm inside an agent.
                ;; For now, just log and swallow it.
                (log/exception log-state
                               ex
                               ::write-bytes-to-child-stream!
                               "Failure in child callback.")))
            ;; And drop the consolidated blocks
            log-state (log/debug log-state
                                 ::write-bytes-to-child-stream!
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
            (assoc ::weald/state log-state))))
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
                       ::weald/state
                       log/exception
                       ex
                       ::write-bytes-to-child-stream!
                       "Failed to forward message to child")))))

(defn close-parent-input!
  [{:keys [::specs/from-parent-trigger
           ::specs/to-child-done?]
    :as io-handle}]
  (deliver to-child-done? true)
  (strm/close! from-parent-trigger))

(s/fdef possibly-close-stream!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state
                     :log-state ::weald/state)
        :ret ::specs/state)
(defn possibly-close-stream!
  "Maybe signal child that it won't receive anything else"
  [{:keys [::specs/from-parent-trigger]
    :as io-handle}
   {{:keys [::specs/contiguous-stream-count
            ::specs/receive-eof
            ::specs/receive-total-bytes
            ::specs/receive-written]
     :as incoming} ::specs/incoming
    log-state ::weald/state
    :as state}]
  (let [log-state
        (log/debug log-state
                   ::possibly-close-stream!
                   "Process EOF?"
                   incoming)]
    (if (not= ::specs/false receive-eof)
      (if (= receive-written receive-total-bytes)
        (let [log-state
              (log/info log-state
                         ::possibly-close-stream!
                         "Have received everything other side will send")
              log-state (if-not from-parent-trigger
                          (log/error log-state
                                     ::possibly-close-stream!
                                     "Missing from-parent-trigger, so we can't close it")
                          log-state)
              log-state (try
                          ;; This actual point is easy to miss in the middle of all
                          ;; the logging/error handling.
                          (close-parent-input! io-handle)
                          log-state
                          (catch RuntimeException ex
                            (log/exception log-state
                                           ex
                                           ::possibly-close-stream!
                                           "Trying to close to-child failed")))
              log-state (log/warn log-state
                                  ::possibly-close-stream!
                                  "EOF flag received."
                                  (select-keys incoming
                                               [::specs/contiguous-stream-count
                                                ::specs/receive-eof
                                                ::specs/receive-total-bytes
                                                ::specs/receive-written]))]
          (assoc state
                 ::weald/state log-state)))
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
                     :parent-log ::weald/state
                     :callback ::callback)
        :ret ::specs/child-input-loop)
(defn start-parent-monitor!
  "This is probably a reasonable default for many/most use cases"
  ;; I *do* want to provide the option to write your own, though.
  ;; Maybe I should add an optional parameter during startup:
  ;; if you don't provide
  ;; that, it will default to calling this.
  [{:keys [::weald/logger
           ::specs/child-in
           ::specs/message-loop-name]
    trigger-stream ::specs/from-parent-trigger
    :as io-handle}
   parent-log
   ;; FIXME: Having multiple manifold streams running consume
   ;; here seems inefficient.
   ;; Though, honestly, if they're running on an (their
   ;; own?) executor pool, that might not be awful.
   ;; It seems like it would be much better to have
   ;; a handler registrar which maps the key associated
   ;; with each parent's peer to the appropriate child.
   ;; Except that we could have multiple connected peers
   ;; with the same keys. And even the same IP address.
   ;; And that would add another layer of complexity
   ;; that I don't know I need.
   ;; For that matter, I don't have any evidence that
   ;; it would improve anything.
   cb]
  (let [[parent-log my-logs] (log/fork parent-log ::parent-monitor)
        buffer (byte-array K/standard-max-block-length)
        my-logs (log/info my-logs
                          ::loop
                          "Starting the loop watching for bytes the parent has sent toward the child")
        my-logs (log/flush-logs! logger my-logs)
        result (strm/consume (partial trigger-from-parent!
                                      (assoc io-handle ::weald/state my-logs)
                                      buffer
                                      cb)
                             trigger-stream)
        finished (dfrd/deferred)]
    (-> result
        (dfrd/chain (fn [success]
                      (let [my-logs (log/warn my-logs
                                              ::loop
                                              "parent-monitor source exhausted")]
                        ;; Writing to the from-parent-trigger stream
                        ;; here seems like the obvious thing to do.
                        ;; But closing that was the signal that
                        ;; led us here.
                        ;; So just call the callback's caller directly.
                        (trigger-from-parent! io-handle
                                              buffer
                                              cb
                                              {::result-writer finished
                                               ::weald/state my-logs
                                               ::specs/bs-or-eof ::specs/normal})))
                    (fn [_]
                      ;; This is really just waiting for logs from
                      ;; trigger-from-parent!
                      ;; Which is an obnoxious way to handle this.
                      finished)
                    (fn [logs]
                      ;; Really want to synchronize these logs.
                      ;; There's no good way to do that.
                      ;; Worse: time stamps get lost, and there's no
                      ;; good way to coordinate back to the parent.
                      ;; TODO: This needs more hammock-time
                      (log/flush-logs! logger logs)
                      (log/flush-logs! logger my-logs)))
        (dfrd/catch (fn [ex]
                      (log/exception my-logs
                                     ex
                                     ::parent-monitor-loop
                                     "Error escaped")))
        (dfrd/finally (fn [logs]
                        (log/flush-logs! logger logs))))
    result))

(s/fdef forward!
        :args (s/cat :io-handle ::specs/io-handle
                     :primed ::specs/state)
  :ret ::specs/state)
(defn forward!
  "Trigger the parent-monitor 'loop'"
  ;; lines 615-632
  [{:keys [::specs/from-parent]
    parent-trigger ::specs/from-parent-trigger
    :as io-handle}
   {:keys [::specs/message-loop-name]
    original-incoming ::specs/incoming
    log-state ::weald/state
    :as state}]
  {:pre [log-state]}
  (let [log-state (log/debug log-state
                             ::forward!
                             "Top of forward!")
        {{:keys [::specs/receive-eof]
          :as consolidated-incoming} ::specs/incoming
         log-state ::weald/state
         :as consolidated} (consolidate-gap-buffer (assoc state ::weald/state log-state))
        ->child-buffer (::specs/->child-buffer consolidated-incoming)
        block-count (count ->child-buffer)
        log-state (try (log/debug log-state
                                  ::forward!
                                  "Consolidated block(s) ready to go to child."
                                  {::block-count block-count
                                   ::specs/receive-eof receive-eof})
                       (catch Exception ex
                         ;; This should probably be fatal, with
                         ;; gobs more details.
                         (println "Log Problem:" ex
                                  "\nTrying to log to\n"
                                  log-state)
                         log-state))
        consolidated (assoc consolidated ::weald/state log-state)]
    (if (< 0 block-count)
      (let [preliminary (reduce (partial write-bytes-to-child-stream!
                                         parent-trigger)
                                consolidated
                                ->child-buffer)]
        (possibly-close-stream! io-handle preliminary))
      (let [result (update consolidated
                           ::weald/state
                           log/warn
                           ::forward!
                           "0 bytes to forward to child")]
        (possibly-close-stream! io-handle result)))
    ;; 610-614: counters/looping
    ;; (doesn't really apply to this implementation)
    ))
