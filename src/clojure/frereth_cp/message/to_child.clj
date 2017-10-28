(ns frereth-cp.message.to-child
  "Looks like this may not be needed at all

  Pretty much everything that might have been interesting really
  seems to belong in from-parent.

  Or in the callback that got handed to message as part of its constructor.

  Although there *is* the bit about closing the pipe to the child at
  the bottom of each event loop."
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.util :as utils])
  (:import [io.netty.buffer ByteBuf]))

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
        :args (s/cat :incoming ::specs/incoming
                     :gap-buffer ::specs/gap-buffer)
        :ret ::specs/incoming)
(defn consolidate-message-block
  "Move the parts of the gap-buffer that are ready to write to child

  Really only meant as a helper refactored out of consolidate-gap-buffer"
  ;; @param message-loop-name: Help us track which is doing what
  ;; @param incoming: Really an accumulator inside a reduce
  ;; @param k-v-pair: Incoming message block. Tuple of (start-stop tuple) => bytes
  ;; @return modified accumulator
  [message-loop-name
   {:keys [::specs/->child-buffer
           ::specs/gap-buffer
           ::specs/contiguous-stream-count]
    :as incoming}
   k-v-pair]
  (let [[[start stop] ^ByteBuf buf] k-v-pair]
    ;; Important note re: the logic that's about to hit:
    ;; start, strm-hwm, and stop are all absolute stream
    ;; addresses.
    ;; If we've received 1 byte, the strm-hwm is at 0.
    ;; If start is 0 or 1, then we might have some overlap.
    ;; As long as stop is somewhere past strm-hwm.
    (log/debug (utils/pre-log message-loop-name)
               (str "Does " start "-" stop " close a hole in "
                    gap-buffer " after "
                    contiguous-stream-count
                    " contiguous bytes?"))
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
            (let [bytes-to-skip (- contiguous-stream-count start)]
              (log/info (utils/pre-log message-loop-name)
                        "Skipping"
                        bytes-to-skip
                        "previously received bytes in"
                        buf)
              (.skipBytes buf bytes-to-skip)))
          (log/debug (utils/pre-log message-loop-name)
                     (str "Consolidating entry 1/"
                          (count (::specs/gap-buffer
                                  incoming))))
          (-> incoming
              (update ::specs/gap-buffer pop-map-first)
              ;; There doesn't seem to be any good reason to hang
              ;; onto buf here. It's helpful for debugging,
              ;; but I need byte-arrays downstream.
              ;; There's an open question about where it makes
              ;; sense to copy the bytes over
              ;; (and release the buffer)
              (update ::specs/->child-buffer conj buf)
              ;; Microbenchmarks indicate that assoc
              ;; is significantly faster than update
              (assoc ::specs/contiguous-stream-count stop)))
        (do
          (log/debug (utils/pre-log message-loop-name)
                     "Dropping previously consolidated block")
          (let [to-drop (val (first gap-buffer))]
            (try
              (.release to-drop)
              (catch RuntimeException ex
                (log/error (utils/pre-log message-loop-name)
                           ex
                           "Failed to release"
                           to-drop))))
          (update incoming ::specs/gap-buffer pop-map-first)))
      ;; Gap starts past the end of the stream.
      (do
        (reduced incoming)))))

(s/fdef consolidate-gap-buffer
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn consolidate-gap-buffer
  ;; I'm dubious that this belongs in here.
  ;; But this namespace is looking very skimpy compared to from-parent,
  ;; which seems like a better choice.
  [{{:keys [::specs/gap-buffer]
     :as incoming} ::specs/incoming
    :keys [::specs/message-loop-name]
    :as state}]
  (when-not gap-buffer
    (throw (ex-info "Missing gap-buffer"
                    {::incoming incoming
                     ::message-loop message-loop-name
                     ::incoming-keys (keys incoming)})))
  (assoc state
         ::specs/incoming
         (reduce (fn [{:keys [::specs/contiguous-stream-count]
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
                       (consolidate-message-block message-loop-name acc buffer-entry)
                       ;; Start is past the contiguous end.
                       ;; That means there's another gap. Move on.
                       (reduced acc))))
                 ;; TODO: Experiment with using a transient or proteus for this
                 incoming
                 gap-buffer)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef build-gap-buffer
        :ret ::specs/gap-buffer)
(defn build-gap-buffer
  []
  (sorted-map))

(s/fdef forward!
        :args (s/cat :->child ::specs/->child
                     :primed ::specs/state)
  :ret ::specs/state)
(defn forward!
  "Try sending data to child:"
  ;; lines 615-632
  [->child
   {:keys [::specs/incoming
           ::specs/message-loop-name]
    :as state}]
  (let [pre-log (utils/pre-log message-loop-name)]
    ;; Major piece of the puzzle that I'm currently missing:
    ;; line 617 will generally update receive-written.
    ;; TODO: expand it to include the pieces I haven't translated yet
    ;; (such as sending some signal, like a nil, to indicate that
    ;; we've hit EOF).
    ;; Q: Is receive-written still a thing?
    ;; (How does it compare w/ HWM?)
    (log/warn pre-log "TODO: Should update receive-written sometime soon")
    (let [consolidated (consolidate-gap-buffer state)
          ->child-buffer (get-in consolidated [::specs/incoming ::specs/->child-buffer])
          block-count (count ->child-buffer)]
      (log/debug pre-log
                 "Have"
                 block-count
                 "consolidated blocks ready to go to child")
      (if (< 0 block-count)
        ;; Q: If I have a ton of messages to deliver, do I really want to call the child
        ;; repeatedly right here and now?
        ;; The reference implementation actually puts the bytes that are ready
        ;; to write into its circular buffer and tries to write as many as possible
        ;; (up to the end of the circular buffer) all at once. It flags the
        ;; written bytes as invalid and moves on.
        ;; In that world, anything that didn't get written this time will happen
        ;; on the next loop iteration.
        ;; Which looks like it might not happen for another minute.
        (reduce (fn [state' ^ByteBuf buf]
                  ;; Forward the byte-array inside the buffer
                  (try
                    ;; It's tempting to special-case this to avoid the
                    ;; copy, if we have a buffer that's backed by a byte-array.
                    ;; But that winds up sending along extra data that we don't
                    ;; want, like the header and pieces that we should have
                    ;; skipped due to gap buffering
                    (let [bs (byte-array (.readableBytes buf))]
                      (.readBytes buf bs)
                      (log/info pre-log
                                "triggering child's callback with"
                                (count bs)
                                "bytes")
                      ;; Really need to isolate this in its own
                      ;; try-catch block. Problems in the provided callback are
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
                        ;; ~2x faster than nanoTime, and this resolution
                        ;; seems plenty granular
                        (let [start-time (System/nanoTime)]
                          (->child bs)
                          (let [end-time (System/nanoTime)
                                delta (- end-time start-time)
                                msg (str "Child callback took " delta " ns")]
                            (if (< callback-threshold-warning delta)
                              (if (< callback-threshold-error delta)
                                (log/error pre-log msg)
                                (log/warn pre-log msg))
                              (log/debug pre-log msg))))
                        (catch RuntimeException ex
                          ;; It's very tempting to just re-raise this exception,
                          ;; especially if I'm inside an agent.
                          ;; For now, just log and swallow it.
                          (log/error ex
                                     pre-log
                                     "Failure in child callback."))))
                    ;; And drop the consolidated blocks
                    (log/debug pre-log "Dropping block we just finished sending to child")
                    (.release buf)
                    (update-in state'
                               ;; Yes, this is already a vector
                               [::specs/incoming ::specs/->child-buffer]
                               (comp vec rest))
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
                      (log/error ex pre-log "Failed to forward message to child")
                      (reduced state'))))
                consolidated
                ->child-buffer)
        consolidated)
      ;; 610-614: counters/looping
      )))
