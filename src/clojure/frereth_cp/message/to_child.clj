(ns frereth-cp.message.to-child
  "Looks like this may not be needed at all

  Pretty much everything that might have been interesting really
  seems to belong in from-parent.

  Or in the callback that got handed to message as part of its constructor.

  Although there *is* the bit about closing the pipe to the child at
  the bottom of each event loop."
  (:require [clojure.pprint :refer (cl-format)]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
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
  (let [prelog (utils/pre-log message-loop-name)
        [[start stop] ^ByteBuf buf] k-v-pair]
    ;; Important note re: the logic that's about to hit:
    ;; start, strm-hwm, and stop are all absolute stream
    ;; addresses.
    ;; If we've received 1 byte, the strm-hwm is at 0.
    ;; If start is 0 or 1, then we might have some overlap.
    ;; As long as stop is somewhere past strm-hwm.
    (log/debug prelog
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
              (log/info prelog
                        "Skipping"
                        bytes-to-skip
                        "previously received bytes in"
                        buf)
              (.skipBytes buf bytes-to-skip)))
          (log/debug prelog
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
              ;; Microbenchmarks and common sense indicate that
              ;; assoc is significantly faster than update
              (assoc ::specs/contiguous-stream-count stop)))
        (do
          (log/debug prelog
                     "Dropping previously consolidated block")
          (let [to-drop (val (first gap-buffer))]
            (when-not keyword? to-drop
                      (try
                        (.release to-drop)
                        (catch RuntimeException ex
                          (log/error prelog
                                     ex
                                     "Failed to release"
                                     to-drop)))))
          (update incoming ::specs/gap-buffer pop-map-first)))
      ;; Gap starts past the end of the stream.
      (do
        (reduced incoming)))))

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

(s/fdef read-bytes-from-parent!
        :args (s/cat :io-handle ::specs/io-handle
                     :buffer bytes?)
        :ret (s/or :buffer bytes?
                   :eof ::specs/eof-flag))
(defn read-bytes-from-parent!
  "Parent wrote bytes to its outbuffer. Read them."
  [{:keys [::specs/child-in
           ::specs/message-loop-name]
    :as io-handle}
   #^bytes buffer]
  {:pre [buffer
         child-in]}
  (let [prelog (utils/pre-log message-loop-name)
        bytes-available (.available child-in)
        max-n (count buffer)]
    (if (< 0 bytes-available)
      (let [n (.read child-in buffer 0 (min bytes-available
                                            max-n))]
        (if (<= 0 n)
          ;; Can't just return buffer: we don't
          ;; have a good way to tell the caller
          ;; how many bytes we just received
          (let [holder (byte-array n)]
            (log/debug prelog
                       n "bytes received from parent")
            (b-t/byte-copy! holder 0 n buffer)
            holder)
          ::specs/normal))
      (do
        (log/info prelog "No bytes available for child. Blocking Parent Monitor")
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
          (log/info prelog "Parent Monitor thread unblocked")
          (let [result
                (cond (neg? byte1) (do
                                     (log/warn prelog "Parent monitor received EOF")
                                     ;; Q: Do I need to .close child-in here?
                                     ;; A: It won't hurt.
                                     (.close child-in)
                                     ::specs/normal)
                      (keyword? byte1) byte1
                      (< 0 bytes-available)
                      (do
                        (log/debug prelog
                                   "Trying to read"
                                   bytes-available
                                   "bytes from"
                                   child-in
                                   "into"
                                   (count buffer)
                                   "bytes in"
                                   buffer)
                        ;; Have to account for the initial unblocking byte
                        (let [n (.read child-in buffer 0 (min bytes-available
                                                              (dec max-n)))]
                          (if (<= 0 n)
                            (let [holder (byte-array (inc n))]
                              (log/debug prelog
                                         (inc n)
                                         "bytes received from parent after initial"
                                         byte1)
                              (aset-byte holder 0 (b-t/possibly-2s-complement-8 byte1))
                              (b-t/byte-copy! holder 1 n buffer)
                              holder))))
                      :else (byte-array [byte1]))]
            (when (keyword? result)
              ;; We got this because the connected PipedOutputStream closed.
              (.close child-in))
            result))))))

(defn write-bytes-to-child-pipe!
  "Forward the byte-array inside the buffer"
  [prelog
   to-child
   state
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
      (log/info prelog
                "Signalling child's input loop with"
                n
                "bytes")
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
            (if (< (* 1000000 callback-threshold-warning) delta)
              (if (< (* 1000000 callback-threshold-error) delta)
                (log/error prelog msg)
                (log/warn prelog msg))
              (log/debug prelog msg))))
        (catch RuntimeException ex
          ;; It's very tempting to just re-raise this exception,
          ;; especially if I'm inside an agent.
          ;; For now, just log and swallow it.
          (log/error ex
                     prelog
                     "Failure in child callback.")))
      ;; And drop the consolidated blocks
      (log/debug prelog "Dropping block we just finished sending to child")
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
          (update-in [::specs/incoming ::specs/receive-written] + n)))
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
      (log/error ex prelog "Failed to forward message to child")
      (reduced state))))

(s/fdef possibly-close-pipe!
        :args (s/cat :io-handle ::specs/io-handle
                     :state ::specs/state
                     :prelog string?)
        :ret any?)
(defn possibly-close-pipe!
  "Maybe signal child that it won't receive anything else"
  [{:keys [::specs/to-child]
    :as io-handle}
   {{:keys [::specs/contiguous-stream-count
            ::specs/receive-eof
            ::specs/receive-total-bytes
            ::specs/receive-written]
     :as incoming} ::specs/incoming
    :as state}
   prelog]
  (log/debug (str prelog "Process EOF? (receive-eof: " receive-eof ")"))
  (if (= ::specs/false receive-eof)
    state
    (if (= receive-written receive-total-bytes)
      (do
        (log/info prelog "Have received everything other side will send")
        (when-not to-child
          (log/error prelog "Missing to-child, so we can't close it"))
        (.close to-child))
      (log/warn (str prelog
                     "EOF flag received.\n"
                     (select-keys incoming
                                  [::specs/contiguous-stream-count
                                   ::specs/receive-eof
                                   ::specs/receive-total-bytes
                                   ::specs/receive-written]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef build-gap-buffer
        :ret ::specs/gap-buffer)
(defn build-gap-buffer
  []
  (sorted-map))

(defn start-parent-monitor!
  "This is probably a reasonable default for many/most use cases"
  ;; I *do* want to provide the option to write your own, though.
  ;; Maybe I should add an optional parameter: if you don't provide
  ;; this, it will default to calling this.
  [{:keys [::specs/message-loop-name
           ::specs/child-in]
    :as io-handle}
   cb]
  (dfrd/future
    (let [prelog (utils/pre-log message-loop-name)
          buffer (byte-array K/standard-max-block-length)]
      (log/info prelog "Starting the loop watching for bytes the parent has sent toward the child")
      (try
        (loop []
          (let [holder (read-bytes-from-parent! io-handle buffer)
                start-time (System/nanoTime)]
            (log/debug prelog "Triggering child callback")
            (try
              (cb holder)
              (catch ExceptionInfo ex
                (log/error ex
                           prelog
                           (str "At least we can log something interesting with this:\n"
                                (utils/pretty (.getData ex))))
                (assert (not ex) (str prelog
                                      "Child callback failed")))
              (catch Exception ex
                (log/error ex
                           prelog
                           "This is not acceptable behavior at all")
                (assert (not ex) (str prelog
                                      "Child callback failed"))))
            (let [end-time (System/nanoTime)
                  msg (cl-format nil
                                 "Child callback took ~:d nanoseconds"
                                 (- end-time start-time))]
              (log/debug prelog msg))
            (when (bytes? holder)
              (recur))))
        (log/warn prelog "parent-monitor loop exited")
        (catch IOException ex
          (log/warn ex
                    prelog
                    "This should happen because the stream from parent closed"))
        (catch Exception ex
          (log/error ex
                     prelog
                     "Parent Monitor failed unexpectedly"))))))

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
  (let [prelog (utils/pre-log message-loop-name)]
    (let [{{:keys [::specs/receive-eof]
            :as consolidated-incoming} ::specs/incoming
           :as consolidated} (consolidate-gap-buffer state)
          ->child-buffer (::specs/->child-buffer consolidated-incoming)
          block-count (count ->child-buffer)]
      (log/debug (str prelog
                      "Have "
                      block-count
                      " consolidated block(s) ready to go to child.\n"
                      "receive-eof: "
                      receive-eof))
      (if (< 0 block-count)
        (let [result (reduce (partial write-bytes-to-child-pipe!
                                      prelog
                                      to-child)
                             consolidated
                             ->child-buffer)]
          (possibly-close-pipe! io-handle result prelog))
        (do
          (log/warn prelog "0 bytes to forward to child")
          (possibly-close-pipe! io-handle consolidated prelog)))
      ;; 610-614: counters/looping
      ;; (doesn't really apply to this implementation)
      )))
