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
;;; Internal Helpers

;; The caller needs to verify that the gap-buffer's start
;; is < receive-bytes.
;; Well, it does, because it can short-circuit a reduce
;; if that's the case.
;; It seems like it would be nice to be able to spec that
;; here for the sake of generative testing.
;; I think I can get away with s/and, though I'll probably
;; be forced to get fancy with the generator
;; TODO: Ask about how.
(s/fdef consolidate-message-block
        :args (s/cat :incoming ::specs/incoming
                     :gap-buffer (s/tuple ::specs/gap-buffer-key ::specs/buf))
        :ret ::specs/incoming)
(defn consolidate-message-block
  "Move the parts of the gap-buffer that are ready to write to child

  Really only meant as a helper refactored out of consolidate-gap-buffer"
  ;; @param incoming: Really an accumulator inside a reduce
  ;; @param k-v-pair: Incoming message block. Tuple of (start-stop tuple) => bytes
  ;; @return modified accumulator
  [{:keys [::specs/->child-buffer
           ::specs/receive-bytes
           ::specs/gap-buffer]
    :as incoming}
   k-v-pair]
  (let [[[start stop] buf] k-v-pair]
    (log/debug "Does"  start "-" stop "close a hole in" gap-buffer "from HWM" receive-bytes "?")
    ;; For now, this top-level if check is redundant.
    ;; I'd rather be safe and trust the JIT than remove it
    ;; under the assumption that callers will be correct.
    ;; Even though I'm the only caller at the moment, this
    ;; is a detail I don't trust in myself.
    (if (<= start receive-bytes)
      ;; Q: Did a previous message overwrite this message block?
      (if (< stop receive-bytes)
        (do
          (log/debug "Dropping previously consolidated block")
          ;; Previously consolidated block. Just drop it.
          (update incoming ::specs/gap-buffer (partial drop 1)))
        ;; Consolidate this message block
        ;; I'm dubious about the logic for bytes-to-skip.
        ;; The math behind it seems wrong...but it seems
        ;; to work in practice.
        ;; Except that it doesn't.
        (let [bytes-to-skip (- receive-bytes start)]
          (when (< 0 bytes-to-skip)
            (log/info "Skipping" bytes-to-skip "previously received bytes in" buf)
            (.skipBytes buf bytes-to-skip))
          (log/debug "Moving first entry from " (::specs/gap-buffer incoming))
          (-> incoming
              (update ::specs/gap-buffer (partial drop 1))
              (update ::specs/->child-buffer conj buf)
              ;; TODO: Compare performance w/ using assoc here
              (update ::specs/receive-bytes (constantly (inc stop))))))
      (reduced incoming))))

(s/fdef consolidate-gap-buffer
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn consolidate-gap-buffer
  ;; I'm dubious that this belongs in here.
  ;; But this namespace is looking very skimpy compared to from-parent,
  ;; which seems like a better choice.
  [{{:keys [::specs/gap-buffer]
     :as incoming} ::specs/incoming
    :as state}]
  {:pre [gap-buffer]}
  (assoc state
         ::specs/incoming
         (reduce (fn [{:keys [::specs/receive-bytes]
                       :as acc}
                      buffer-entry]
                   {:pre [acc
                          receive-bytes]}
                   (assert receive-bytes (str "Missing receive-bytes among: "
                                              (keys acc)
                                              "\nin:\n"
                                              acc
                                              "\na"
                                              (class acc)))
                   (let [[[start stop] buf] buffer-entry]
                     ;; Q: Have we [possibly] filled an existing gap?
                     (if (<= start receive-bytes)
                       (consolidate-message-block acc buffer-entry)
                       ;; There's another gap. Move on
                       (reduced acc))))
                 ;; TODO: Experiment with using a transient for this
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
   {:keys [::specs/incoming]
    :as primed}]
  ;; Major piece of the puzzle that I'm currently missing:
  ;; line 617 will generally update receive-written.
  ;; TODO: expand it to include the pieces I haven't translated yet
  ;; (such as sending some signal, like a nil, to indicate that
  ;; we've hit EOF).
  (let [consolidated (consolidate-gap-buffer primed)
        ->child-buffer (get-in consolidated [::specs/incoming ::specs/->child-buffer])]
    (reduce (fn [state buf]
              ;; Forward buf
              (try
                (->child buf)
                ;; And drop it
                (update state
                        ::specs/->child-buffer
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
                  (log/error ex "Failed to forward message to child")
                  (reduced state))))
            consolidated
            ->child-buffer)
    ;; 610-614: counters/looping
    ))
