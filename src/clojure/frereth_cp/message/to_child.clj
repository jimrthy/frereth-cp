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
            [frereth-cp.message.specs :as specs])
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
  "Move the parts of the gap-buffer that are ready to write to child"
  [{:keys [::specs/->child-buffer
           ::specs/receive-bytes
           ::specs/gap-buffer]
    :as incoming}
   k-v-pair]
  (let [[[start stop] buf] k-v-pair]
    ;; For now, this top-level if check is redundant.
    ;; I'd rather be safe and trust the JVM that remove it
    ;; under the assumption that callers will be correct.
    ;; Even though I'm the only caller at the moment, this
    ;; is a detail I don't trust in myself.
    (if (<= start receive-bytes)
      ;; Q: Did a previous message overwrite this message block?
      (if (<= stop receive-bytes)
        ;; Skip this message block
        (update incoming ::specs/gap-buffer (partial drop 1))
        ;; Consolidate this message block
        (let [bytes-to-skip (- receive-bytes start)]
          (when (< 0 bytes-to-skip)
            (.skipBytes buf bytes-to-skip))
          (log/debug "Dropping first entry from " (::specs/gap-buffer incoming))
          (-> incoming
              (update ::specs/gap-buffer (partial drop 1))
              (update ::specs/->child-buffer conj buf)
              (update ::specs/receive-bytes (constantly stop))))))))

(s/fdef consolidate-gap-buffer
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn consolidate-gap-buffer
  ;; I'm dubious that this belongs in here.
  ;; But this namespace is looking very skimpy compared to from-parent,
  ;; which seems like a better choice.
  [{:keys [::specs/incoming]
    :as state}]
  ;; TODO: Needs unit tests!
  ;; This seems to be begging for generative testing
  (let [{:keys [::specs/gap-buffer]} incoming]
    (assoc state
           ::specs/incoming
           (reduce (fn [{:keys [::specs/receive-bytes]
                         :as acc}
                        [[[start stop] k] buf]]
                     ;; Q: Have we filled an existing gap?
                     (if (<= start receive-bytes)
                       (consolidate-message-block acc buf)
                       ;; There's another gap. Move on
                       (reduced acc)))
                   incoming
                   gap-buffer))))

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
  "lines 615-632  cover what's supposed to happen next."
  [->child
   {:keys [::specs/incoming]
    :as primed}]
  ;; Major piece of the puzzle that I'm currently missing:
  ;; line 617 will generally update receive-written.
  ;; TODO: Move what little I have here into to-child and
  ;; expand it to include the pieces I haven't translated yet
  ;; (such as sending some signal, like a nil, to indicate that
  ;; we've hit EOF).
  (let [consolidated (consolidate-gap-buffer primed)
        ->child-buffer (get-in consolidated ::specs/->child-buffer)]
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
