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

(s/fdef consolidate-gap-buffer
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn consolidate-gap-buffer
  ;; I'm dubious that this belongs in here.
  ;; But this namespace is looking very skimpy compared to from-parent,
  ;; which seems like a better choice.
  [{:keys [::specs/incoming]
    :as state}]
  (let [{:keys [::specs/->child-buffer
                ::specs/gap-buffer
                ::specs/receive-bytes]} incoming]
    (throw (RuntimeException. "Write this"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

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
