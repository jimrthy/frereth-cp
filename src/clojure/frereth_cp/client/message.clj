(ns frereth-cp.client.message
  (:require [clojure.tools.logging :as log]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared.constants :as K]
            [manifold.stream :as strm]))

(defn pull-initial-message-bytes
  [wrapper msg-byte-buf]
  (when msg-byte-buf
    (log/info "pull-initial-message-bytes ByteBuf:" msg-byte-buf)
    (let [bytes-available (K/initiate-message-length-filter (.readableBytes msg-byte-buf))]
      (when (< 0 bytes-available)
        (let [buffer (byte-array bytes-available)]
          (.readBytes msg-byte-buf buffer)
          ;; TODO: Compare performance against .discardReadBytes
          ;; A lot of the difference probably depends on hardware
          ;; choices.
          ;; Though, realistically, this probably won't be running
          ;; on minimalist embedded controllers for a while.
          (.discardSomeReadBytes msg-byte-buf)

          (if (< 0 (.readableBytes msg-byte-buf))
            ;; Reference implementation just fails on this scenario.
            ;; That seems like a precedent that I'm OK breaking.
            ;; The key for it is that (in the reference) there's another
            ;; buffer program sitting between
            ;; this client and the "real" child that can guarantee that this works
            ;; correctly.
            (send wrapper update ::state/read-queue conj msg-byte-buf)
            ;; I actually have a gaping question about performance here:
            ;; will I be able to out-perform java's garbage collector by
            ;; recycling used ByteBufs?
            ;; A: Absolutely not!
            ;; It was ridiculous to ever even contemplate.
            (strm/put! (::release->child @wrapper) msg-byte-buf))
          buffer)))))
