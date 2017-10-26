(ns frereth-cp.client.message
  (:require [clojure.tools.logging :as log]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared.constants :as K]
            [manifold.stream :as strm])
  (:import io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

(defn pull-initial-message-bytes
  [wrapper ^bytes msg-bytes]
  (log/info (str "pull-initial-message-bytes"
                 (class msg-bytes)
                 ": "
                 (count msg-bytes)
                 " incoming bytes"))
  (when msg-bytes
    (let [bytes-available (K/initiate-message-length-filter (count msg-bytes))]
      (when (< 0 bytes-available)
        msg-bytes))))
