(ns frereth-cp.client.message
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.specs :as specs]
            [manifold.stream :as strm])
  (:import io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::possible-response bytes?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef filter-initial-message-bytes
        :args (s/cat :log-state ::log/state
                     :msg-bytes ::specs/msg-bytes)
        :ret  (s/keys :req [::log/state]
                      :opt [::possible-response]))
(defn filter-initial-message-bytes
  "Make sure bytes are legal for a Vouch"
  [log-state
   ^bytes initiate-packet]
  (when initiate-packet
    (let [packet-size (count initiate-packet)
          log-state (log/info log-state
                              ::filter-initial-message-bytes
                              ""
                              {::shared/packet initiate-packet
                               ::incoming-class (class initiate-packet)
                               ::incoming-length packet-size})
          result {::log/state log-state}]
      (if (<= packet-size K/max-initiate-packet-size)
        (assoc result ::possible-response initiate-packet)
        result))))
