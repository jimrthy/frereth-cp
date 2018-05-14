(ns frereth-cp.client.message
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.specs :as specs]
            [manifold.stream :as strm])
  (:import io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

(s/def ::possible-response bytes?)

(s/fdef filter-initial-message-bytes
        :args (s/cat :log-state ::log/state
                     :msg-bytes ::specs/msg-bytes)
        :ret  (s/keys :req [::log/state]
                      :opt [::possible-response]))
(defn filter-initial-message-bytes
  "Make sure bytes are legal for a Vouch"
  [log-state
   ^bytes msg-bytes]
  (let [log-state (log/info log-state
                            ::filter-initial-message-bytes
                            ""
                            {::incoming msg-bytes
                             ::incoming-class (class msg-bytes)
                             ::incoming-length (count msg-bytes)})
        result {::log/state log-state}]
    (if (and msg-bytes
             (K/legal-vouch-message-length? msg-bytes))
      (assoc result ::possible-response msg-bytes)
      result)))
