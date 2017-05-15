(ns frereth-cp.client.cookie
  (:require [clojure.pprint :refer (pprint)]
            [clojure.tools.logging :as log]
            [frereth-cp.client.initiate :as initiate]
            [frereth-cp.client.state :as state]
            [manifold.deferred :as deferred]
            [manifold.stream :as strm]))

(defn hello-response-timed-out!
  [this failure]
  (send this #(throw (ex-info "Timed out waiting for hello response"
                              (assoc %
                                     :problem failure)))))

(defn wait-for-cookie
  [wrapper sent]
  (if (not= sent ::sending-hello-timed-out)
    (do
      (log/info "client/wait-for-cookie -- Sent to server:" sent)
      (let [chan<-server (::state/chan<-server @wrapper)
            timeout (state/current-timeout wrapper)
            d (strm/try-take! chan<-server
                                ::drained
                                timeout
                                ::hello-response-timed-out)]
        (deferred/on-realized d
          (fn [cookie]
            (log/info "Incoming response from server:\n"
                      (with-out-str (pprint cookie)))
            (if-not (or (= cookie ::drained)
                        (= cookie ::hello-response-timed-out))
              (do
                (log/info "Building/sending Vouch")
                (initiate/build-and-send-vouch wrapper cookie))
              (log/error "Server didn't respond to HELLO.")))
          (partial hello-response-timed-out! wrapper))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
