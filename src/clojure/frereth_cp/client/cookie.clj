(ns frereth-cp.client.cookie
  (:require [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.client.initiate :as initiate]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/fdef received-response
        :args (s/cat :this ::state/state
                     :notifier dfrd/deferrable?
                     :cookie ::specs/network-packet)
        :ret any?)
(defn received-response
  [{log-state ::log2/state
    :as this}
   notifier
   {:keys [:host :message :port]
        :or {message (byte-array 0)}
        :as cookie}]
  ;; FIXME: Have to compare :host (and, realistically, :port)
  ;; against the server associated with the most recently
  ;; sent HELLO.
  ;; If they don't match, we need to discard this cookie
  ;; and go back to waiting (don't forget to reduce the
  ;; timeout based on elapsed time)
  (let [log-state (log2/info log-state
                             ::received-response
                             "Possibly got a response from server"
                             cookie)]
    (if-not (or (= cookie ::drained)
                (= cookie ::hello-response-timed-out))
      (if (= K/cookie-packet-length (count message))
        (dfrd/success! notifier (assoc this
                                       ::log2/state log-state
                                       ::specs/network-packet cookie))
        ;; FIXME: Retry with a timeout reduced for elapsed time
        (let [log-state (log2/warn log-state
                                   ::received-response
                                   "Invalid response. Just discard and retry"
                                   {::problem cookie})]
          (dfrd/success! notifier (assoc this ::log2/state log-state))))
      (let [log-state (log2/warn log-state
                                 ::received-response
                                 "Server didn't respond to HELLO. Move on to next.")]
        (dfrd/success! notifier (assoc this ::log2/state log-state))))))

(defn hello-response-failed!
  [this failure]
  (send this #(throw (ex-info "Timed out waiting for hello response"
                              (assoc %
                                     :problem failure)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef wait-for-cookie!
        :args (s/cat :wrapper ::state/agent-wrapper
                     :notifier dfrd/deferrable?
                     ::timeout (s/and number?
                                      (complement neg?))
                     :sent ::specs/network-packet)
        :ret any?)
(defn wait-for-cookie!
  [wrapper notifier timeout sent]
  (if (not= sent ::sending-hello-timed-out)
    (do
      (log/info "client/wait-for-cookie -- Sent to server:" sent)
      (let [chan<-server (::state/chan<-server @wrapper)
            d (strm/try-take! chan<-server
                                ::drained
                                timeout
                                ::hello-response-timed-out)]
        (dfrd/on-realized d
                          (partial received-response @wrapper notifier)
                          (partial hello-response-failed! wrapper))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
