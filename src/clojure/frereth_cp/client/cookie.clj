(ns frereth-cp.client.cookie
  (:require [clojure.pprint :refer (pprint)]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.client.initiate :as initiate]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm]))

(defn hello-response-timed-out!
  [this failure]
  (send this #(throw (ex-info "Timed out waiting for hello response"
                              (assoc %
                                     :problem failure)))))

(s/fdef wait-for-cookie!
        :args (s/cat :wrapper ::state/agent-wrapper
                     :notifier dfrd/deferrable?
                     :sent ::specs/network-packet)
        :ret any?)
(defn wait-for-cookie!
  [wrapper notifier sent]
  (if (not= sent ::sending-hello-timed-out)
    (do
      (log/info "client/wait-for-cookie -- Sent to server:" sent)
      (let [chan<-server (::state/chan<-server @wrapper)
            timeout (state/current-timeout wrapper)
            d (strm/try-take! chan<-server
                                ::drained
                                timeout
                                ::hello-response-timed-out)]
        (dfrd/on-realized d
          (fn [{:keys [:host :message :port]
                :as cookie}]
            ;; FIXME: Have to compare :host (and, realistically, :port)
            ;; against the server associated with the most recently
            ;; sent HELLO.
            ;; If they don't match, we need to discard this cookie
            ;; and go back to waiting (don't forget to reduce the
            ;; timeout based on elapsed time)
            (log/info "Incoming response from server:\n"
                      (utils/pretty cookie))
            (if-not (or (= cookie ::drained)
                        (= cookie ::hello-response-timed-out))
              (if (= K/cookie-packet-length (count message))
                (dfrd/success! notifier (assoc @wrapper
                                               ::specs/network-packet cookie))
                ;; FIXME: Retry with a timeout reduced for elapsed time
                (dfrd/error! (ex-info "TODO: Just discard and retry"
                                      cookie)))
              (do
                ;; TODO: More forgiving error handling.
                ;; One bad server really shouldn't ruin everything.
                (assert
                        (str "Invalid cookie. Expected "
                             K/cookie-packet-length
                             " bytes. Got "
                             (count message)
                             " in\n"
                             (b-t/->string message)))))
            (log/error "Server didn't respond to HELLO."))
          ;; Note that timing out doesn't actually count as
          ;; an error.
          ;; This branch will never be taken.
          (partial hello-response-timed-out! wrapper))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
