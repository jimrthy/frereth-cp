(ns frereth-cp.client.cookie
  (:require [clojure.pprint :refer (pprint)]
            [clojure.tools.logging :as log]
            [frereth-cp.client.initiate :as initiate]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.util :as utils]
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
          (fn [{:keys [:host :message :port]
                :as cookie}]
            (log/info "Incoming response from server:\n"
                      (utils/pretty cookie))
            (if-not (or (= cookie ::drained)
                        (= cookie ::hello-response-timed-out))
              (do
                ;; TODO: More forgiving error handling.
                ;; One bad server really shouldn't ruin everything.
                ;; (Note that that's another major part of the
                ;; protocol that I've totally glossed over for the
                ;; moment: trying to contact multiple servers at once)
                (assert (= K/cookie-packet-length (count message))
                        (str "Invalid cookie. Expected "
                             K/cookie-packet-length
                             " bytes. Got "
                             (count message)
                             " in\n"
                             cookie))
                (log/info "Building/sending Vouch")
                (initiate/build-and-send-vouch wrapper cookie))
              (log/error "Server didn't respond to HELLO.")))
          ;; Note that timing out doesn't actually count as
          ;; an error.
          ;; This branch will never be taken.
          (partial hello-response-timed-out! wrapper))))
    (throw (RuntimeException. "Timed out sending the initial HELLO packet"))))
