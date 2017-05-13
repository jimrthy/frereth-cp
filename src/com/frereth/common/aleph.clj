(ns com.frereth.common.aleph
  "Wrappers for my aleph experiments

In a lot of ways, this should just go away
completely. I'd like this library to be
transport-neutral."
  (:require [aleph.udp :as udp]
            [clojure.edn :as edn]
            [clojure.spec :as s]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))


;; TODO: Get these spec'd
(s/def ::connection-info any?)
(s/def ::server any?)
(s/def ::stream any?)

;; None of the rest of these belong in here...do they?
(defn put!
  "Really just a convenience wrapper to cut down on the number
of namespaces clients have to :require to use this one"
  [stream msg]
  (comment
    (stream/put! stream msg))
  (throw (Exception. "Replace this")))

(defn take!
  "Note that this approach doesn't really compose well.

Since everything else in manifold expects the deferred.

That makes this much less useful"
  ([stream]
   (comment
     @(stream/take! stream))
   (throw (Exception. "Replace this")))
  ([stream default]
   (comment
     @(stream/take! stream default))
   (throw (Exception. "Replace this")))
  ([stream default timeout]
   (comment
     (let [deferred (stream/take! stream default)]
       (deref deferred timeout ::timeout)))
   (throw (Exception. "Replace this"))))

(defn router-event-loop
  "Sets up an event loop like a 0mq router socket

At least conceptually."
  [f s cleanup])

(s/fdef router
        :args (s/cat :connections any?
                     :f (s/fspec
                         :args (s/cat :message bytes?)
                         ;; nil is the signal to close the connection
                         :ret any?))
        :ret (s/fspec :args (s/cat :s ::stream
                                   :info any?)))
(defn router
  [connections f]
  (fn [s {:keys [remote-addr]}]
    (let [putter (partial put! s)]
      (try
        (swap! connections
               assoc remote-addr putter)
        (catch Exception ex
          (println "Failed to add new connection!\n" ex)
          (.printStackTrace ex)
          (throw ex)))
      (assert (identical? (@connections remote-addr) putter)))
    (let [cleanup (fn [_]
                    (swap! connections dissoc remote-addr))]
      (router-event-loop f s cleanup))))

(s/fdef request-response
        :args (s/cat :f (s/fspec
                         :args (s/cat :message bytes?)
                         ;; nil is the signal to close the connection
                         :ret any?))
        :ret (s/fspec :args (s/cat :s ::stream
                                   :info any?)))
(defn request-response
  "This works fine for request/response style messaging,
  but seems pretty useless for real async exchanges.

  i.e. How am I supposed to send arbitrary messages back
  to the client at arbitrary times?"
  [f]
  (fn [s info]
    ;; That loop's running in the background.
    (println "req-rsp loop started")))

(defn close!
  "Closes a server instance"
  [x]
  (.close x))

(defn start-client!
  "Apparently this doesn't need to be closed"
  ([host port ssl? insecure?])
  ([host port]
   (start-client! host port false false)))

(s/fdef start-server!
        :args (s/cat :handler (s/fspec :args (s/cat :stream ::stream
                                                    :info ::connection-info))
                     :port :zmq-socket/port)
        :ret ::server)
(defn start-server!
  "Starts a server that listens on port and calls handler"
  ([handler port ssl-context])
  ([handler port]
   (start-server! handler port nil)))
