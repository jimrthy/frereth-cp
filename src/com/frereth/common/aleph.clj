(ns com.frereth.common.aleph
  "Wrappers for my aleph experiments"
  (:require [aleph.udp :as udp]
            [clojure.edn :as edn]
            [clojure.spec :as s]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))


;; TODO: Get these spec'd
(s/def ::connection-info any?)
(s/def ::server any?)
(s/def ::stream any?)

(comment
  (defn wrap-gloss-protocol
    "Use the gloss library as middleware to apply a protocol to a raw stream"
    [protocol s]
    (let [out (stream/stream)]
      (stream/connect
       (stream/map #(gloss-io/encode protocol %) out)
       s)
      (stream/splice out
                     (gloss-io/decode-stream s protocol)))))

(comment
  (defn simplest
    "Encode a length and a string into a packet
  Then translate the string into EDN.
  This approach is rife for abuse. What happens
  if one side lies about the string length? Or
  sends garbage?"
    [stream]
    (comment
      (let [protocol (gloss/compile-frame
                      (gloss/finite-frame :uint32
                                          (gloss/string :utf-8))
                      pr-str
                      edn/read-string)]
        (wrap-gloss-protocol protocol stream)))))

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
  [f s cleanup]
  (comment
    (deferred/chain
      (deferred/loop []
        ;; Q: How much cleaner would this be to just
        ;; use stream/consume ?
        ;; Or would that work at all?
        (-> (deferred/let-flow [msg (stream/take! s ::none)]
              (when-not (identical? ::none msg)
                (deferred/let-flow [result (f msg)]
                  (when result
                    (deferred/recur)))))
            (deferred/catch
                (fn [ex]
                  (println "Server Oops!\n" ex)
                  (.printStackTrace ex)
                  (put! s {:error (.getMessage ex)
                           :type (-> ex class str)})
                  (stream/close! s)))))
      cleanup)))

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
    (comment
      (deferred/chain
        (deferred/loop []
          (-> (deferred/let-flow [msg (stream/take! s ::none)]
                (when-not (identical? ::none msg)
                  (deferred/let-flow [msg' (deferred/future (f msg))
                                      result (put! s msg')]
                    (when result
                      (deferred/recur)))))
              (deferred/catch
                  (fn [ex]
                    (println "Server Oops!")
                    (put! s {:error (.getMessage ex)
                             :type (-> ex class str)})
                    ;; Q: Is this really what should happen?
                    (stream/close! s)))))
        (fn [_]
          ;; Actually, I should be able to clean up in here
          (println "Client connection really exited"))))
    ;; That loop's running in the background.
    (println "req-rsp loop started")))

(defn close!
  "Closes a server instance"
  [x]
  (.close x))

(comment
  (defn start-deferred-client!
    [host port ssl? insecure?]
    (comment (deferred/chain (tcp/client {:host host
                                          :port port
                                          :ssl? ssl?
                                          :insecure? insecure?})
               ;; Honestly, we need a way to specify this.
               ;; Except that this is the way, right?
               #(simplest %)))))

(defn start-client!
  "Apparently this doesn't need to be closed"
  ([host port ssl? insecure?]
   (comment
     @(start-deferred-client! host port ssl? insecure?)))
  ([host port]
   (start-client! host port false false)))

(s/fdef start-server!
        :args (s/cat :handler (s/fspec :args (s/cat :stream ::stream
                                                    :info ::connection-info))
                     :port :zmq-socket/port)
        :ret ::server)
(defn start-server!
  "Starts a server that listens on port and calls handler"
  ([handler port ssl-context]
   (comment (tcp/start-server
             (fn [s info]
               (println (java.util.Date.) "Outer server handler")
               (handler (comment (simplest s)) info))
             {:port port
              :ssl-context ssl-context})))
  ([handler port]
   (start-server! handler port nil)))
