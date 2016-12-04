(ns com.frereth.common.aleph
  (:require [aleph.tcp :as tcp]
            [clojure.spec :as s]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))

;; TODO: Get these spec'd
(s/def ::connection-info any?)
(s/def ::server any?)
(s/def ::stream any?)

(s/fdef start-server
        :args (s/cat :handler (s/fspec :args (s/cat :stream ::stream
                                                    :info ::connection-info)))
        :ret ::server)
(defn start-server!
  "Starts a server that listens on port and calls handler"
  [handler port]
  (tcp/start-server
   handler
   {:port port}))

(defn put!
  "Really just a convenience wrapper to cut down on the number
of namespaces clients have to :require to use this one"
  [stream bs]
  (stream/put! stream bs))

(defn take!
  [stream]
  @(stream/take! stream))

(s/fdef request-response
        :args (s/cat :connections any?
                     :f (s/fspec
                         :args (s/cat :message bytes?)
                         ;; nil is the signal to close the connection
                         :ret any?))
        :ret (s/fspec :args (s/cat :s ::stream
                                   :info any?)))
(defn router
  [connections f]
  (fn [s info]
    (println "Client connecting:\n"
             s "\n" info)
    ;; Want to do something like this, so the server can send
    ;; messages to this client asynchronously.
    ;; Is it really this simple/easy?
    (swap! connections update (:remote-addr info) (partial put! s))
    (deferred/loop []
      (-> (deferred/let-flow [msg (take! s ::none)]
            (println "client->server")
            (when-not (identical? ::none msg)
              (deferred/let-flow [result (f msg)]
                (when result
                  (deferred/recur)))))
          (deferred/catch
              (fn [ex]
                (println "Server Oops!")
                (put! s (-> {:error (.getMessage ex)
                             :type (class ex)}
                            pr-str
                            .getBytes))
                (stream/close! s)))))
    (println "What's the best way to clean up connections when that loop exits?")))

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
  to the client at arbitrary times?

  (there are probably hints in the full duplex wrapper
  at the very beginning of the example)"
  [f]
  (fn [s info]
    (println "Client connecting:\n"
             s ", a" (class s) "\n" info)
    (deferred/loop []
      (-> (deferred/let-flow [msg (stream/take! s ::none)]
            (println "client->server")
            ;; Note that, as implemented, this will never be true
            ;; msg is just raw bytes at this point
            (when-not (identical? ::none msg)
              (deferred/let-flow [msg' (deferred/future (f msg))
                                  result (put! s msg')]
                (println "server->client: " (String. msg'))
                (when result
                  (deferred/recur)))))
          (deferred/catch
              (fn [ex]
                (println "Server Oops!")
                ;; TODO: Need a serialization library
                (put! s (-> {:error (.getMessage ex)
                             :type (class ex)}
                            pr-str
                            .getBytes))
                (stream/close! s)))))))

(defn start-client!
  [host port]
  @(tcp/client {:host host, :port port}))
