(ns com.frereth.common.aleph
  (:require [aleph.tcp :as tcp]
            [clojure.edn :as edn]
            [clojure.spec :as s]
            [gloss.core :as gloss]
            [gloss.io :as gloss-io]
            [manifold.deferred :as deferred]
            [manifold.stream :as stream]))

;; TODO: Get these spec'd
(s/def ::connection-info any?)
(s/def ::server any?)
(s/def ::stream any?)

(def glossy-protocol
  "For experimentation only
  (at least for now)
  Either transit or fressian seems like a much better option.
  Especially since I really mean to send the data encrypted"
  (gloss/compile-frame
   (gloss/finite-frame :uint32
                       (gloss/string :utf-8))
   pr-str
   edn/read-string))

(defn wrap-duplex-stream
  [protocol s]
  (let [out (stream/stream)]
    (stream/connect
     (stream/map #(gloss-io/encode protocol %) out)
     s)
    (stream/splice
     out
     (gloss-io/decode-stream s protocol))))

(s/fdef start-server
        :args (s/cat :handler (s/fspec :args (s/cat :stream ::stream
                                                    :info ::connection-info)))
        :ret ::server)
(defn start-server!
  "Starts a server that listens on port and calls handler"
  [handler port]
  (tcp/start-server
   (fn [s info]
     (println "New client connection:" info)
     (handler (wrap-duplex-stream glossy-protocol s) info))
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
                (put! s {:error (.getMessage ex)
                         :type (-> ex class str)})
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
    (deferred/chain
      (deferred/loop []
        (-> (deferred/let-flow [msg (stream/take! s ::none)]
              (println "client->server")
              (when-not (identical? ::none msg)
                (deferred/let-flow [msg' (deferred/future (f msg))
                                    result (put! s msg')]
                  (println "server->client: " msg')
                  (when result
                    (deferred/recur)))))
            (deferred/catch
                (fn [ex]
                  (println "Server Oops!")
                  ;; TODO: Need a serialization library
                  (put! s {:error (.getMessage ex)
                           :type (-> ex class str)})
                  (stream/close! s)))))
      (fn [_]
        ;; Actually, I should be able to clean up in here
        (println "Client connection really exited")))
    ;; That loop's running in the background.
    (println "After the req-rsp loop")))

(defn start-client!
  [host port]
  @(deferred/chain (tcp/client {:host host, :port port})
     #(wrap-duplex-stream glossy-protocol %)))
