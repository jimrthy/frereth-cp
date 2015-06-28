(ns com.frereth.common.zmq-socket
  (:require [cljeromq.core :as mq]
            [com.stuartsierra.component :as component]
            [schema.core :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

(def socket-types (s/enum :push :pull
                          :req :rep
                          :pair
                          :pub :sub
                          :router :dealer))

(s/defrecord ContextWrapper
    [ctx :- mq/Context
     thread-count :- s/Int]
  component/Lifecycle
  (start
   [this]
   (when-not ctx
     (let [thread-count (or thread-count 1)
           ctx (mq/context thread-count)]
       (assoc this
              :ctx ctx
              :thread-count thread-count))))
  (stop
   [this]
   (when ctx
     ;; Note that this is going to hang until
     ;; all sockets are closed
     (mq/terminate! ctx)
     (assoc this :ctx nil))))

(s/defrecord SocketDescription
    [ctx :- ContextWrapper
     url :- mq/zmq-url
     sock-type :- socket-types
     direction :- (s/enum :bind :connect)
     socket :- mq/Socket]
  ;; Q: Why can't I include a docstring?
  ;; "Describe a 0mq socket"
  component/Lifecycle
  (start
   [this]
   (when-not socket
     (let [sock (mq/socket! (:ctx ctx) sock-type)
         uri (mq/connection-string url)]
     (if (= direction :bind)
       (mq/bind! sock uri)
       (mq/connect! sock uri))
     (assoc this :socket sock))))
  (stop
   [this]
   (when socket
     (mq/set-linger! socket 0)
     (mq/close! socket)
     (assoc this :socket nil))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public
;;; TODO: Really need to add wrappers for everything interesting,
;;; esp. send/recv

(s/defn ctx-ctor :- ContextWrapper
  "TODO: This doesn't belong in a socket namespace"
  [{:keys [thread-count]
    :or [thread-count 1]
    :as options}]
  (map->ContextWrapper options))

(s/defn ctor :- SocketDescription
  [{:keys [ctx url direction sock-type]
    :or {direction :connect}
    :as options}]
  (map->SocketDescription options))
