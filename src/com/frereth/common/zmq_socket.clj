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

(s/defrecord SocketDescription
    [ctx :- mq/Context
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
     (let [sock (mq/socket! ctx sock-type)
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

(s/defn ctor :- SocketDescription
  [{:keys [url direction sock-type]
    :or {direction :connect}
    :as options}]
  (map->SocketDescription options))
