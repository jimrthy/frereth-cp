(ns com.frereth.common.async-component
  "Component wrapper around core.async pieces

So I can use them in Systems without really thinking
about the bigger picture.

  No, this probably isn't a very good idea"
  (:require [clojure.core.async :as async]
            [com.frereth.common.schema :as frereth-schema]
            [com.stuartsierra.component :as component]
            [schema.core :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

(s/defrecord AsyncChannelComponent [buffer :- clojure.core.async.impl.protocols.Buffer
                                    buffer-size :- (s/maybe s/Int)
                                    ch :- frereth-schema/async-channel
                                    transducer
                                    ex-handler :- (s/=> s/Any java.lang.Throwable)]
  component/Lifecycle
  (start [this]
    (let [buffer (or buffer (async/buffer buffer-size))]
      (assoc this
             :buffer buffer
             :ch (cond ex-handler (async/chan buffer transducer ex-handler)
                       transducer (async/chan buffer transducer)
                       :else (async/chan buffer)))))
  (stop [this]
    (when ch
      (async/close! ch))
    (assoc this :ch nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/defn chan-ctor
  [{:keys [buffer-size]
    :or {buffer-size 0}
    :as options}]
  (map->AsyncChannelComponent (assoc (select-keys options [:buffer
                                                           :ex-handler
                                                           :transducer])
                                     :buffer-size buffer-size)))
