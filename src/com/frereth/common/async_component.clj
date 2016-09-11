(ns com.frereth.common.async-component
  "Component wrapper around core.async pieces

So I can use them in Systems without really thinking
about the bigger picture.

  No, this probably isn't a very good idea"
  (:require [clojure.core.async :as async]
            [clojure.spec :as s]
            [com.frereth.common.schema :as frereth-schema]
            [com.stuartsierra.component :as component]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

(defrecord AsyncChannelComponent [buffer
                                  buffer-size
                                  ch
                                  transducer
                                  ex-handler]
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
;; Q: Is there a better spec for this?
(s/def ::buffer :com.frereth.common.schema/async-channel)
(s/def ::buffer-size int?)
(s/def ::ch :com.frereth.common.schema/async-channel)
;;; Q: What is the spec for this, really?
;;; A: Well...it's really a function w/ 3 arities that
;;; transforms one reducing function into another
;;; i.e.
;;; (whatever, input -> whatever) -> (whatever, input -> whatever)
;;; For now, just punt on that one
(s/def ::transducer identity)
(s/def ::async-channel (s/keys :unq-req [::ch]
                               :unq-opt [::buffer
                                         ::buffer-size
                                         ::ex-handler
                                         ::transducer]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef chan-ctor
        :args (s/cat :options (s/keys :unq-opt [:buffer-size
                                                :buffer
                                                :ex-handler
                                                :transducer]))
        :ret ::async-channel)
(defn chan-ctor
  [{:keys [buffer-size]
    :or {buffer-size 0}
    :as options}]
  (map->AsyncChannelComponent (assoc (select-keys options [:buffer
                                                           :ex-handler
                                                           :transducer])
                                     :buffer-size buffer-size)))
