(ns com.frereth.common.system
  "This is another one that doesn't make a lot of sense"
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [com.frereth.common.async-component]
            [component-dsl.system :as cpt-dsl]
            [ribol.core :refer (raise)]
            [schema.core :as s])
  (:import [com.stuartsierra.component SystemMap]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/defn build :- SystemMap
  ([description :- cpt-dsl/system-description
    options :- cpt-dsl/option-map]
   (cpt-dsl/build description options))
  ([description :- cpt-dsl/system-description]
   (build description {})))

(defn build-event-loop
  "For running as an integrated library inside the Renderer

At one point I thought I was really jumping the gun on this one.
It provides a decent example, but it really seems to just belong
inside frereth.client.

And frereth.server. And, if there's ever a 'real' stand-alone
frereth.renderer, there.

So this abstraction absolutely belongs in common.

It seems to make less sense under the system namespace, but
I'm not sure which alternatives make more sense."
  [{:keys [client-keys
           ctx-thread-count
           direction
           event-loop-name
           server-key
           socket-type
           url]
    :or {ctx-thread-count 1
         socket-type :dealer
         direction :connect}}]
  (let [url (cond-> url
              (not (:protocol url)) (assoc :protocol :tcp)
              (not (:address url)) (assoc :address [127 0 0 1])
              (not (:port url)) (assoc :port 9182))]
    (let [defaults {:event-loop {:_name event-loop-name}
                    :ex-sock {:url url
                              :direction direction
                              :sock-type socket-type}
                    :zmq-context {:thread-count ctx-thread-count}}
          description {:structure '{:event-loop com.frereth.common.async-zmq/ctor
                                    :evt-iface com.frereth.common.async-zmq/ctor-interface
                                    :ex-sock com.frereth.common.zmq-socket/ctor
                                    :in-chan com.frereth.common.async-component/chan-ctor
                                    :status-chan com.frereth.common.async-component/chan-ctor
                                    :zmq-context com.frereth.common.zmq-socket/ctx-ctor}
                       :dependencies {:evt-iface [:ex-sock :in-chan :status-chan]
                                      :event-loop {:interface :evt-iface}
                                      :ex-sock {:ctx :zmq-context}}}]
      (cpt-dsl/build description defaults))))
