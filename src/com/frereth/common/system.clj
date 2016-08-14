(ns com.frereth.common.system
  "This is another one that doesn't make a lot of sense"
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [com.frereth.common.async-component]
            [component-dsl.system :as cpt-dsl]
            [hara.event :refer (raise)]
            [schema.core :as s])
  (:import [com.stuartsierra.component SystemMap]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/defn build :- SystemMap
  "TODO: Just make this go away as pointless"
  ([description :- cpt-dsl/system-description
    options :- cpt-dsl/option-map]
   (cpt-dsl/build description options))
  ([description :- cpt-dsl/system-description]
   (build description {})))

(s/defn build-event-loop :- SystemMap
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
           context
           event-loop-name
           server-key
           url]
    :or {socket-type :dealer
         direction :connect}}]
  (let [url (cond-> url
              (not (:protocol url)) (assoc :protocol :tcp)
              (not (:address url)) (assoc :address [127 0 0 1])
              (not (:port url)) (assoc :port 9182))]
    (let [defaults {:event-loop {:_name event-loop-name}
                    :ex-sock {:url url
                              :direction direction
                              :sock-type socket-type
                              :ctx context}}
          description {:structure '{:event-loop com.frereth.common.async-zmq/ctor
                                    :evt-iface com.frereth.common.async-zmq/ctor-interface
                                    :ex-chan com.frereth.common.async-component/chan-ctor
                                    :ex-sock com.frereth.common.zmq-socket/ctor
                                    :in-chan com.frereth.common.async-component/chan-ctor
                                    :status-chan com.frereth.common.async-component/chan-ctor}
                       :dependencies {:evt-iface [:ex-sock :in-chan :status-chan]
                                      :event-loop {:interface :evt-iface
                                                   :ex-chan :ex-chan}}}
          default-result (cpt-dsl/build description defaults)])))
