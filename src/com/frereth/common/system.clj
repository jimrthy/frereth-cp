(ns com.frereth.common.system
  "This is another one that doesn't make a lot of sense"
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
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

Note that I was really jumping the gun on this one.
It provides a decent example, but it really belongs inside
frereth.client.

And frereth.server. And, if there's ever a 'real' stand-alone
frereth.renderer, there.

So this abstraction absolutely belongs here in common.

It seems to make less sense under system, but I'm not sure which
alternatives make more sense."
  [{:keys [ctx-thread-count
           socket-type
           direction
           ;; TODO: Further destructure the URL?
           url]
    :or {ctx-thread-count 1
         socket-type :dealer
         direction :connect
         ;; Just pick something arbitrary
         url {:protocol :tcp
              :address [127 0 0 1]
              :port 9182}}}]
  (let [context (mq/context ctx-thread-count)
        description {:structure '{:event-loop com.frereth.common.async-zmq/ctor
                                  :ex-sock com.frereth.common.zmq-socket/ctor}
                     :dependencies {:event-loop [:ex-sock]}}]
    (cpt-dsl/build description
                   {:event-loop {:in-chan (async/chan)}
                    :ex-sock {:url url
                              :direction direction
                              :sock-type socket-type}})))
