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

(defn build-library
  "For running as an integrated library inside the Renderer"
  [{:keys [:ctx-thread-count
           :socket-type
           :direction
           :url]
    :or {:ctx-thread-count 1
         :socket-type :dealer
         :direction :connect
         ;; Just pick something arbitrary
         :url "tcp://localhost:9182"}}]
  (raise :not-implemented)
  (let [context (mq/context ctx-thread-count)
        socket (mq/socket! socket-type)
        description {:structure '{:event-loop com.frereth.common.async-zmq/ctor}
                     :dependencies {}}]
    (if (= :bind direction)
      (mq/bind! socket url)
      (mq/connect! socket url))
    (cpt-dsl/build description {:event-loop {:mq-ctx context
                                             :ex-sock socket
                                             :in-chan (async/chan)}})))
