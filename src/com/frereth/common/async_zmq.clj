(ns com.frereth.common.async-zmq
  "Communicate among 0mq sockets and async channels.

Strongly inspired by lynaghk's zmq-async

Not sure how much sense ever made in the first place.

It definitely seems to run against the grain of netty/aleph
and curvecp.

Keeping it around as/for reference for now, but it really
should just go away if/when I decide to really move forward
with this branch."
  (:require #_[cljeromq.common :as mq-cmn]
            #_[cljeromq.core :as mq]
            #_[cljeromq.curve]
            [clojure.core.async :as async :refer (>! >!!)]
            [clojure.edn :as edn]
            [clojure.pprint :refer (pprint)]
            [clojure.spec :as s]
            [com.frereth.common.async-component]
            [com.frereth.common.schema :as fr-sch]
            [com.frereth.common.util :as util]
            [com.frereth.common.zmq-socket :as zmq-socket]
            [com.stuartsierra.component :as component]
            [component-dsl.system :as cpt-dsl]
            [full.async :refer (<? <?? alts? go-try)]
            [hara.event :refer (raise)]
            [taoensso.timbre :as log])
  (:import [com.frereth.common.async_component AsyncChannelComponent]
           #_[com.frereth.common.zmq_socket SocketDescription]
           [com.stuartsierra.component SystemMap]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs
