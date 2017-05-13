(ns com.frereth.common.zmq-socket
  "This should be a wrapper interface that hides as many low-level queue
  implementation details as possible.

  Actually, there needs to be a higher level interface for that.
  This might be a great use case for protocols."
  (:require #_[cljeromq
             [common :as mq-cmn]
             [core :as mq]
             [curve :as curve]]
            [clojure.pprint :refer (pprint)]
            [clojure.spec :as s]
            [com.frereth.common
             [schema :as schema]
             [util :as util]]
            [com.frereth.common.curve.shared :as curve]
            [com.stuartsierra.component :as component]
            [taoensso.timbre :as log])
  (:import [clojure.lang ExceptionInfo]
           #_[org.zeromq ZMQException]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

(s/def ::ctx #_:cljeromq.common/context any?)
(s/def ::thread-count int?)
(s/def ::context-wrapper (s/keys :req-un [::ctx
                                          ::thread-count]))

(s/def ::client-keys (s/nilable ::curve/long-pair))
;; TODO: Move this into schema instead
(s/def ::port (s/nilable (s/and nat-int? #(< % 65536))))
(s/def ::public-server-key ::curve/public-key)
(s/def ::private-server-key ::curve/secret-key)
