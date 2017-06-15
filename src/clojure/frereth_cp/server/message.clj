(ns frereth-cp.server.message
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.schema :as specs]
            [frereth-cp.server.state :as state]
            [manifold.stream :as strm]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal helpers

(defn child-reader
  [buffer]
  ;; This really needs to encompass lines 453-495 of curvecpserver.c
  ;; I think I really should be seeing this exception now, when my
  ;; unit test echoes back its initial message.
  (throw (RuntimeException. "Where is this ball getting dropped?")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef add-listener!
        :args (s/cat :state ::state/state
                     :child ::state/child-interaction)
        :ret ::specs/manifold-stream)
(defn add-listener!
  [state
   {:keys [::state/client-ip
           ::state/client-port
           ::state/read<-child]
    :as child}]
  (strm/consume child-reader
                read<-child))
