(ns com.frereth.common.curve.server.helpers
  "Utility functions that are generally useful for Curve servers"
  (:require [clojure.spec :as s]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.curve.shared.constants :as K]))

(defn hide-long-arrays
  "Try to make pretty printing less obnoxious

  By hiding the vectors that take up huge amounts of screen space"
  [state]
  (-> state
      (assoc-in [:com.frereth.common.curve.state/current-client
                 :com.frereth.common.curve.state/message] "...")
      (assoc-in [::shared/packet-management ::shared/packet] "...")
      (assoc-in [::shared/my-keys ::K/server-name] "...decode this...")
      (assoc #_[::message "..."]
             ::shared/working-area "...")))

(defn one-minute
  ([]
   (* 60 shared/nanos-in-second))
  ([now]
   (+ (one-minute) now)))
