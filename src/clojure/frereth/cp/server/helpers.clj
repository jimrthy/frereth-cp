(ns frereth.cp.server.helpers
  "Utility functions that are generally useful for Curve servers"
  (:require [frereth.cp.shared :as shared]
            [frereth.cp.shared.constants :as K]))

(defn hide-long-arrays
  "Try to make pretty printing less obnoxious

  By hiding the vectors that take up huge amounts of screen space"
  [state]
  (-> state
      ;; Avoiding a circular dependency with server.state
      ;; forces me to spell out the full ns hierarchy.
      ;; Nesting it this deeply was a mistake.
      (assoc-in [:com.frereth.common.curve.server.state/current-client
                 :com.frereth.common.curve.server.state/message] "...")
      (assoc-in [::shared/my-keys ::K/srvr-name] "...decode this...")))

(defn one-minute
  "In nanoseconds"
  ([]
   (* 60 shared/nanos-in-second))
  ([now]
   (+ (one-minute) now)))
