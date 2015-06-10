(ns com.frereth.common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require [clojure.core.async :as async]
            [schema.core :as s])
  (:import [java.util Date]))

(def async-channel (class (async/chan)))
(def java-byte-array (Class/forName "[B"))
;; FIXME: This should probably come from something like
;; simple-time instead
(def time-stamp Date)
