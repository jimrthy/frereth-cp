(ns com.frereth.common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [schema.core :as s])
  (:import [java.util Date]))

(def async-channel (class (async/chan)))
(def atom-type (class (atom nil)))
(def java-byte-array mq/byte-array-class)
(def korks
  "I hated this name the first few times I ran across it in argument lists.
Now that I've typed out the full keyword-or-keywords often enough, I get it."
  (s/either s/Keyword [s/Keyword]))
;; FIXME: This should probably come from something like
;; simple-time instead
(def time-stamp Date)
