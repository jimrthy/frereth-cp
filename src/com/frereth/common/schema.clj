(ns com.frereth.common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require [cljeromq.common :as mq-common]
            [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [schema.core :as s])
  (:import [java.util Date]))

(def async-channel (class (async/chan)))
(def atom-type (class (atom nil)))
(def java-byte-array mq-common/byte-array-type)
(def byte-arrays [java-byte-array])
(def korks
  "I hated this name the first few times I ran across it in argument lists.
Now that I've typed out the full keyword-or-keywords often enough, I get it."
  (s/either s/Keyword [s/Keyword]))
(def promise-type (class (promise)))
;; FIXME: This should probably come from something like
;; simple-time instead
(def time-stamp Date)
