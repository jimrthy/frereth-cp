(ns com.frereth.common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require [cljeromq.common :as mq-common]
            [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.spec :as s]
            [schema.core :as s2])
  (:import [java.util Date]))

(def async-channel (class (async/chan)))
(s/def ::async-channel #(instance? async-channel %))
(def atom-type (class (atom nil)))
(s/def ::atom-type #(instance? atom-type %))
(def java-byte-array
  "Very tempting to deprecate and just use the mq-common version.
But that does make it more difficult to switch the underlying
message queue implementation"
  mq-common/byte-array-type)
(s/def ::byte-array-type :cljeromq.common/byte-array-type)
(def byte-arrays
  "Deprecated: switch to the spec version instead"
  [java-byte-array])
(s/def ::byte-array-seq :cljeromq.common/byte-array-seq)
(s/def ::korks :cljeromq.common/korks)
(def korks
  "Deprecated: switch to the spec version instead"
  (s2/either s2/Keyword [s2/Keyword]))
(def promise-type (class (promise)))
(s/def ::promise? #(instance? promise-type %))

;; FIXME: This should come from something like
;; simple-time instead
(def time-stamp Date)
