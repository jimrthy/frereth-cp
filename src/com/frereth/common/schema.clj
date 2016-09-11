(ns com.frereth.common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require [cljeromq.common :as mq-common]
            [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.spec :as s])
  (:import [java.util Date]))

(defn class-predicate
  "Returns a predicate to check whether an object is an instance of the supplied class.
This really seems like a bad road to go down.

TODO: At the very least, it needs its own spec."
  [klass]
  #(instance? klass %))

(def async-channel-type (class (async/chan)))
(s/def ::async-channel (class-predicate async-channel-type))
(def atom-type (class (atom {})))
(s/def ::atom-type (class-predicate atom-type))

;; Very tempting to deprecate and just use the mq-common versions.
;; But that does make it more difficult to switch the underlying
;; message queue implementation
(def java-byte-array cljeromq.common/byte-array-type)
(s/def ::byte-array-type :cljeromq.common/byte-array-type)
(s/def ::byte-array-seq :cljeromq.common/byte-array-seq)
(s/def ::korks :cljeromq.common/korks)

(def promise-type (class (promise)))
(s/def ::promise? (class-predicate promise-type))

;; FIXME: This should come from something like
;; simple-time instead
(s/def ::time-stamp (class-predicate Date))
