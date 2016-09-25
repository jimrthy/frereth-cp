(ns com.frereth.common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require [cljeromq.common :as mq-common]
            [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.spec :as s]
            [com.stuartsierra.component])
  (:import [com.stuartsierra.component SystemMap]
           [java.util Date]))

(defn class-predicate
  "Returns a predicate to check whether an object is an instance of the supplied class.
This really seems like a bad road to go down.

TODO: At the very least, it needs its own spec."
  [klass]
  #(instance? klass %))

;;; These next 2 are duplicated in substratum.util.
;;; Very tempting to create a common library to eliminate
;;; the Copy/Paste.
;;; Not quite tempting enough to convince me that it would be
;;; worthwhile.
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

;; Note that the original schema version is copy/pasted into web's frereth.globals.cljs
;; And it doesn't work
;; Q: What's the issue? (aside from the fact that it's experimental)
;; TODO: Ask on the mailing list
(s/def ::generic-id (s/or :keyword keyword?
                          :string string?
                          :uuid ::uuid))

;; Q: Is this worth really defining?
(s/def ::system-map (class-predicate SystemMap))
