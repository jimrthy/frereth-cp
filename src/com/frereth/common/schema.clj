(ns com.frereth.common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require #_[cljeromq.common :as mq-common]
            #_[cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.spec :as s]
            [com.stuartsierra.component]
            [manifold.stream :as strm])
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
(let [async-channel-type
      (class (async/chan))]
  (s/def ::async-channel (class-predicate async-channel-type)))
(let [manifold-stream-type (class strm/stream)]
  (s/def ::manifold-stream (class-predicate manifold-stream-type)))

(def atom-type (class (atom {})))
(s/def ::atom-type (class-predicate atom-type))

(comment
  ;; Very tempting to deprecate and just use the mq-common versions.
  ;; But that does make it more difficult to switch the underlying
  ;; message queue implementation
  (def java-byte-array cljeromq.common/byte-array-type)
  (s/def ::byte-array-seq :cljeromq.common/byte-array-seq)
  (s/def ::korks :cljeromq.common/korks))
;; As a step toward moving away from that completely,
;; just copy/paste those definitions I was referencing:
(def java-byte-array
  "This isn't a spec. Use bytes? for that.
But we do need it for places like method dispatch"
  (Class/forName "[B"))

(s/def ::byte-array-seq (s/coll-of bytes?))
;; I hated this name the first few times I ran across it in argument lists.
;; Now that I've typed out the full keyword-or-keywords often enough, I get it.
(s/def ::korks (s/or :single-key keyword?
                     :multi-keys (s/coll-of keyword?)))

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
                          :uuid uuid?))

;; Q: Is this worth really defining?
(s/def ::system-map (class-predicate SystemMap))
