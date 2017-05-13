(ns frereth-cp.schema
  (:require [clojure.spec.alpha :as s]
            [manifold.stream :as strm]))

(defn class-predicate
  "Returns a predicate to check whether an object is an instance of the supplied class.
This really seems like a bad road to go down.

TODO: At the very least, it needs its own spec."
  [klass]
  #(instance? klass %))

(let [manifold-stream-type (class strm/stream)]
  (s/def ::manifold-stream (class-predicate manifold-stream-type)))
