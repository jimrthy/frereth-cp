(ns frereth-cp.shared.specs
  "For specs that make sense to share among all the pieces"
  (:require [clojure.spec.alpha :as s]))

(defn class-predicate
  "Returns a predicate to check whether an object is an instance of the supplied class.
This really seems like a bad road to go down."
  [klass]
  #(instance? klass %))

(s/def ::atom (class-predicate (class (atom nil))))

(s/def ::public-long bytes?)
(s/def ::public-short bytes?)
(s/def ::peer-keys (s/keys :req [::public-long
                                 ::public-short]))
