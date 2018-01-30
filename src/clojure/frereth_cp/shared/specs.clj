(ns frereth-cp.shared.specs
  "For specs that make sense to share among all the pieces"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.shared.constants :as K]))

(defn class-predicate
  "Returns a predicate to check whether an object is an instance of the supplied class.
This really seems like a bad road to go down."
  [klass]
  #(instance? klass %))

(s/def ::atom (class-predicate (class (atom nil))))

(s/def ::crypto-key (s/and bytes?
                           #(= (count %) K/key-length)))

;; public long-term key
(s/def ::public-long ::crypto-key)
;; public short-term key
(s/def ::public-short ::crypto-key)

;; secret long-term key
(s/def ::secret-long ::crypto-key)
;; secret short-term key
(s/def ::secret-short ::crypto-key)

(s/def ::my-long-keys (s/keys :req [::public-long
                                    ::secret-long]))
(s/def ::my-short-keys (s/keys :req [::public-short
                                     ::secret-short]))

;; Keys of the peer with which we're communicating
(s/def ::peer-keys (s/keys :req [::public-long
                                 ::public-short]))
