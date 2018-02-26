(ns frereth-cp.shared.specs
  "For specs that make sense to share among all the pieces"
  (:require [clojure.spec.alpha :as s]
            [clojure.test.check.generators :as lo-gen]
            [clojure.test.check.rose-tree :as rose]
            [frereth-cp.util :as utils]))

(defn class-predicate
  "Returns a predicate to check whether an object is an instance of the supplied class.
This really seems like a bad road to go down."
  [klass]
  #(instance? klass %))

(s/def ::atom (class-predicate (class (atom nil))))

(def ^Integer key-length 32)
;; I really don't want to reference generators in here.
;; Much less something like rose-tree.
;; Those sorts of details really belong in a test ns.
;; But it seems to smell to split them up.
(s/def ::crypto-key (s/with-gen (s/and bytes?
                                       #(= (count %) key-length))
                      #(lo-gen/->Generator (fn [_ _]
                                             (rose/make-rose (utils/random-secure-bytes key-length) [])))))

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
                                 ;; Q: Is there any reason to retain this?
                                 ::public-short]))

(def header-length 8)
(defn random-header
  []
  (byte-array (take header-length
                    (repeatedly #(- (rand-int 256) 128)))))
(comment (random-header))

(s/def ::prefix
  (s/and bytes?
         #(= (count %) header-length)))

(def extension-length 16)
(s/def ::extension (s/and bytes?
                          #(= (count %) extension-length)))
(s/def ::srvr-xtn ::extension)
(s/def ::clnt-xtn ::extension)
