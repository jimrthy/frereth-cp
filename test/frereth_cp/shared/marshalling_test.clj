(ns frereth-cp.shared-test
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer (are is deftest testing)]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.marshal :as marshal]))

(deftest serialization-round-trip
  ;; initiate-packet-spec probably isn't a good choice for starting,
  ;; since it has the variable-length message field
  (let [vouch-descriptions (gen/sample (s/gen ::K/initiate-packet-spec))
        encoded (map (fn [fields]
                       (marshal/compose ::K/initiate-packet-dscr fields)))]
    (dorun (map #(= %1
                    (marshal/decompose ::K/initiate-packet-dscr %2))
                vouch-descriptions
                encoded))))

(comment
  (s/exercise ::K/initiate-packet-spec)
  (gen/generate (s/gen ::K/hello-spec))
  (gen/sample (s/gen ::K/prefix))
  (gen/sample (gen/bytes))
  (gen/sample (gen/such-that (s/and #(= K/extension-length (count %))
                                    identity)
                             (gen/bytes)))
  (gen/generate (s/with-gen ::K/prefix
                  (gen/such-that (s/and #(= K/extension-length (count %))
                                        identity)
                                 #_(gen/vector gen/byte K/extension-length)
                                 (gen/bytes K/extension-length))))
  (map count (gen/sample (gen/bytes 16)))
  )
