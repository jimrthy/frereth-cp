(ns user
  (:require [byte-streams :as b-s]
            [clojure
             [data :as data]
             [edn :as edn]
             [repl :refer (apropos dir doc pst root-cause source)]]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.spec.test.alpha :as test]
            [clojure.test.check :refer (quick-check)]
            [clojure.test.check
             [clojure-test :refer (defspec)]
             [generators :as lo-gen]
             [properties :as props]
             [generators :as lo-gen]]
            ;; These are moderately useless under boot.
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            [frereth-cp.message :as msg]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [logging :as log]
             [specs :as shared-specs]]
            [frereth-cp.util :as utils]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]]))
