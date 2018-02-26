(ns user
  (:require [clojure.edn :as edn]
            [clojure.repl :refer (apropos dir doc pst root-cause source)]
            [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test.check.generators :as lo-gen]
            ;; These are moderately useless under boot.
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm]))
