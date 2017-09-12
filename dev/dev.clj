(ns dev
  ;; TODO: Just make it go away
  "This ns is pointless"
  (:require [clojure.edn :as edn]
            [clojure.inspector :as i]
            [clojure.java.io :as io]
            [clojure.pprint :refer (pprint)]
            [clojure.reflect :as reflect]
            [clojure.repl :refer :all]  ; dir is very useful
            [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.string :as string]
            [clojure.test :as test]
            [clojure.tools.logging :as log]
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            [manifold.stream :as strm]))

(def system nil)
