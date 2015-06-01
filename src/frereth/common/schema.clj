(ns frereth-common.schema
  "Prismatic schema definitions that are shared pretty much everywhere"
  (:require [clojure.core.async :as async]
            [schema.core :as s]))

(def async-chan (class (async/chan)))
