(ns frereth.common.system
  "This is another one that doesn't make a lot of sense"
  (:require [component-dsl.system :as cpt-dsl]  ; At least try to get it included as a dependency
            [ribol.core :refer (raise)]
            [schema.core :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn build
  []
  (raise :not-implemented)
  cpt-dsl/system-description)
