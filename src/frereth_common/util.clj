(ns frereth-common.util
  (:require [puget.printer :as puget]
            [ribol.core :refer (raise)]
            [schema.core :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; TODO

;; Global functions like this are bad.
;; Especially since I'm looking at a
;; white terminal background, as opposed to what
;; most seem to expect
;; TODO: Put this inside a component's start
;; instead
(puget/set-color-scheme! :keyword [:bold :green])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn describe-annotations
  [as]
  (raise :not-implemented))

(s/defn interpret-modifiers :- s/Keyword
  [ms :- s/Int]
  (raise :not-implemented))

(defn describe-field
  [f]
  {:name (.getName f)
   :annotations (map describe-annotations (.getDeclaredAnnotations f))
   :modifiers (interpret-modifiers (.getModifiers f))})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn pretty
  [& os]
  (with-out-str (apply puget/cprint os)))

(defn dir
  [something]
  (let [k (class something)
        fields (.getDeclaredFields k)
        useful-fields (map describe-field fields)
        methods (.getDeclaredMethods k)]
    {:fields useful-fields}
    (raise :not-implemented)))
