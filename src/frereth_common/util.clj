(ns frereth-common.util
  (:require [puget.printer :as puget]))

;; Global functions like this are bad.
;; Especially since I'm looking at a
;; white terminal background, as opposed to what
;; most seem to expect
;; TODO: Put this inside a component's start
;; instead
(puget/set-color-scheme! :keyword [:bold :green])

(defn pretty
  [& os]
  (with-out-str (apply puget/cprint os)))
