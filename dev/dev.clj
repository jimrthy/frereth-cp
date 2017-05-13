(ns dev
  "TODO: I think I probably want/need something along the liens of Components or Integrant

Although tools.namespace may work just fine for what actually happens here"
  (:require [clojure.edn :as edn]
            [clojure.inspector :as i]
            [clojure.java.io :as io]
            [clojure.pprint :refer (pprint)]
            [clojure.reflect :as reflect]
            [clojure.repl :refer :all]  ; dir is very useful
            [clojure.spec :as s]
            [clojure.spec.gen :as gen]
            [clojure.string :as string]
            [clojure.test :as test]
            [clojure.tools.logging :as log]
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]))

(def +frereth-component+
  "Just to help me track which REPL is which"
  'common)

(def system nil)

(defn init
  "Constructs the current development system."
  []
  (set! *print-length* 50)
  (throw (RuntimeException. "This needs reconsideration")))

(comment
  (defn start
    "Starts the current development system."
    []
    (alter-var-root #'system component/start))

  (defn stop
    "Shuts down and destroys the current development system."
    []
    (alter-var-root #'system
                    (fn [s] (when s (component/stop s)))))

  (defn go-go
    "Initializes the current development system and starts it running.
  Can't just call this go: that conflicts with a macro from core.async."
    []
    (println "Initializing system")
    (init)
    (println "Restarting system")
    (start))

  (defn reset []
    (println "Stopping")
    (stop)
    (println "Refreshing namespaces")
    (try
      (refresh :after 'dev/go-go)
      (catch clojure.lang.ExceptionInfo ex
        (pprint ex)
        (println "Refresh failed")))))
