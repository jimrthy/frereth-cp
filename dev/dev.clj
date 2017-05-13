(ns dev
  "TODO: Really should figure out a way to share all the common pieces
  (hint, hint)"
  (:require [clj-time.core :as dt]
            [clojure.core.async :as async]
            [clojure.edn :as edn]
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
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            [com.stuartsierra.component :as component]
            #_[com.frereth.common.aleph :as aleph]
            #_[com.frereth.common.communication :as com-comm]
            #_[com.frereth.common.config :as cfg]
            #_[com.frereth.common.system :as sys]
            #_[com.frereth.common.util :as util]
            [component-dsl.system :as cpt-dsl]
            [hara.event :refer (raise)]))

(def +frereth-component+
  "Just to help me track which REPL is which"
  'common)

(def system nil)

(defn init
  "Constructs the current development system."
  []
  (set! *print-length* 50)
  (throw (RuntimeException. "This needs reconsideration")))

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
  ;; This pulls up a window (in the current thread) which leaves
  ;; emacs unusable. Get it at least not dying instantly from lein run,
  ;; then make this play nicely with the main window in a background
  ;; thread.
  ;; Which doesn't really work at all on a Mac: more impetus than
  ;; ever to get a REPL working there internally.
  ;; But I don't need it yet.
  (comment (raise :currently-broken))
  (try
    (refresh :after 'dev/go-go)
    (catch clojure.lang.ExceptionInfo ex
      (pprint ex)
      (println "Refresh failed"))))
