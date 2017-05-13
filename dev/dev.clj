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
            [com.frereth.common.aleph :as aleph]
            [com.frereth.common.communication :as com-comm]
            [com.frereth.common.config :as cfg]
            [com.frereth.common.system :as sys]
            [com.frereth.common.util :as util]
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
  (throw (RuntimeException. "This needs reconsideration"))
  (comment
    (let [ctx (mq/context 4)
          socket-pair (mq/build-internal-pair! ctx)
          reader (fn [sock]
                   (println "Fake system reading")
                   (mq/raw-recv! sock))
          writer (fn [sock msg]
                   (println "Fake system sending")
                   (mq/send! sock msg))
          parameters-tree {:event-loop {:context ctx
                                        :ex-sock (:lhs socket-pair)
                                        :in-chan (async/chan)
                                        :external-reader reader
                                        :external-writer writer}}
          ;; Note that this fails on startup:
          ;; since it's specifically designed to be a component nested among others,
          ;; it fails when I try to create it at the top level.
          ;; This is a bug/design flaw, but not really a primary concern.
          ;; Actually, for this scenario, I could just call it directly and build a component
          ;; from the definition the event-loop ctor returns
          config #:component-dsl.system {:structure '{:event-loop com.frereth.common.async-zmq/ctor}
                                         :dependencies []}]
      (alter-var-root #'system
                      (constantly (assoc (cpt-dsl/build config parameters-tree)
                                         ;; fake-external is here to let me interact with the
                                         ;; event loop.
                                         :fake-external (:rhs socket-pair)))))))

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
