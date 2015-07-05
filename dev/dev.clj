(ns dev
  "TODO: Really should figure out a way to share all the common pieces
  (hint, hint)"
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.inspector :as i]
            [clojure.string :as str]
            [clojure.pprint :refer (pprint)]
            [clojure.repl :refer :all]  ; dir is very useful
            [clojure.test :as test]
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            [com.stuartsierra.component :as component]
            [com.frereth.common.config :as cfg]
            [com.frereth.common.system :as sys]
            [com.frereth.common.util :as util]
            [ribol.core :refer (raise)]))

;; Because this seems to be the only namespace I ever actually
;; use in here, and I'm tired of typing it out because it's
;; ridiculously long
(require '[com.frereth.common.async-zmq-test :as azt])

(def system nil)

(defn init
  "Constructs the current development system."
  []
  (set! *print-length* 50)

  (let [ctx (mq/context 4)
        socket-pair (mq/build-internal-pair! ctx)
        reader (fn [sock]
                 (println "Fake system reading")
                 (mq/raw-recv! sock))
        writer (fn [sock msg]
                 (println "Fake system sending")
                 (mq/send! sock msg))
        parameters-tree {:event-loop {:mq-ctx ctx
                                      :ex-sock (:lhs socket-pair)
                                      :in-chan (async/chan)
                                      :external-reader reader
                                      :external-writer writer}}
        config {:structure '{:event-loop com.frereth.common.async-zmq/ctor}
                :dependencies []}]
    (alter-var-root #'system
                    (constantly (assoc (sys/build config parameters-tree)
                                       :fake-external (:rhs socket-pair))))))

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
