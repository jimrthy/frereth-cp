(defproject frereth-common "0.0.1-SNAPSHOT"
  :description "Pieces that the different Frereth parts share"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  ;; Q: Could I totally pull datomic dependencies out of everything else
  ;; by putting them in here?
  ;; TODO: Pick a date library and use it.
  :dependencies [;; TODO: Switch to something like component-dsl
                 [com.stuartsierra/component "0.3.1"]
                 [com.taoensso/timbre "4.3.1" :exclusions [org.clojure/tools.reader]]
                 ;; TODO: Switch to hara-events
                 [im.chit/ribol "0.4.1"]
                 [mvxcvi/puget "1.0.0"]
                 [org.clojure/clojure "1.8.0"]
                 [prismatic/schema "1.1.1"]]

  :profiles {:dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/tools.namespace "0.2.10"]
                                  [org.clojure/java.classpath "0.2.3"]]}
             :uberjar {:aot :all}}
  :repl-options {:init-ns user})
