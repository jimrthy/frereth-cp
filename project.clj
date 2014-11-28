(defproject frereth-common "0.0.1-SNAPSHOT"
  :description "Pieces that the different Frereth parts share"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  ;; TODO: Could I totally pull datomic dependencies out of everything else?
  :dependencies [[com.stuartsierra/component "0.2.2"]
                 [com.taoensso/timbre "3.3.1" :exclusions [org.clojure/tools.reader]]
                 [im.chit/ribol "0.4.0"]
                 [mvxcvi/puget "0.6.4"]
                 [org.clojure/clojure "1.6.0"]
                 [prismatic/schema "0.3.3"]]

  :profiles {:dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/tools.namespace "0.2.7"]
                                  [org.clojure/java.classpath "0.2.2"]]}
             :uberjar {:aot :all}}
  :repl-options {:init-ns user})
