(defproject frereth-cp "0.0.1-SNAPSHOT"
  :description "Implement CurveCP in clojure"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[aleph "0.4.1"]
                 [org.clojure/clojure "1.9.0-alpha16"]
                 [org.clojure/spec.alpha "0.1.108"]]
  :java-source-paths ["src/java"]
  ;; Pretty sure this was only ever involved for the sake of jzmq.
  ;; TODO: Verify that and then hopefully make it go away
  :jvm-opts [~(str "-Djava.library.path=/usr/local/lib:" (System/getenv "LD_LIBRARY_PATH"))]

  :profiles {:dev {:dependencies [[org.clojure/test.check "0.9.0"]
                                  [org.clojure/tools.namespace "0.2.11"]]
                   ;; Q: Why do I have tools.namespace under both dev-dependencies and plugins?
                   :plugins [[org.clojure/tools.namespace "0.2.11" :exclusions [org.clojure/clojure]]]
                   :source-paths ["dev"]}
             :uberjar {:aot :all}}
  :repl-options {:init-ns user
                 :timeout 120000}
  :source-paths ["src/clojure"])
