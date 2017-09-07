(def project 'frereth-cp)
(def version "0.0.1-SNAPSHOT")

(set-env! :resource-paths #{"src/clojure"}
          :source-paths   #{"dev" "dev-resources" "src/java" "test"}
          :dependencies   '[[adzerk/boot-test "RELEASE" :scope "test"]
                            [aleph "0.4.3"]
                            [org.apache.logging.log4j/log4j-core "2.8.2" :scope "test"]
                            [org.apache.logging.log4j/log4j-1.2-api "2.8.2" :scope "test"]
                            [org.clojure/clojure "1.9.0-alpha17"]
                            [org.clojure/spec.alpha "0.1.123"]
                            [org.clojure/tools.logging "0.4.0"]
                            [samestep/boot-refresh "0.1.0" :scope "test"]
                            [tolitius/boot-check "0.1.4" :scope "test"]])

(task-options!
 aot {:namespace   #{'frereth-cp.server 'frereth-cp.client}}
 pom {:project     project
      :version     version
      :description "Implement CurveCP in clojure"
      ;; TODO: Add a real website
      :url         "https://github.com/jimrthy/frereth-cp"
      :scm         {:url "https://github.com/jimrthy/frereth-cp"}
      ;; Q: Should this go into public domain like the rest
      ;; of the pieces?
      :license     {"Eclipse Public License"
                    "http://www.eclipse.org/legal/epl-v10.html"}}
 jar {:main        'frereth-cp.server
      :file        (str "frereth-cp-server-" version "-standalone.jar")})

(require '[samestep.boot-refresh :refer [refresh]])
(require '[tolitius.boot-check :as check])

(deftask build
  "Build the project locally as a JAR."
  [d dir PATH #{str} "the set of directories to write to (target)."]
  ;; Note that this approach passes the raw command-line parameters
  ;; to -main, as opposed to what happens with `boot run`
  ;; TODO: Eliminate this discrepancy
  (let [dir (if (seq dir) dir #{"target"})]
    (comp (aot) (pom) (uber) (jar) (target :dir dir))))

(deftask run
  "Run the project."
  [f file FILENAME #{str} "the arguments for the application."]
  ;; This is a leftover template from another project that I
  ;; really just copy/pasted over.
  ;; Q: Does it make any sense to keep it around?
  (require '[frereth-cp.server :as app])
  (apply (resolve 'app/-main) file))

(require '[adzerk.boot-test :refer [test]])
