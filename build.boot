(def project 'frereth-cp)
(def version "0.0.1-SNAPSHOT")

;; TODO: Add a dependency on weald and refactor away the local copy
;; of shared.logging.
(set-env! :resource-paths #{"src/clojure"}
          :dependencies '[[adzerk/boot-test "RELEASE" :scope "test"]
                          ;; Default uses a version of netty that's about 6 months
                          ;; old.
                          ;; That might not be a huge deal...but there have been
                          ;; 6 bug fix releases since then.
                          ;; STARTED: Switch to newer version and see how it works.
                          #_[aleph "0.4.4" :exclusions [io.netty/netty-all
                                                      org.clojure/tools.logging]]
                          ;; Alt: Try this instead
                          [aleph "0.4.7-alpha2"]
                          ;; Note that 5.0.0 is up to alpha2
                          [io.netty/netty-all "4.1.20.Final"]
                          ;; TODO: Eliminate these logging dependencies.
                          ;; I have no business imposing them on library
                          ;; users
                          [org.apache.logging.log4j/log4j-core "2.10.0" :scope "test"]
                          [org.apache.logging.log4j/log4j-1.2-api "2.10.0" :scope "test"]
                          [org.clojure/clojure "1.10.0-beta3" :exclusions [org.clojure/spec.alpha]]
                          [org.clojure/spec.alpha "0.2.176"]
                          ;; FIXME: Move this to the testing task.
                          ;; Don't want to depend on it in general.
                          [org.clojure/test.check "0.10.0-alpha2" :scope "test" :exclusions [org.clojure/clojure]]
                          ;; TODO: Eliminate this dependency. It's another one
                          ;; that I really don't have any business imposing on anyone else
                          [org.clojure/tools.logging "0.4.0" :exclusions [org.clojure/clojure]]
                          ;; TODO: Move this into the dev task
                          ;; (sadly, it isn't a straight copy/paste)
                          [samestep/boot-refresh "0.1.0" :scope "test" :exclusions [org.clojure/clojure]]
                          [tolitius/boot-check "0.1.9" :scope "test" :exclusions [org.clojure/clojure]]]
          :source-paths   #{"src/java"})

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
(require '[adzerk.boot-test :refer [test]])
(require '[boot.pod :as pod])

(deftask build
  "Build the project locally as a JAR."
  [d dir PATH #{str} "the set of directories to write to (target)."]
  ;; Note that this approach passes the raw command-line parameters
  ;; to -main, as opposed to what happens with `boot run`
  ;; TODO: Eliminate this discrepancy
  (let [dir (if (seq dir) dir #{"target"})]
    (comp (javac) (aot) (pom) (jar) (target :dir dir))))

(deftask check-conflicts
  "Verify there are no dependency conflicts."
  []
  (with-pass-thru fs
    (require '[boot.pedantic :as pedant])
    (let [dep-conflicts (resolve 'pedant/dep-conflicts)]
      (if-let [conflicts (not-empty (dep-conflicts pod/env))]
        (throw (ex-info (str "Unresolved dependency conflicts. "
                             "Use :exclusions to resolve them!")
                        conflicts))
        (println "\nVerified there are no dependency conflicts.")))))

(deftask dev
  "Add the dev resources to the mix"
  []
  (merge-env! :source-paths #{"dev" "dev-resources"})
  identity)

(deftask testing
  "Add pieces for testing"
  []
  (merge-env! :dependencies '[[gloss "0.2.6"
                               :scope "test"
                               :exclusions [byte-streams
                                            io.aleph/dirigiste
                                            manifold
                                            org.clojure/tools.logging
                                            potemkin
                                            riddley]]]
              :source-paths #{"test"})
  identity)

(deftask cider-repl
  "Set up a REPL for connecting from CIDER"
  [p port PORT int]
  ;; Just because I'm prone to forget one of the vital helper steps
  ;; Note that this would probably make more sense under profile.boot.
  ;; Except that doesn't have access to the defined in here, such
  ;; as...well, almost any of what it actually uses.
  ;; Q: Should they move to there also?
  (let [port (or port 32767)]
    (comp (dev) (testing) (check-conflicts) (cider) (javac) (repl :port port :bind "0.0.0.0"))))

(deftask run
  "Run the project."
  [f file FILENAME #{str} "Application arguments passed to main."]
  ;; This is a leftover template from another project that I
  ;; really just copy/pasted over.
  ;; Q: Does it make any sense to keep it around?
  (require '[frereth-cp.server :as app])
  (apply (resolve 'app/-main) file))
