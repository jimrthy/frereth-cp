(def project-name "com.frereth/cp")

(require '[clojure.java.shell :as sh])

(defn next-version [version]
  (when version
    (let [[a b] (next (re-matches #"(.*?)([\d]+)" version))]
      (when (and a b)
        (str a (inc (Long/parseLong b)))))))

(def default-version
  "Really just for running inside docker w/out git tags"
  "0.0.4-???-dirty")

(defn deduce-version-from-git
  "Avoid another decade of pointless, unnecessary and error-prone
  fiddling with version labels in source code.

  Important note: this only works if your repo has tags!
  And the tags this cares about need to be numeric. Can't
  use, e.g. 0.0.1-SNAPSHOT.

  Another interesting detail is that tags must have commit
  messages for describe to work properly:
  `git tag 0.0.2 -m 'Move forward'`"
  []
  (let [[version previous-hash commits hash dirty?]
        (next (re-matches #"(\d+\.\d+\.\d+)(-\w*)?-(\d*)-(.*?)(-dirty)?\n"
                          (:out (sh/sh "git"
                                       "describe"
                                       "--always"
                                       "--dirty"
                                       "--long"
                                       "--tags"
                                       "--match" "[0-9].*"))))]
    (if commits
      (cond
        dirty? (str (next-version version) "-" hash "-dirty")
        (pos? (Long/parseLong commits)) (str (next-version version) "-" hash)
        :otherwise version)
      default-version)))

(def project 'com.frereth/cp)

(set-env! :resource-paths #{"src/clojure"}
          :dependencies '[[adzerk/bootlaces "0.1.13" :scope "test"]
                          [adzerk/boot-test "RELEASE" :scope "test"]
                          ;; Stick with whichever version of netty this inherits.
                          ;; netty isn't shy about breaking backwards compatibility
                          ;; between build versions.
                          [aleph "0.4.7-alpha3"]
                          [com.frereth/weald "0.0.4-ga530ad0"]
                          ;; TODO: Eliminate these logging dependencies.
                          ;; I have no business imposing them on library
                          ;; users
                          #_[org.apache.logging.log4j/log4j-core "2.10.0" :scope "test"]
                          #_[org.apache.logging.log4j/log4j-1.2-api "2.10.0" :scope "test"]
                          [org.clojure/clojure "1.9.0" :exclusions [org.clojure/spec.alpha] :scope "provided"]
                          [org.clojure/spec.alpha "0.2.176"]
                          ;; FIXME: Move this to the testing task.
                          ;; Don't want to depend on it in general.
                          [org.clojure/test.check "0.10.0-alpha3" :scope "test" :exclusions [org.clojure/clojure]]
                          ;; TODO: Eliminate this dependency. It's another one
                          ;; that I really don't have any business imposing on anyone else
                          ;; Then again, we inherit it from aleph no matter what.
                          #_[org.clojure/tools.logging "0.4.1" :exclusions [org.clojure/clojure]]
                          ;; Q: Why do we need this?
                          ;; A: clojure.tools.analyzer.jvm uses it.
                          [org.clojure/tools.reader "1.3.2" :exclusions [org.clojure/clojure]]
                          ;; TODO: Move this into the dev task
                          ;; (sadly, it isn't a straight copy/paste)
                          [samestep/boot-refresh "0.1.0" :scope "test" :exclusions [org.clojure/clojure]]
                          [tolitius/boot-check "0.1.11" :scope "test" :exclusions [org.clojure/clojure]]]
          :source-paths   #{"src/java"})

(task-options!
 aot {:namespace   #{'frereth-cp.server 'frereth-cp.client}}
 jar {:main        'frereth-cp.server}
 pom {:project     project
      :description "Implement CurveCP in clojure"
      ;; TODO: Add a real website
      :url         "https://github.com/jimrthy/frereth-cp"
      :scm         {:url "https://github.com/jimrthy/frereth-cp"}
      ;; Q: Should this go into public domain like the rest
      ;; of the pieces?
      :license     {"Eclipse Public License"
                    "http://www.eclipse.org/legal/epl-v10.html"}}
 ;; This might not be generally warranted.
 push {:ensure-branch nil})

(require '[adzerk.bootlaces :refer [bootlaces! build-jar push-snapshot push-release]]
         '[adzerk.boot-test :refer [test]]
         '[boot.core :as boot]
         '[boot.pod :as pod]
         '[samestep.boot-refresh :refer [refresh]]
         '[tolitius.boot-check :as check])

(deftask set-version
  []
  (let [version (deduce-version-from-git)]
    (task-options!
     jar {:file (str "frereth-cp-" version ".jar")}
     pom {:version version})
    (bootlaces! version :dont-modify-paths? true))
  identity)

(deftask build
  "Build the project locally as a JAR."
  [d dir PATH #{str} "the set of directories to write to (target)."]
  ;; Note that this approach passes the raw command-line parameters
  ;; to -main, as opposed to what happens with `boot run`
  ;; TODO: Eliminate this discrepancy (not that it matters for
  ;; a library)
  (let [dir (if (seq dir) dir #{"target"})]
    (comp (set-version) (javac) (aot) (pom) (jar) (target :dir dir))))

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

(deftask to-clojars
  "Publish"
  []
  (comp (set-version) (javac) (build-jar) (push-release)))
