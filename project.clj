(defproject com.frereth/common "0.0.1-SNAPSHOT"
  :description "Pieces that the different Frereth parts share"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  ;; TODO: Could I totally pull datomic dependencies out of everything else?
  :dependencies [;; Q: Does this make any sense in production?
                 ;; A: Well, it makes sense for the general runtime which
                 ;; is the primary goal.
                 [com.cemerick/pomegranate "0.3.0" :exclusions [org.codehaus.plexus/plexus-utils]]
                 ;; For now, this next library needs to be distributed to
                 ;; a local maven repo.
                 ;; It seems like it should really take care of its handler
                 ;; ...except that very likely means native libraries, so
                 ;; it gets more complicated. Still, we shouldn't be worrying
                 ;; about details like jeromq vs jzmq here.
                 ;; Q: Does the reference to this really belong in here?
                 ;; After all, there's a pretty strong chance that "only"
                 ;; server and client will actually use it.
                 ;; Then again, if that happens, web will only inherit
                 ;; this through client. And, if it doesn't, renderer
                 ;; will need this to talk to the stand-alone "client."
                 ;; So the short answer is "Yes"
                 [com.jimrthy/cljeromq "0.1.0-SNAPSHOT" :exclusions [com.stuartsierra/component
                                                                     org.clojure/clojure
                                                                     prismatic/schema]]
                 [com.jimrthy/component-dsl "0.1.1-SNAPSHOT" :exclusions [org.clojure/clojure]]
                 [com.stuartsierra/component "0.2.3"]
                 [com.taoensso/timbre "3.4.0" :exclusions [#_com.taoensso/encore
                                                           org.clojure/clojure
                                                           org.clojure/tools.reader]]
                 [fullcontact/full.async "0.4.22" :exclusions [org.clojure/clojure
                                                               org.clojure/core.async]]
                 [im.chit/ribol "0.4.0" :exclusions [org.clojure/clojure]]
                 [io.aviso/config "0.1.1" :exclusions [org.clojure/clojure
                                                       prismatic/schema]]
                 [mvxcvi/puget "0.8.1" :exclusions [org.clojure/clojure]]
                 [org.clojure/clojure "1.7.0-RC1"]
                 [org.clojure/core.async "0.1.346.0-17112a-alpha" :exclusions [org.clojure/clojure]]
                 [org.clojure/tools.reader "0.9.2" :exclusions [org.clojure/clojure]]
                 [prismatic/plumbing "0.4.4"]
                 [prismatic/schema "0.4.3"]]

  :jvm-opts [~(str "-Djava.library.path=/usr/local/lib:" (System/getenv "LD_LIBRARY_PATH"))]

  :profiles {:dev {:source-paths ["dev"]
                   :plugins [[org.clojure/tools.namespace "0.2.10" :exclusions [org.clojure/clojure]]
                             [org.clojure/java.classpath "0.2.2" :exclusions [org.clojure/clojure]]]}
             :uberjar {:aot :all}}
  :repl-options {:init-ns user})
