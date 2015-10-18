(defproject com.frereth/common "0.0.1-SNAPSHOT"
  :description "Pieces that the different Frereth parts share"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  ;; TODO: Could I totally pull datomic dependencies out of everything else?
  :dependencies [;; Q: Do I really want to choose this over clj-time?
                 [clojure.joda-time "0.6.0"]
                 ;; Q: Does this make any sense in production?
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
                 [com.taoensso/timbre "4.1.4" :exclusions [org.clojure/clojure
                                                           org.clojure/tools.reader]]
                 [fullcontact/full.async "0.8.13" :exclusions [org.clojure/clojure
                                                              org.clojure/core.async]]
                 ;; This has been deprecated.
                 ;; TODO: Switch to hara
                 [im.chit/ribol "0.4.1" :exclusions [org.clojure/clojure]]
                 [io.aviso/config "0.1.8" :exclusions [org.clojure/clojure
                                                       prismatic/schema]]
                 ;; This is screwing up EDN serialization
                 ;; In particular dates.
                 ;; TODO: Make it ignore those
                 #_[mvxcvi/puget "0.8.1" :exclusions [org.clojure/clojure]]
                 [org.clojure/clojure "1.7.0"]
                 [org.clojure/core.async "0.1.346.0-17112a-alpha" :exclusions [org.clojure/clojure]]
                 ;; Desperately want something like this version for offer!
                 ;; Q: Where can I find it?
                 ;; A: So far, you have to clone it from github and install it locally.
                 ;; I'm not quite ready to inflict that on anyone who might be willing to test this sucker
                 #_[org.clojure/core.async "0.1.0-SNAPSHOT" :exclusions [org.clojure/clojure]]
                 [org.clojure/tools.reader "0.10.0" :exclusions [org.clojure/clojure]]
                 [prismatic/plumbing "0.5.0"]
                 [prismatic/schema "1.0.1"]]

  :jvm-opts [~(str "-Djava.library.path=/usr/local/lib:" (System/getenv "LD_LIBRARY_PATH"))]

  :plugins []

  :profiles {:dev {:dependencies [[org.clojure/java.classpath "0.2.2"
                                   :exclusions [org.clojure/clojure]]]
                   :source-paths ["dev"]
                   :plugins [[org.clojure/tools.namespace "0.2.11" :exclusions [org.clojure/clojure]]]}
             :uberjar {:aot :all}}
  :repl-options {:init-ns user})
