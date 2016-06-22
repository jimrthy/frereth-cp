(defproject com.frereth/common "0.0.1-SNAPSHOT"
  :description "Pieces that the different Frereth parts share"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  ;; Q: Could I totally pull datomic dependencies out of everything else
  ;; by putting them in here?
  ;; A: Probably. But it would be a foolish choice. The web and client components
  ;; really shouldn't have access to that sort of thing.
  ;; TODO: Pick a date library and use it.
  :dependencies [;; Q: Do I really want to choose this over clj-time?
                 ;; A: No.
                 ;; Better Q: Why is this mentioned here at all?
                 [clojure.joda-time "0.7.0"]
                 ;; Q: Does this make any sense in production?
                 ;; A: Well, it makes sense for the general runtime which
                 ;; is the primary goal.
                 ;; It doesn't seem to belong everywhere, but I'm not
                 ;; sure which pieces won't need to update CLASSPATH on
                 ;; the fly.
                 ;; Maybe not the renderer, but that may where it actually
                 ;; makes the most sense.
                 ;; Including this is strictly speculative at this point,
                 ;; but it really is a major part of The Point.
                 [com.cemerick/pomegranate "0.3.1" :exclusions [org.codehaus.plexus/plexus-utils]]
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
                 ;; Longer answer is "Do I really want to depend on a native library?"
                 ;; This answer to that question is rapidly turning to "No, but..."
                 ;; It does make sense for the client/server (until/unless I just swap
                 ;; it out for hornetq), but I'm writing an app that needs functionality
                 ;; implemented in here, and I really don't want to install this for it.
                 [com.jimrthy/cljeromq "0.1.0-SNAPSHOT" :exclusions [com.stuartsierra/component
                                                                     org.clojure/clojure
                                                                     prismatic/schema]]
                 [com.jimrthy/component-dsl "0.1.1-SNAPSHOT" :exclusions [org.clojure/clojure]]
                 [com.taoensso/timbre "4.4.0" :exclusions [io.aviso/pretty
                                                           org.clojure/clojure
                                                           org.clojure/tools.reader]]
                 [fullcontact/full.async "0.9.0" :exclusions [org.clojure/clojure
                                                              org.clojure/core.async]]
                 ;; This has been deprecated.
                 ;; TODO: Switch to hara-events
                 [im.chit/ribol "0.4.1" :exclusions [org.clojure/clojure]]
                 ;; Note that this pulls in weavejester's medley, making it available
                 [io.aviso/config "0.1.13" :exclusions [org.clojure/clojure
                                                        prismatic/schema]]
                 ;; This is screwing up EDN serialization
                 ;; In particular dates.
                 ;; TODO: Make it ignore those
                 ;; Q: Has the situation improved in the months I've been ignoring it?
                 #_[mvxcvi/puget "1.0.0" :exclusions [org.clojure/clojure]]
                 ;; 1.9.0-alpha5 breaks async-zmq
                 ;; TODO: Fix that
                 #_[org.clojure/clojure "1.8.0"]
                 [org.clojure/clojure "1.9.0-alpha5"]
                 [org.clojure/core.async "0.2.385" :exclusions [org.clojure/clojure
                                                                org.clojure/tools.analyzer]]
                 [org.clojure/tools.analyzer "0.6.9"]
                 [org.clojure/tools.reader "1.0.0-beta2" :exclusions [org.clojure/clojure]]
                 [prismatic/plumbing "0.5.3"]
                 ;; Q: What's the status on this, now that specs are being added for 1.9.0?
                 [prismatic/schema "1.1.2"]]
  :jvm-opts [~(str "-Djava.library.path=/usr/local/lib:" (System/getenv "LD_LIBRARY_PATH"))]
  :plugins []
  :profiles {:dev {:dependencies [[org.clojure/java.classpath "0.2.3"
                                   :exclusions [org.clojure/clojure]]
                                  [org.clojure/tools.namespace "0.2.11"]]
                   ;; Q: Why do I have tools.namespace under both dependencies and plugins?
                   :plugins [[org.clojure/tools.namespace "0.2.11" :exclusions [org.clojure/clojure]]]
                   :source-paths ["dev"]}
             :uberjar {:aot :all}}
  :repl-options {:init-ns user})
