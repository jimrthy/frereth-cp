(defproject com.frereth/common "0.0.1-SNAPSHOT"
  :description "Pieces that the different Frereth parts share
TODO: This needs to be converted to either
a. boot
b. lein managed dependencies"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  ;; Q: Could I totally pull datomic dependencies out of everything else
  ;; by putting them in here?
  ;; A: Probably. But it would be a foolish choice. The web and client components
  ;; really shouldn't have access to that sort of thing.
  ;; TODO: Pick a date library and use it.
  :dependencies [;; In the world of CurveCP, aleph doesn't seem to make an awful lot of sense.
                 ;; TODO: Just use netty's UDP layer directly.
                 [aleph "0.4.1"]
                 [buddy/buddy-core "1.1.1"]
                 [clj-time "0.12.2"]
                 ;; Q: Does this make any sense in production?
                 ;; A: Well, it makes sense for the general runtime which
                 ;; is the primary goal.
                 ;; It seems to totally fit for frereth.client.
                 ;; And possibly for the server.
                 ;; Q: Does it make any sense for the renderer?
                 ;; A: Depends on whether that uses the client as a library
                 ;; or a stand-alone executable.
                 ;; As it stands: absolutely. Especially if I stick with a browser-
                 ;; based renderer
                 [com.cemerick/pomegranate "0.3.1" :exclusions [org.apache.httpcomponents/httpclient
                                                                org.apache.httpcomponents/httpcore
                                                                org.apache.maven.wagon/wagon-http
                                                                org.codehaus.plexus/plexus-utils]]
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
                 [com.jimrthy/component-dsl "0.1.2-SNAPSHOT" :exclusions [org.clojure/clojure]]
                 [com.taoensso/timbre "4.7.4" :exclusions [org.clojure/clojure
                                                           org.clojure/tools.reader]]
                 ;; Q: Do I really want this?
                 [fullcontact/full.async "1.0.0" :exclusions [org.clojure/clojure
                                                               org.clojure/core.async]]
                 ;; TODO: Replace this with either transit or fressian
                 [gloss "0.2.5" :exclusions [byte-streams
                                             manifold
                                             potemkin]]
                 [im.chit/hara.event "2.4.8" :exclusions [org.clojure/clojure]]
                 [io.aviso/config "0.2.1" :exclusions [org.clojure/clojure
                                                       prismatic/schema]]
                 ;; Because pomegranate and lein conflict.
                 ;; Try the latest versions to see how it works
                 [org.apache.maven.wagon/wagon-http "2.10"]
                 [org.apache.httpcomponents/httpcore "4.4.5"]
                 [org.apache.httpcomponents/httpclient "4.5.2"]

                 ;; This is screwing up EDN serialization
                 ;; In particular dates.
                 ;; TODO: Make it ignore those
                 ;; Q: Has the situation improved in the months I've been ignoring it?
                 #_[mvxcvi/puget "1.0.0" :exclusions [org.clojure/clojure]]
                 [org.clojure/clojure "1.9.0-alpha14"]
                 [org.clojure/core.async "0.2.395" :exclusions [org.clojure/clojure
                                                                org.clojure/tools.analyzer]]
                 [org.clojure/tools.analyzer "0.6.9"]
                 [org.clojure/tools.reader "1.0.0-beta3" :exclusions [org.clojure/clojure]]]
  :java-source-paths ["java"]
  :jvm-opts [~(str "-Djava.library.path=/usr/local/lib:" (System/getenv "LD_LIBRARY_PATH"))]

  :profiles {:dev {:dependencies [[org.clojure/java.classpath "0.2.3"
                                   :exclusions [org.clojure/clojure]]
                                  [org.clojure/test.check "0.9.0"]
                                  [org.clojure/tools.namespace "0.2.11"]]
                   ;; Q: Why do I have tools.namespace under both dependencies and plugins?
                   :plugins [[org.clojure/tools.namespace "0.2.11" :exclusions [org.clojure/clojure]]]
                   :source-paths ["dev"]}
             :uberjar {:aot :all}}
  :repl-options {:init-ns user
                 :timeout 120000})
