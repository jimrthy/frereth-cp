
;; FIXME: Move this into build.boot.
;; The cider-repl task depends on it.
(deftask cider "CIDER profile"
  []
  (require 'boot.repl)

  ;; This has changed with CIDER 0.16. TODO: Look at
  ;; the boot wiki about this and ditch the lazy
  ;; loading.
  (swap! @(resolve 'boot.repl/*default-dependencies*)
         concat '[[org.clojure/tools.nrepl "0.2.12"]
                  [cider/cider-nrepl "0.18.0"]
                  ;; benedekfazekas is looking into
                  ;; Java 9 compatibility issues.
                  ;; Mostly worried about
                  ;; clj-refactor 2.3.2-SNAPSHOT.
                  ;; Until then, he recommends switching
                  ;; to this to avoid CIDER incompatibilities
                  ;; (things started getting broken around
                  ;; 0.16.0)
                  [refactor-nrepl "2.4.0-SNAPSHOT"]])

  (swap! @(resolve 'boot.repl/*default-middleware*)
         concat
         '[cider.nrepl/cider-middleware
           refactor-nrepl.middleware/wrap-refactor])
  identity)
