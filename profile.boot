
;; FIXME: Move this into build.boot.
;; The cider-repl task depends on it.
(deftask cider "CIDER profile"
  []
  (require 'boot.repl)

  ;; This has supposedly changed with CIDER 0.16. According to the boot
  ;; wiki I should be able to make these global without noticing the
  ;; difference.
  ;; Starting a plain REPL that way is a couple of seconds faster than
  ;; starting it with this in the task chain, but it's still 14
  ;; seconds slower (on my desktop) than starting without these
  ;; dependencies at all.
  ;; Stick with this version for now.
  (swap! @(resolve 'boot.repl/*default-dependencies*)
         concat '[[org.clojure/tools.nrepl "0.2.12"]
                  [cider/cider-nrepl "0.18.0"]
                  [refactor-nrepl "2.4.0"]])

  (swap! @(resolve 'boot.repl/*default-middleware*)
         concat
         '[cider.nrepl/cider-middleware
           refactor-nrepl.middleware/wrap-refactor])
  identity)
