(ns frereth-cp.shared.logging
  "Functional logging mechanism"
  (:require [clojure.spec.alpha :as s]
            [clojure.stacktrace :as s-t]
            [frereth-cp.util :as utils])
  (:import clojure.lang.ExceptionInfo
           java.io.OutputStream))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::context (s/or :string string?
                       :keyword keyword?
                       :uuid uuid?
                       :int int?))

;;;; Implement this for your side-effects
(defprotocol Logger
  "Extend this for logging side-effects"
  (log! [this msg]
    "At least queue up a log message to side-effect")
  (flush! [this] "Some loggers need to do this at the end of a batch"))
(s/def ::logger #(satisfies? Logger %))

(def log-levels #{::trace
                  ::debug
                  ::info
                  ::warn
                  ::error
                  ::exception
                  ::fatal})
(s/def ::level log-levels)

(s/def ::label keyword?)

;; Go with milliseconds since epoch
;; Note that these next two are *totally* distinct
(s/def ::time nat-int?)
;;; Honestly, this doesn't belong in here.
;;; I can't add a clock to the CurveCP protocol
;;; without breaking it (which doesn't seem like
;;; a terrible idea), but I can make it easily
;;; available to implementers.
;;; For that matter, I might be able to shove one
;;; into the
;;; the zero-padding bytes of each Message.
(s/def ::lamport nat-int?)

(s/def ::message string?)

(s/def ::details any?)

(s/def ::entry (s/keys :req [::level
                             ::label
                             ::time
                             ::message]
                       :opt [::details]))

(s/def ::entries (s/coll-of ::entry))

(s/def ::state (s/keys :req [::context
                             ::entries
                             ::lamport]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef add-log-entry
        :args (s/cat :log-state ::state
                     :level ::level
                     :label ::label
                     :message ::message
                     :details ::details)
        :ret ::entries)
(defn add-log-entry
  ([{:keys [::context
            ::lamport]
     :as log-state}
    level
    label
    message
    details]
   (when-not lamport
     (let [ex (ex-info "Desperation warning: missing clock among" (or log-state
                                                                      {::problem "falsey log-state"}))]
       (s-t/print-stack-trace ex)))
   (-> log-state
       (update
        ::entries
        conj
        {::context context
         ::current-thread (utils/get-current-thread)
         ::details details
         ::label label
         ::lamport lamport
         ::level level
         ::time (System/currentTimeMillis)
         ::message message})
       (update ::lamport inc)))
  ([{:keys [::lamport]
     :as log-state}
    level
    label
    message]
   (-> log-state
       (update
        ::entries
        conj
        {::current-thread (utils/get-current-thread)
         ::label label
         ::lamport lamport
         ::level level
         ::time (System/currentTimeMillis)
         ::message message})
       (update ::lamport inc))))

(defmacro deflogger
  [level]
  ;; TODO: I'd much rather do something like this for the sake of hygiene:
  (comment
    `(let [lvl-holder# '~level
           tag-holder# (keyword (str *ns*) (name lvl-holder#))]
       (defn '~lvl-holder#
         ([entries#
           label#
           message#
           details#]
          (add-log-entry entries# ~'~tag-holder label# message# details#))
         ([entries#
           label#
           message#]
          (add-log-entry entries# ~'~tag-holder label# message#)))))
  (let [tag (keyword (str *ns*) (name level))]
    ;; The auto-gensymmed parameter names are obnoxious.
    ;; And largely irrelevant.
    ;; This isn't the kind of macro that you nest inside
    ;; other macros.
    ;; Then again...auto-namespacing makes eliminating them
    ;; interesting.
    `(defn ~level
       ;; TODO: Refactor the parameter order.
       ;; It doesn't seem like it should ever be worth it, but a
       ;; complex function might save some code by setting up
       ;; partial(s) using the label
       ([log-state#
         label#
         message#
         details#]
        (add-log-entry log-state# ~tag label# message# details#))
       ([log-state#
         label#
         message#]
        (add-log-entry log-state# ~tag label# message#)))))

(defrecord StreamLogger [stream]
  ;; I think this is mostly correct,
  ;; but I haven't actually tried testing it
  Logger
  (log! [{^OutputStream stream :stream
          :as this}
         msg]
    (.write stream (prn-str msg)))
  (flush! [{^OutputStream stream :stream
            :as this}]
    (.flush stream)))

(defrecord StdOutLogger []
  ;; Really just a StreamLogger
  ;; where stream is STDOUT.
  ;; But it's simple/easy enough that it seemed
  ;; worth writing this way instead
  Logger
  (log! [_ msg]
    (println (pr-str msg)))
  ;; Q: Is there any point to calling .flush
  ;; on STDOUT?
  ;; A: Not according to stackoverflow.
  ;; It flushes itself after every CR/LF
  (flush! [_]))

(defn exception-details
  [ex]
  (let [stack-trace (with-out-str (s-t/print-stack-trace ex))
        base {::stack stack-trace
              ::exception ex}
        with-details (if (instance? ExceptionInfo ex)
                       (assoc-in base [::data ::problem] (.getData ex))
                       base)]
    (if-let [cause (.getCause ex)]
      (assoc with-details ::cause (exception-details cause))
      with-details)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(deflogger trace)
(deflogger debug)
(deflogger info)
(deflogger warn)
(deflogger error)

(defn exception
  ([log-state ex label message]
   (exception log-state ex label message nil))
  ([log-state ex label message original-details]
   (let [details {::original-details original-details
                  ::problem (exception-details ex)}]
     (add-log-entry log-state ::exception label message details))))

(deflogger fatal)

(s/fdef init
        :args (s/cat :start-time ::lamport)
        :ret ::state)
(defn init
  ([context start-clock]
   {::entries []
    ::lamport start-clock
    ::context context})
  ;; FIXME: Honestly, this needs a high-level context
  ;; i.e. What is the purpose of this group of logs?
  ([start-clock]
   (init "FIXME: This arity should go away" start-clock))
  ([]
   ;; the 1-arity version should include the context.
   ;; *This* is the arity that should just go away
   (init 0)))

(s/fdef fork
        :args (s/cat :source ::state
                     :child-context ::context)
        :ret (s/tuple ::state ::state))
(defn fork
  [src child-context]
  (let [src-ctx (::context src)
        combiner (if (seq? src-ctx)
                   conj
                   list)
        forked (init (combiner src-ctx child-context)
                     (::lamport src))]
    (synchronize src forked)))

(defn std-out-log-factory
  []
  (->StdOutLogger))

(defn stream-log-factory
  [stream]
  (->StreamLogger stream))

(s/fdef flush-logs!
        :args (s/cat :logger ::logger
                     :logs ::state)
        :ret ::state)
(defn flush-logs!
  "For the side-effects to write the accumulated logs.

Returns fresh set of log entries"
  [logger
   {:keys [::context]
    :as log-state}]
  ;; Honestly, there should be an agent that handles this
  ;; so we don't block the calling thread.
  ;; The i/o costs should be quite a bit higher than
  ;; the agent overhead...though I do know that
  ;; a go-loop would be more efficient
  (doseq [message (::entries log-state)]
    (log! logger message))
  (flush! logger)
  ;; Q: Which of these next 2 options will perform
  ;; better?
  ;; It seems like it should be a toss-up, since most
  ;; of the impact will come from garbage collecting the
  ;; old entries anyway.
  ;; But it seems like the latter might get a minor
  ;; win by avoiding the overhead of the update call
  (comment
    (-> log-state
        (update ::lamport inc)
        (assoc ::entries [])))
  (init (inc (::lamport log-state))))

(s/fdef synchronize
        :args (s/cat :lhs ::state
                     :rhs ::state)
        :fn (s/and #(let [{:keys [:args :ret]} %
                          {:keys [:lhs :rhs]} args]
                      ;; Only changes the lamport tick of the
                      ;; clock states
                      (and (= (-> ret first (dissoc ::lamport))
                              (dissoc lhs ::lamport))
                           (= (-> ret second (dissoc ::lamport))
                              (dissoc rhs ::lamport))))
                   #(let [{:keys [:args :ret]} %
                          {:keys [:lhs :rhs]} args]
                      (= (ret first ::lamport)
                         (ret second ::lamport)
                         (max (::lamport lhs)
                              (::lamport rhs)))))
        :ret (s/tuple ::log-state ::state))
(defn synchronize
  "Fix 2 clocks that have probably drifted apart"
  [{l-clock ::lamport
    :as lhs}
   {r-clock ::lamport
    :as rhs}]
  (let [synced (inc (max l-clock r-clock))
        lhs (assoc lhs ::lamport synced)
        rhs (assoc rhs ::lamport synced)]
    [(debug lhs ::synchronized "")
     (debug rhs ::synchronized "")]))
