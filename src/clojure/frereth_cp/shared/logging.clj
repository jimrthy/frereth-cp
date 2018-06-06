(ns frereth-cp.shared.logging
  "Functional logging mechanism"
  (:require [clojure.spec.alpha :as s]
            [clojure.stacktrace :as s-t]
            [clojure.string :as str]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as utils])
  (:import clojure.lang.ExceptionInfo
           [java.io BufferedWriter FileWriter OutputStream OutputStreamWriter]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::ctx-atom (s/or :string string?
                        :keyword keyword?
                        :uuid uuid?
                        :int int?))
(s/def ::ctx-seq (s/coll-of ::ctx-atom))
(s/def ::context (s/or :atom ::ctx-atom
                       :seq ::ctx-seq))

;;;; Implement this for your side-effects
(defprotocol Logger
  "Extend this for logging side-effects"
  (log! [this msg]
    "At least queue up a log message to side-effect")
  ;; It's tempting to add things like filtering to do things like
  ;; discarding all logs except warn and error.
  ;; Don't give in to temptation: keep the concerns separated.
  ;; Honestly, that's something that should probably be stateful
  ;; in a serious system, so operators can modify logging levels
  ;; on the fly based on whether or not something's going wrong.
  ;; For that matter, it would be nice to use something like anomaly
  ;; detectiong to handle those changes automatically.
  (flush! [this] "Some loggers need to do this at the end of a batch"))
(s/def ::logger #(satisfies? Logger %))

;; It's tempting to pass around this instead of a ::logger
;; instance directly.
;; To create Logger instances on demand and then discard them.
;; The temptation seems dumb.
;; Q: So why am I still tempted?
(s/def ::log-builder (s/fspec :args nil
                              :ret ::logger))

;;; TODO: I need a map of these keys to numeric values to make
;;; things like removing unwanted messages trivial.
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
                             ::lamport
                             ::time
                             ::message]
                       :opt [::details]))

(s/def ::entries (s/coll-of ::entry))

(s/def ::state (s/keys :req [::context
                             ::entries
                             ::lamport]))

(s/def ::state-atom (s/and ::specs/atom
                           #(s/valid? ::state (deref %))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef build-log-entry
        :args (s/or :with-msg (s/cat :label ::label
                                     :lamport ::lamport
                                     :level ::level
                                     :message ::message)
                    :sans-msg (s/cat :label ::label
                                     :lamport ::lamport
                                     :level ::level)))
(defn build-log-entry
  ([label lamport level]
   {::current-thread (utils/get-current-thread)
    ::label label
    ::lamport lamport
    ::level level
    ::time (System/currentTimeMillis)})
  ([label lamport level message]
   (assoc (build-log-entry label lamport level)
          ::message message)))

(s/fdef add-log-entry
        :args (s/cat :log-state ::state
                     :level ::level
                     :label ::label
                     :message ::message
                     :details ::details)
        :ret ::entries)
(defn add-log-entry
  ([{:keys [::lamport]
     :as log-state}
    level
    label]
   (when-not lamport
     (let [ex (ex-info "Desperation warning: missing clock among" (or {::problem log-state}
                                                                      {::problem "falsey log-state"}))]
       (s-t/print-stack-trace ex)))
   (-> log-state
       (update
        ::entries
        conj
        (build-log-entry label lamport level))
       (update ::lamport inc)))
  ([{:keys [::lamport]
     :as log-state}
    level
    label
    message]
   (when-not lamport
     (let [ex (ex-info "Desperation warning: missing clock among" (or {::problem log-state}
                                                                      {::problem "falsey log-state"}))]
       (s-t/print-stack-trace ex)))
   (-> log-state
       (update
        ::entries
        conj
        (build-log-entry label lamport level message))
       (update ::lamport inc)))
  ([{:keys [::context
            ::lamport]
     :as log-state}
    level
    label
    message
    details]
   (-> log-state
       (add-log-entry level label message)
       (update ::entries
               (fn [cur]
                 (assoc-in cur
                           [(dec (count cur))
                            ::details]
                           details))))))

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
        (add-log-entry log-state# ~tag label# message#))
       ([log-state#
         label#]
        (add-log-entry log-state# ~tag label#)))))

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

(declare init)
(defn format-log-string
  [caller-stack-holder entry]
  (try
    (prn-str entry)
    (catch RuntimeException ex
      (let [injected
            (prn-str (add-log-entry (init ::logging-formatter -1)
                                    ::exception
                                    ::log!
                                    "Failed to write a log"
                                    {::immediate (exception-details ex)
                                     ::caller (exception-details caller-stack-holder)
                                     ::redacted-problem (prn-str (dissoc entry ::details))}))]
        ;; Q: What's the best thing to do here?
        (comment (throw ex))
        injected))))

(defrecord OutputWriterLogger [writer]
  Logger
  ;; According to stackoverflow (and the java source
  ;; code that was provided as evidence), BufferedWriter
  ;; .write and .flush are both synchronized and thus
  ;; safe to use from multiple threads at once.
  (log! [{writer :writer
          :as this}
         entry]
    (let [get-caller-stack (RuntimeException. "Q: Is there a cheaper way to get the call stack?")
          formatted (format-log-string get-caller-stack entry)]
      (.write writer formatted)))
  (flush! [{^BufferedWriter writer :writer
            :as this}]
    (.flush writer)))

(defrecord StreamLogger [stream]
  ;; I think this is mostly correct,
  ;; but I haven't actually tried testing it
  ;; And, realistically, contrasted with
  ;; OutputWriterLogger, this should probably
  ;; never be used.
  Logger
  (log! [{^OutputStream stream :stream
          :as this}
         entry]
    (let [get-caller-stack (RuntimeException. "Q: Is there a cheaper way to get the call stack?")
          formatted (format-log-string get-caller-stack entry)]
      (.write stream formatted)))
  (flush! [{^OutputStream stream :stream
            :as this}]
    (.flush stream)))

(defrecord StdOutLogger [state-agent]
  ;; Really just a StreamLogger
  ;; where stream is STDOUT.
  ;; But it's simple/easy enough that it seemed
  ;; worth writing this way instead
  Logger
  (log! [{:keys [:state-agent]
          :as this} msg]
    (when-let [ex (agent-error state-agent)]
      (println "Logging Agent Failed:\n"
               (exception-details ex))
      ;; Q: What are the odds this will work?
      (let [last-state @state-agent]
        (println "Logging Agent State:\n"
                 last-state)
        (restart-agent state-agent last-state)))
    ;; Creating an exception that we're going to throw away
    ;; for almost every log message seems really wasteful.
    (let [get-caller-stack (RuntimeException. "Q: Is there a cheaper way to get the call stack?")]
      (send state-agent (fn [state entry]
                          (print (format-log-string get-caller-stack entry))
                          state)
            msg)))
  ;; Q: Is there any point to calling .flush
  ;; on STDOUT?
  ;; A: Not according to stackoverflow.
  ;; It flushes itself after every CR/LF
  (flush! [_]
    (send state-agent #(update % ::flush-count inc))))

(defrecord StdErrLogger [state-agent]
  ;; Really just a StreamLogger
  ;; where stream is STDOUT.
  ;; But it's simple/easy enough that it seemed
  ;; worth writing this way instead
  Logger
  (log! [{:keys [:state-agent]
          :as this} msg]
    (binding [*out* *err*]
      (when-let [ex (agent-error state-agent)]
        (println "Logging Agent Failed:\n"
                 (exception-details ex))
        ;; Q: What are the odds this will work?
        (let [last-state @state-agent]
          (println "Logging Agent State:\n"
                   last-state)
          (restart-agent state-agent last-state)))
      ;; Creating an exception that we're going to throw away
      ;; for almost every log message seems really wasteful.
      (let [get-caller-stack (RuntimeException. "Q: Is there a cheaper way to get the call stack?")]
        (send state-agent (fn [state entry]
                            (print (format-log-string get-caller-stack entry))
                            state)
              msg))))
  ;; Q: Is there any point to calling .flush
  ;; on STDOUT?
  ;; A: Not according to stackoverflow.
  ;; It flushes itself after every CR/LF
  (flush! [_]
    (send state-agent #(update % ::flush-count inc))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(deflogger trace)
(deflogger debug)
(deflogger info)
(deflogger warn)
(deflogger error)

(defn exception
  ([log-state ex label]
   (add-log-entry log-state ::exception label ""
                  (exception-details ex)))
  ([log-state ex label message]
   (add-log-entry log-state ::exception label message
                  (exception-details ex)))
  ([log-state ex label message original-details]
   (let [details {::original-details original-details
                  ::problem (exception-details ex)}]
     (add-log-entry log-state ::exception label message details))))

(deflogger fatal)

(declare get-official-clock)
(s/fdef init
        :args (s/cat :context ::context
                     :start-time ::lamport)
        :ret ::state)
(defn init
  ([context start-clock]
   {::entries []
    ::lamport start-clock
    ::context context})
  ([context]
   (init context (get-official-clock))))

(defn file-writer-factory
  [file-name]
  (let [writer (BufferedWriter. (FileWriter. file-name))]
    (->OutputWriterLogger writer)))

(defn std-out-log-factory
  []
  (->StdOutLogger (agent {::flush-count 0})))

(defn std-err-log-factory
  []
  (->StdErrLogger (agent {::flush-count 0})))

(defn stream-log-factory
  [stream]
  (->StreamLogger stream))

(s/fdef flush-logs!
        :args (s/cat :logger ::logger
                     :logs ::state)
        :ret ::state)
;; Do what I can to keep local clocks synchronized
(let [my-lamport (atom 0)]
  (defn get-official-clock
    []
    @my-lamport)
  (comment (get-official-clock))

  (s/fdef do-sync-clock
          :args (s/cat :log-state ::state)
          :ret ::state)
  (defn do-sync-clock
    "Synchronize my clock with a state's"
    [log-state]
    (let [{:keys [::lamport]} log-state]
      (swap! my-lamport max lamport)
      (assoc log-state ::lamport @my-lamport)))

  (defn flush-logs!
    "For the side-effects to write the accumulated logs.

  Returns a fresh set of log entries"
    ;; TODO: Reverse these parameters.
    ;; So I can thread-first log-state through
    ;; log calls into this
    [logger
     {:keys [::context]
      :as log-state}]
    ;; Honestly, there should be an agent that handles this
    ;; so we don't block the calling thread.
    ;; The i/o costs should be quite a bit higher than
    ;; the agent overhead...though
    ;; a go-loop would be more efficient
    (let [{:keys [::lamport]
           :as log-state} (add-log-entry log-state
                                         ::trace
                                         ::top
                                         "flushing"
                                         {::context context})]
      (doseq [message (::entries log-state)]
        (log! logger message))
      (flush! logger)

      (assoc (do-sync-clock log-state)
             ::entries []))))

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
        ;; Yes. It really is a pair of them.
        :ret (s/tuple ::state ::state))
(defn synchronize
  "Fix 2 clocks that have probably drifted apart"
  [{l-clock ::lamport
    l-ctx ::context
    :as lhs}
   {r-clock ::lamport
    r-ctx ::context
    :as rhs}]
  {:pre [l-clock
         r-clock]}
  (let [synced (max l-clock r-clock)
        lhs (assoc lhs ::lamport synced)
        rhs (assoc rhs ::lamport synced)]
    [(debug lhs ::synchronized "" {::context l-ctx})
     (debug rhs ::synchronized "" {::context r-ctx})]))

(s/fdef clean-fork
        :args (s/cat :source ::state
                     :child-context ::context)
        :ret ::state)
(defn clean-fork
  "Fork the context/lamport clock without the logs.

Main use-case is exception handlers in weird side-effecty places
where it isn't convenient to propagate a log line or 2 that will
show up later."
  [src child-context]
  (let [parent-ctx (::context src)
        combiner (if (seq? parent-ctx)
                   conj
                   list)]
    (init (combiner parent-ctx child-context)
          (inc (::lamport src)))))

(s/fdef fork
        :args (s/or :with-child-ctx (s/cat :source ::state
                                           :child-context ::context)
                    :without-child-ctx (s/cat :source ::state))
        ;; Note that the return value really depends
        ;; on the caller arity.
        ;; TODO: Need to write the :fn value to reflect this.
        :ret (s/or :with-nested-context (s/tuple ::state ::state)
                   :keep-parent-context ::state))
(defn fork
  "Return shape depends on arity"
  ([src child-context]
   (let [parent-ctx (::context src)
         combiner (if (seq? parent-ctx)
                    conj
                    list)
         forked (init (combiner parent-ctx child-context)
                      (::lamport src))]
     (synchronize src forked)))
  ([src]
   (init (::context src) (inc (::lamport src)))))

(s/fdef merge-state
        :args (s/cat :logs1 ::state
                     :logs2 ::state)
        :ret ::state)
(defn merge-state
  "Combine the entries of two log states"
  [x y]
  (throw (RuntimeException. "Write this")))
