(ns frereth-cp.shared.logging
  "Functional logging mechanism"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.util :as utils])
  (:import clojure.lang.ExceptionInfo
           java.io.OutputStream))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;;; Implement this for your side-effects
(defprotocol Logger
  (log! [this msg])
  (flush! [this]))
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

(s/def ::state (s/keys :req [::entries ::lamport]))

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
  ([{:keys [::lamport]
     :as log-state}
    level
    label
    message
    details]
   (-> log-state
       (update
        ::entries
        conj
        {::current-thread (utils/get-current-thread)
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
    (.write stream (pr-str msg)))
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
                  ::stack (.getStackTrace ex)
                  ::exception ex}
         details (if (instance? ExceptionInfo ex)
                   (assoc details ::data (.getData ex))
                   details)]
     (add-log-entry log-state ::exception label message details))))

(deflogger fatal)

(s/fdef init
        :args (s/cat :start-time ::lamport)
        :ret ::state)
(defn init
  ([start-clock]
   {::entries []
    ::lamport start-clock})
  ([]
   (init 0)))

(defn std-out-log-factory
  []
  (->StdOutLogger))

(defn stream-log-factory
  [stream]
  (->StreamLogger stream))

(s/fdef flush-logs!
        :args (s/cat :logger #(satisfies? Logger %)
                     :logs ::state)
        :ret ::state)
(defn flush-logs!
  "For the side-effects to write the accumulated logs"
  [logger
   log-state]
  ;; Honestly, there should be an agent that handles this
  ;; so we don't block the calling thread.
  ;; The i/o costs should be quite a bit higher than
  ;; the agent overhead...though I do know that
  ;; a go-loop would be more efficient
  (doseq [message (::entries log-state)]
    (log! logger message))
  (flush! logger)
  (-> log-state
      (update ::lamport inc)
      (assoc ::entries [])))

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
    [lhs rhs]))
