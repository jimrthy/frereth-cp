(ns frereth-cp.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [byte-streams :as b-s]
            [clojure.data :as data]
            [clojure.spec.alpha :as s]
            [clojure.pprint :refer [pprint]]
            [frereth-cp.client
             [cookie :as cookie]
             [hello :as hello]
             [initiate :as initiate]
             [state :as state]]
            [frereth-cp.message
             [specs :as msg-specs]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log]
             [specs :as specs]]
            [frereth-cp.util :as util]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(set! *warn-on-reflection* true)

(def heartbeat-interval (* 15 shared/millis-in-second))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(defn hide-long-arrays
  "Make pretty printing a little less verbose"
  [this]
  ;; In some scenarios, we're winding up with the client as a
  ;; deferred.
  ;; This is specifically happening when my interaction test
  ;; throws an unhandled exception.
  ;; I probably shouldn't do this to try to work around that problem,
  ;; but I really want/need as much debug info as I can get in
  ;; that sort of scenario
  (let [this (if (associative? this)
               this
               (try
                 (assoc @this ::-hide-long-array-notice "This was a deferred")
                 (catch java.lang.ClassCastException ex
                   (throw (ex-info (str @this ": deferred that breaks everything")
                                   {:cause (str ex)})))))]
    (-> this
        ;; TODO: Write a mirror image version of dns-encode to just show this
        (assoc-in [::server-security ::specs/srvr-name] "name")
        (assoc-in [::shared/packet-management ::shared/packet] "...packet bytes..."))))

(defn child-exited!
  [this]
  (throw (ex-info "child exited" this)))

(defn child->server
  "Child sent us (as an agent) a signal to add bytes to the stream to the server"
  [this msg]
  (throw (RuntimeException. "Not translated")))

(defn server->child
  "Received bytes from the server that need to be streamed back to child"
  [this msg]
  (throw (RuntimeException. "Not translated")))

(defn chan->server-closed
  [{:keys [::log/logger
           ::log/state]
    :as this}]
  ;; This is moderately useless. But I want *some* record
  ;; that we got here.
  (log/flush-logs! logger
                   (log/warn (log/fork state)
                             ::chan->server-closed)))

(declare stop!)
(defn unexpectedly-terminated-successfully
  [result unexpected]
  ;; terminated is for something really extreme,
  ;; when you really want to kill the client,
  ;; can't, and are not quite in a position
  ;; to do anything short of terminating
  ;; the JVM.
  ;; There should never be a "success"
  ;; condition that leads to termination.
  (let [logger (log/std-err-log-factory)
        log-state (log/init ::ctor)]
    ;; It's very tempting to completely kill the JVM
    ;; as a way to discourage this sort of behavior.
    (log/flush-logs! logger
                     (log/error log-state
                                ::successful-termination
                                "Don't ever do this"
                                {::details unexpected})))
  (stop! result))

(defn unexpectedly-terminated-unsuccessfully
  [result outcome]
  (stop! result)
  (let [logger (log/std-err-log-factory)
        log-state (log/init ::ctor)]
    ;; It's very tempting to completely kill the JVM
    ;; as a way to discourage this sort of behavior.
    (log/flush-logs! logger
                     (if (instance? Throwable outcome)
                       (log/exception log-state
                                      outcome
                                      ::botched-termination)
                       (log/error log-state
                                  ::expected-termination
                                  "If you have to do this, provide copious details"
                                  {::details outcome})))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef start!
        :args (s/cat :this ::state/state)
        ;; Q: Does this return anything meaningful at all?
        ;; A: Well, to remain consistent with the Component workflow,
        ;; it really should return the "started" agent.
        ;; Even though it really is just called for side-effects.
        :ret any?)
(defn start!
  ;; Take the client state as a standard immutable value parameter.
  ;; Return a deferred that's really a chain of everything that
  ;; happens here, up to the point of switching into message-exchange
  ;; mode.
  "Perform the side-effects to establish a connection with a server"
  [{:keys [::log/logger
           ::state/chan->server]
    log-state ::log/state
    :as this}]
  {:pre [chan->server
         log-state
         logger]}
  (let [log-state-atom (atom (log/clean-fork log-state ::for-exception-handling))
        major-problem (fn [ex]
                        (log/flush-logs! logger
                                         (log/exception @log-state-atom
                                                        ex
                                                        ::start!
                                                        "Failure escaped")))]
    (try
      (strm/on-drained chan->server
                       (partial chan->server-closed this))
      (let [log-state (log/info log-state
                                ::start!
                                "client/start! Wiring side-effects through chan->server")]
        (-> (assoc this ::log/state log-state)
            (dfrd/chain
             (fn [this]
               (hello/set-up-server-polling! this
                                             log-state-atom
                                             cookie/wait-for-cookie!))
             (fn [{log-state ::log/state
                   :as this}]
               ;; We're getting here
               (println "Outcome from hello/set-up-server-polling!")
               (pprint this)
               ;; This construct's an argument in favor of just passing the
               ;; ::state/state through everything.
               ;; That approach is certainly easier. Though, ultimately,
               ;; not exactly simpler. It also takes us in the direction
               ;; of java, checked exceptions, and needing to change all
               ;; the callers when something at the bottom of the call
               ;; stack changes.
               (into this
                     (initiate/build-inner-vouch this)))
             cookie/servers-polled
             initiate/initial-packet-sent)
            (dfrd/catch (fn [ex]
                          (assoc this
                                 ::log/state (log/flush-logs! logger
                                                              (log/exception @log-state-atom
                                                                             ex
                                                                             ::start!)))))))
      (catch Throwable ex
        (swap! log-state-atom
               #(log/exception %
                               ex
                               ::start!))
        (update this
                ::log/state #(log/flush-logs! logger %)))
      (finally
        (log/flush-logs! logger (log/debug @log-state-atom
                                           ::start!
                                           "End"))))))

(s/fdef stop!
        :args (s/cat :state ::state/state)
        :ret any?)
(defn stop!
  [{log-state ::log/state
    :keys [::log/logger
           ::state/chan->server
           ::shared/packet-management]
    :or {log-state (log/init ::stop!-missing-logs)
         logger (log/std-out-log-factory)}
    :as this}]
  (let [log-state (log/flush-logs! logger
                                   (log/debug log-state
                                              ::stop!
                                              "Trying to stop a client"
                                              {::wrapper-content-class (class this)
                                               ::state/state (dissoc this ::log/state)}))
        log-state
        (try
          (let [;; This is what signals the Child ioloop to stop
                log-state (state/do-stop (assoc this
                                                ::log/state log-state))
                log-state
                (try
                  (let [log-state (log/flush-logs! logger
                                                   (log/trace log-state
                                                              ::stop!
                                                              "Possibly closing the channel to server"
                                                              {::state/chan->server chan->server}))]
                    (if chan->server
                      (do
                        (strm/close! chan->server)
                        (log/debug log-state
                                   ::stop!
                                   "chan->server closed"))
                      (log/warn log-state
                                ::stop!
                                "chan->server already nil"
                                (dissoc this ::log/state))))
                  (catch Exception ex
                    (log/exception log-state
                                   ex
                                   ::stop!)))]
            (log/flush-logs! logger
                             (log/info log-state
                                       ::stop!
                                       "Done")))
          (catch Exception ex
            (log/exception log-state
                           ex
                           ::stop!
                           "Actual stop function failed")))]
    (println "Successfully reached the bottom of client/stop!")
    (assoc this
           ::chan->server nil
           ;; Q: What should this logging context be?
           ::log/state (log/init ::ended-during-stop!)
           ::shared/packet-management nil)))

(s/fdef ctor
        :args (s/cat :opts (s/keys :req [::msg-specs/->child
                                         ::state/chan->server
                                         ::specs/message-loop-name
                                         ::shared/my-keys
                                         ::state/server-security])
                     :log-initializer (s/fspec :args nil
                                               :ret ::log/logger))
        :ret ::state/state)
(defn ctor
  [opts logger-initializer]
  (let [result
        (-> opts
            (state/initialize-immutable-values logger-initializer)
            ;; Assigning this really belongs in
            ;; state/initialize-immutable-values
            ;; (or maybe its mutable counterpart)
            ;; But that would create circular imports.
            ;; This is a red flag.
            ;; FIXME: Come up with a better place for it to live.
            (assoc ::state/packet-builder initiate/build-initiate-packet!)
            state/initialize-mutable-state!
            (assoc
             ;; This seems very cheese-ball, but they
             ;; *do* need to be part of the agent.
             ;; Assuming the agent just doesn't go completely away.
             ;; We definitely don't want multiple threads
             ;; messing with them.
             ;; TODO: Now that the agent has gone away, eliminate
             ;; these also.
             ::shared/packet-management (shared/default-packet-manager)
             ::shared/work-area (shared/default-work-area)))]
    (dfrd/on-realized (::state/terminated result)
                      (partial unexpectedly-terminated-successfully result)
                      (partial unexpectedly-terminated-unsuccessfully result))
    result))
