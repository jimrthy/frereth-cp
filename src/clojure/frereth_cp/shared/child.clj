(ns frereth-cp.shared.child
  ;; I could make a strong argument that this really belongs under
  ;; message.
  ;; But there's already far too much going on in there.
  "Manage child ioloops"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message :as message]
            [frereth-cp.message
             [registry :as registry]
             [specs :as msg-specs]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [specs :as specs]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::state ::msg-specs/io-handle)

(s/def ::child-builder (s/keys :req [::weald/logger
                                     ::weald/state
                                     ::msg-specs/->child
                                     ::msg-specs/child-spawner!
                                     ::msg-specs/message-loop-name]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Globals

(defonce io-loop-registry (atom (registry/ctor)))
(comment
  @io-loop-registry
  (-> io-loop-registry deref keys)
  (swap! io-loop-registry registry/de-register "client-hand-shaker")
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal Implementation


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef fork!
  :args (s/cat :builder ::child-builder
               :child-> ::msg-specs/->parent)
  :ret (s/keys :req [::state
                     ::weald/state]))
(defn fork!
  "Create a new Child to do all the interesting work"
  [{:keys [::weald/logger
           ::msg-specs/->child
           ::msg-specs/child-spawner!
           ::msg-specs/message-loop-name]
    log-state ::weald/state
    :as builder}
   child->]
  {:pre [message-loop-name]}
  (when-not log-state
    (throw (ex-info (str "Missing log state among "
                         (keys builder))
                    builder)))
  (let [log-state (log/info log-state ::fork! "Spawning child!!")
        child-name (str (gensym "child-"))
        ;; Q: Refactor implementation from message into here?
        startable (message/initial-state message-loop-name
                                         false
                                         {::weald/state (log/clean-fork log-state
                                                                        child-name)}
                                         logger)
        {:keys [::msg-specs/io-handle]
         log-state ::weald/state} (message/do-start startable
                                                    logger
                                                    child->
                                                    ->child)
        log-state (log/debug log-state
                             ::fork!
                             "Child message loop initialized"
                             {::child-builder (dissoc builder ::weald/state)
                              ::state (dissoc io-handle ::weald/state)})]
    (swap! io-loop-registry
           #(registry/register % io-handle))
    (child-spawner! io-handle)
    {::state io-handle
     ::weald/state (log/flush-logs! logger log-state)}))

(s/fdef do-halt!
  :args (s/cat :log-state ::weald/state
               :child ::state)
  :ret ::weald/state)
(defn do-halt!
  [log-state child]
  (let [log-state (log/warn log-state
                            ::do-halt!
                            "Halting child's message io-loop")
        message-loop-name (::specs/message-loop-name child)]
    ;; It's tempting to refactor the functionality from message
    ;; into here, since this ns is so skimpy.
    ;; But that gets into the guts of the ioloop.
    ;; And short, easy-to-understand namespaces aren't
    ;; exactly a bad thing.
    (message/halt! child)
    ;; In theory, I should be able to just manually call halt!
    ;; on entries in this registry that don't get stopped when
    ;; things hit a bug.
    ;; In practice, the problems probably go deeper:
    ;; Either from-child or to-parent (more likely) keeps
    ;; feeding un-ackd messages into the queue.
    ;; So I need a way to manually halt that also.

    ;; There are some interrupt functions in the top-level
    ;; frereth-cp.message ns that seem to do the trick.
    ;; It's tempting to expose them.
    ;; Then again, they're a sledge hammer that just stops
    ;; all the message loops.
    ;; Running multiple clients and server connections
    ;; requires a scalpel.
    ;; TODO: Revisit this.
    (swap! io-loop-registry
           #(registry/de-register % message-loop-name))
    (log/warn log-state
              ::do-stop
              "Child's message io-loop halted")))

(s/fdef update-callback!
        :args (s/cat :io-handle ::msg-specs/io-handle
                     :time-out ::specs/time
                     :new-callback ::msg-specs/->parent))
(defn update-callback!
  [io-handle time-out new-callback]
  ;; FIXME: Refactor the implementation from message into here
  (message/swap-parent-callback! io-handle
                                 time-out
                                 ::state
                                 new-callback))
