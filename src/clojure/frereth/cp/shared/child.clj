(ns frereth.cp.shared.child
  ;; I could make a strong argument that this really belongs under
  ;; message.
  ;; But there's already far too much going on in there.
  "Manage child ioloops"
  (:require [clojure.spec.alpha :as s]
            [frereth.cp
             [message :as message]
             [shared :as shared]]
            [frereth.cp.message
             [registry :as registry]
             [specs :as msg-specs]]
            [frereth.cp.shared
             [constants :as K]
             [crypto :as crypto]
             [specs :as specs]
             [templates :as templates]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [deferred :as deferred]
             [stream :as stream]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

(set! *warn-on-reflection* true)

(def send-timeout
  "How many ms do we wait before giving up on a send?"
  ;; This is probably far too long. Need to play with
  ;; it though.
  ;; Since it's UDP, 25 or even 10 seems much more
  ;; reasonable.
  500)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::child-builder (s/keys :req [::weald/logger
                                     ::weald/state
                                     ::msg-specs/->child
                                     ::msg-specs/child-spawner!
                                     ::msg-specs/message-loop-name]))

;; Parameter is the map that was used to build the previous Message Packet.
;; Returns a modified version that will be used to build the next.
(s/def ::structure-updater
  (s/fspec :args (s/cat :structure map?)
           :ret map?))

(s/def ::sending-details (s/keys :req [::structure-updater
                                       ::log/state-atom
                                       ::msg-specs/stream
                                       ::specs/crypto-key]))

;; Q: Does this serve any meaningful purpose?
(s/def ::state ::msg-specs/io-handle)

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

(s/fdef child->
  :args (s/cat :details ::sending-details
               :nonce-prefix ::specs/client-nonce-prefix
               :template map?  ; FIXME: spec
               :structure-atom (s/and #(instance? (class (atom nil)) %)
                                      ;; Q: spec the fields?
                                      ;; Or at least that it's a map
                                      ;; of keywords to primitives?
                                      map?)
               :message-bytes bytes?)
  :ret any?)
;;; Trying to consolidate server's implementation with the way the
;;; client handles its packets.
;;; That seems needlessly complex due to the way the client has to flip
;;; state in the middle.
;;; Which, honestly, means that I've implemented that part incorrectly.
;;; (I have, of course).

;;; FIXME: This is useless without a destination stream
(defn child->
  "Callback for handling message packets from the child"
  [{:keys [::structure-updater
           ::log/logger
           ::log/state-atom
           ::msg-specs/stream
           ::specs/crypto-key]
    :as details}
   nonce-prefix
   template
   structure-atom
   message-bytes]
  ;; This is trying to handle
  ;; both lines 453-484 of curvecpserver.c
  ;; and  lines 426-442 of curvecpclient.c
  ;; There are several ways to trigger a (close).
  ;; TODO: Cope with those scenarios. (Note that they
  ;; probably don't match the reference any longer)
  (let [log-state @state-atom
        message-bytes (bytes message-bytes)
        n (count message-bytes)
        template (assoc-in template
                           [::templates/message ::K/length]
                           (+ K/box-zero-bytes n))
        ;; In the reference implementation:
        ;; For the client, nonce is set by calling
        ;; clientshorttermnonce_update()
        ;; Right after calling clientextension_init()
        ;; That seems wrong.
        ;; The intent definitely seems to be for the
        ;; client extension to rotate periodically
        ;; (it looks like every 5 minutes, but I haven't
        ;; counted the zeroes) over the course of the
        ;; session.
        ;; But it doesn't do anything with that.
        ;; So it just zeroes them out.
        ;; I'm going to run with the "this was half-
        ;; baked" assumption on this one.
        ;; (lines 423-424 in curvecpclient.c)
        ;; The server is easier: it just associates a
        ;; nonce counter with each client.
        structure (assoc (swap! structure-atom
                                structure-updater)
                         ::templates/message message-bytes)
        nonce-suffix (::templates/nonce structure)
        box (crypto/build-box template
                              structure
                              crypto-key
                              nonce-prefix
                              nonce-suffix)
        log-state (log/debug log-state
                             ::child->
                             "Trying to put"
                             ::templates/nonce nonce-suffix)
        success (stream/try-put! stream box send-timeout ::timed-out)]
    (deferred/on-realized success
      (fn [succeeded]
        (swap! state-atom
               #(log/flush-logs! logger
                                 (if (not= succeeded ::timed-out)
                                   (log/debug log-state
                                              ::child->
                                              "Succeeded")
                                   (log/warn log-state
                                             ::child->
                                             "Timed out")))))
      (fn [failed]
        (swap! state-atom
               #(log/flush-logs! logger
                                 ;; Q: What are the odds that failed
                                 ;; is a Throwable?
                                 (log/error log-state
                                            ::child->
                                            "Failed"
                                            {::problem failed})))))
    (throw (RuntimeException. "So, what should this do?"))))

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
    ;; frereth.cp.message ns that seem to do the trick.
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
