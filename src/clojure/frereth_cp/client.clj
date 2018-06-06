(ns frereth-cp.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [byte-streams :as b-s]
            [clojure.data :as data]
            [clojure.spec.alpha :as s]
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
        (assoc-in [::shared/packet-management ::shared/packet] "...packet bytes...")
        (assoc-in [::shared/work-area ::shared/working-nonce] "...FIXME: Decode nonce bytes")
        (assoc-in [::shared/work-area ::shared/text] "...plain/cipher text"))))

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

(s/fdef servers-polled
        :args (s/cat :this ::state/state)
        :ret ::state/state)
(defn servers-polled
  ;; Q: Can I/would it make sense to move this into cookie?
  "Got back a cookie. Respond with a vouch"
  [{log-state ::log/state
    logger ::log/logger
    ;; Q: Is there a good way to pry this out
    ;; so it's its own parameter?
    cookie ::specs/network-packet
    :as this}]
  (println "client: Top of servers-polled")
  (when-not log-state
    ;; This is an ugly situation.
    ;; Something has gone badly wrong
    (let [logger (if logger
                   logger
                   (log/std-out-log-factory))]
      (log/warn (log/init ::servers-polled)
                ::missing-log-state
                ""
                {::state/state this
                 ::state-keys (keys this)})))
  (try
    (let [this (dissoc this ::specs/network-packet)
          log-state (log/info log-state
                              ::servers-polled!
                              "Building/sending Vouch")
          ;; Got a Cookie response packet from server.
          ;; Theory in the reference implementation is that this is
          ;; a good signal that it's time to spawn the child to do
          ;; the real work.
          ;; Note that the packet-builder associated with this
          ;; will start as a partial built from build-initiate-packet!
          ;; The forked callback will call that until we get a response
          ;; back from the server.
          ;; At that point, we need to swap out packet-builder
          ;; as the child will be able to start sending us full-
          ;; size blocks to fill Message Packets.
          {:keys [::state/child]
           :as this} (state/fork! this)]
      this)
    (catch Exception ex
      (let [log-state (log/exception log-state
                                     ex
                                     ::servers-polled)
            log-state (log/flush-logs! logger log-state)
            failure (dfrd/deferred)]
        (dfrd/error! failure ex)
        (assoc this
               ::log/state log-state
               ::specs/deferrable failure)))))

(defn chan->server-closed
  [{:keys [::log/logger
           ::log/state]
    :as this}]
  ;; This is moderately useless. But I want *some* record
  ;; that we got here.
  (log/flush-logs! logger
                   (log/warn (log/fork state)
                             ::chan->server-closed)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

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
  [{:keys [::state/chan->server]
    log-state ::log/state
    :as this}]
  {:pre [chan->server]}
  (try
      (strm/on-drained chan->server
                       (partial chan->server-closed this))
      (let [timeout (state/current-timeout this)
          log-state (log/info log-state
                              ::start!
                              "client/start! Wiring side-effects through chan->server")]
      (let [this (hello/do-build-packet this)]
        (hello/set-up-server-polling! (assoc this ::log/state log-state)
                                      timeout
                                      cookie/wait-for-cookie!
                                      initiate/build-inner-vouch
                                      servers-polled)))
      (catch Exception ex
        ;; A std-out logger doesn't seem serious enough to
        ;; cope with this
        (let [logger (log/std-err-log-factory)
              log-state (log/init ::DOA)]
          (log/flush-logs! logger (log/exception log-state
                                                 ex
                                                 ::start!
                                                 "Failed before I could even get to a logger"))))))

(s/fdef stop!
        :args (s/cat :state ::state/state)
        :ret any?)
(defn stop!
  [this]
  ;; FIXME: local-log-atom can/should go away.
  ;; It's a leftover from the old era where I was shutting
  ;; down an agent with lots of points of failure.
  (let [local-log-atom (atom (log/init ::stop!))
        stop-finished (dfrd/deferred)
        logger (log/std-out-log-factory)]
    (try
      (swap! local-log-atom #(log/debug %
                                        ::stop!
                                        "Trying to stop a client agent"
                                        {::wrapper-content-class (class this)
                                         ::state/state (dissoc this ::log/state)}))
      (try
        (let [{:keys [::state/chan->server
                      ::log/logger
                      ::shared/packet-management]
               log-state ::log/state} this]
          (try
            (swap! local-log-atom #(log/trace % ::stop! "Made it into the real client stopper"))
            (if log-state
              (try
                (let [log-state (log/debug log-state
                                           ::stop!
                                           "Top of the real stopper")
                      ;; This is what signals the Child ioloop to stop
                      log-state (state/do-stop (assoc this
                                                      ::log/state log-state))
                      log-state
                      (try
                        (swap! local-log-atom #(log/trace %
                                                          ::stop!
                                                          "Possibly closing the channel to server"
                                                          {::state/chan->server chan->server}))
                        (if chan->server
                          (do
                            (strm/close! chan->server)
                            (log/debug log-state
                                       ::stop!
                                       "chan->server closed"))
                          (log/warn (log/clean-fork log-state ::possible-issue)
                                    ::stop!
                                    "chan->server already nil"
                                    (dissoc this ::log/state)))
                        (catch Exception ex
                          (log/exception log-state
                                         ex
                                         ::stop!)))
                      log-state (log/flush-logs! logger
                                                 (log/info log-state
                                                           ::stop!
                                                           "Done"))]
                  (assoc this
                         ::chan->server nil
                         ::log/state log-state
                         ::shared/packet-management nil))
                (catch Exception ex
                  (assoc this
                         ::chan->server nil
                         ::log/state (log/exception log-state
                                                    ex
                                                    ::stop!
                                                    "Actual stop function failed")
                         ::shared/packet-management nil)))
              ;; No log state
              ;; It's very tempting to refactor the duplicate functionality into
              ;; its own function. This one is pretty unwieldy.
              ;; And I've botched the copy/paste between the two versions at least once.
              ;; TODO: Clean this up.
              (try
                (swap! local-log-atom
                       #(log/warn %
                                  ::stop!
                                  "Missing log-state. Trying to close the channel to server"
                                  {::state/chan->server chan->server}))
                (swap! local-log-atom
                       #(state/do-stop (assoc this ::log/state %)))
                (if chan->server
                  (do
                    (strm/close! chan->server)
                    (swap! local-log-atom
                           #(log/info %
                                      ::stop!
                                      "client/stop! Failed logging DEBUG: chan->server closed"))
                    (assoc this
                           ::chan->server nil
                           ::log/state (log/init ::resurrected-during-stop!)
                           ::shared/packet-management nil))
                  (do
                    (swap! local-log-atom
                           #(log/info %
                                      ::stop!
                                      "client/stop! Failed logging: chan->server already nil"
                                      {::state/state (dissoc this ::log/state)}))
                    (assoc this
                           ::chan->server nil
                           ::log/state (log/init ::resurrected-during-stop!)
                           ::shared/packet-management nil)))
                (catch Exception ex
                  (swap! local-log-atom
                         #(log/exception %
                                         ex
                                         ::stop!
                                         "Couldn't even do that much"))
                  (assoc this
                         ::chan->server nil
                         ::log/state (log/init ::resurrected-during-stop!)
                         ::shared/packet-management nil))))
            (catch Exception ex
              (swap! local-log-atom
                     #(log/exception %
                                     ex
                                     ::stop!))
              (dfrd/error! stop-finished ex))
            (finally
              (swap! local-log-atom
                     #(log/flush-logs! logger %))
              (dfrd/success! stop-finished true))))
        (println "Successfull reached the bottom of client/stop!")
        (catch Exception ex
          (swap! local-log-atom
                 #(log/exception %
                                 ex
                                 "(send)ing the close function to the client agent failed"))))
      (dfrd/on-realized stop-finished
                        ;; Flushing logs here should be totally redundant.
                        ;; However: This has gotten totally tangled up with the
                        ;; logs coming from somewhere else.
                        ;; So be extra-cautious about what happens here.
                        (fn [success]
                          (println "stop-finished successfully realized at bottom client/stop!")
                          (log/flush-logs! logger @local-log-atom))
                        (fn [fail]
                          (println "stop-finished failed at bottom of client/stop!")
                          (log/flush-logs! logger @local-log-atom)))
      (assoc this
             ::chan->server nil
             ::log/state (log/init ::ended-during-stop!)
             ::shared/packet-management nil))))

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
            ;; This really belongs in state/initialize-immutable-values
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
             ::shared/packet-management (shared/default-packet-manager)
             ::shared/work-area (shared/default-work-area)))]
    (dfrd/on-realized (::state/terminated result)
                      (fn [unexpected]
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
                      (fn [outcome]
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
                                                        {::details outcome}))))))
    result))
