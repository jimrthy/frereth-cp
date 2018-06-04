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

(defn extract-child-message
  "Pretty much blindly translated from the CurveCP reference
implementation. This is code that I don't understand yet"
  [this buffer]
  ;; FIXME: Don't eliminate completely yet. There's at least one
  ;; cross-reference to this in a comment in client.state.
  ;; Have to eliminate that first.
  ;; TODO: Make that happen soon.
  (throw (RuntimeException. "obsolete"))
  (let [reducer (fn [{:keys [:buf-len
                             :msg-len
                             :i
                             :this]
                      ^bytes buf :buf
                      ^bytes msg :msg
                      :as acc}
                     b]
                  (when (or (< msg-len 0)
                            ;; This is the flag that the stream has exited.
                            ;; Q: Is that what it's being used for here?
                            (> msg-len 2048))
                    (throw (ex-info "done" {})))
                  ;; It seems silly to set this and then check the first byte
                  ;; for the quit signal (assuming that's what it is)
                  ;; every time through the loop.
                  (aset msg msg-len (aget buf i))
                  (let [msg-len (inc msg-len)
                        length-code (aget msg 0)]
                    (when (bit-and length-code 0x80)
                      (throw (ex-info "done" {})))
                    ;; This is really checking to see whether we've pulled
                    ;; the promised number of bytes out of the child's read
                    ;; pipe. This part of the code has been totally revamped
                    ;; to reflect the fact that we're using the JVM instead of
                    ;; raw C, and we don't have three different processes
                    ;; communicating over anonymous pipes.
                    ;; This code is a pretty strong indication
                    ;; that this function should go away.
                    (if (= msg-len (inc (* 16 length-code)))
                      (let [{:keys [::shared/extension
                                    ::shared/my-keys
                                    ::shared/packet-management
                                    ::state/server-extension
                                    ::state/shared-secrets
                                    ::state/server-security
                                    ::shared/work-area
                                    ::specs/inner-i-vouch]
                             log-state ::log/state
                             :as this} (state/clientextension-init this)
                            {:keys [::shared/text]} work-area
                            {:keys [::shared/packet
                                    ::shared/packet-nonce]} packet-management
                            _ (throw (RuntimeException. "this Component nonce isn't updated"))
                            short-term-nonce (state/update-client-short-term-nonce
                                              packet-nonce)
                            working-nonce (::shared/working-nonce work-area)]
                        (b-t/uint64-pack! working-nonce K/client-nonce-prefix-length
                                             short-term-nonce)
                        ;; This is where the original splits, depending on whether
                        ;; we've received a message back from the server or not.
                        ;; According to the spec:
                        ;; The server is free to send any number of Message packets
                        ;; after it sees the Initiate packet.
                        ;; The client is free to send any number of Message packets
                        ;; after it sees the server's first Message packet.
                        ;; At this point in time, we know we're still building the
                        ;; Initiate packet.
                        ;; It's tempting to try to avoid duplication the same
                        ;; way the reference implementation does, by handling
                        ;; both logical branches here.
                        ;; And maybe there's a really good reason for doing so.
                        ;; But this function feels far too complex as it is.
                        (let [r (dec msg-len)
                              ^TweetNaclFast$Box$KeyPair my-long-pair (::shared/long-pair my-keys)]
                          (when (or (< r 16)
                                    (> r 640))
                            (throw (ex-info "done" {})))
                          (b-t/byte-copy! working-nonce 0 K/client-nonce-prefix-length
                                          K/initiate-nonce-prefix)
                          ;; TODO: Use compose instead
                          (shared/zero-out! text 0 K/decrypt-box-zero-bytes)
                          ;; This 32-byte padding seems very surprising, since the
                          ;; specs all seem to point to just needing 16.
                          ;; That's just one of the fun little details about the
                          ;; way the underlying library works.
                          (b-t/byte-copy! text K/decrypt-box-zero-bytes
                                          K/key-length
                                          (.getPublicKey my-long-pair))
                          (b-t/byte-copy! text 64 64 inner-i-vouch)
                          (b-t/byte-copy! text
                                          128
                                          specs/server-name-length
                                          (::specs/srvr-name server-security))
                          ;; First byte is a magical length marker
                          ;; TODO: Double-check the original.
                          ;; This doesn't look right at all.
                          ;; I think I need a 32-byte offset for the decryption
                          ;; padding.
                          ;; And the call to open-after really seems like it should start
                          ;; at offset 384 instead of 0
                          (b-t/byte-copy! text 384 r msg 1)
                          (let [box (crypto/open-after (::state/client-short<->server-short shared-secrets)
                                                       text
                                                       0
                                                       (+ r 384)
                                                       working-nonce)
                                offset K/server-nonce-prefix-length]
                            ;; TODO: Switch to compose for this
                            (b-t/byte-copy! packet
                                            0
                                            offset
                                            K/initiate-header)
                            (b-t/byte-copy! packet offset
                                            K/extension-length server-extension)
                            (let [offset (+ offset K/extension-length)]
                              (b-t/byte-copy! packet offset
                                              K/extension-length extension)
                              (let [offset (+ offset K/extension-length)
                                    ^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)]
                                (b-t/byte-copy! packet offset K/key-length
                                                (.getPublicKey my-short-pair))
                                (let [offset (+ offset K/key-length)]
                                  (b-t/byte-copy! packet
                                                  offset
                                                  K/server-cookie-length
                                                  (::state/server-cookie server-security))
                                  (let [offset (+ offset K/server-cookie-length)]
                                    (b-t/byte-copy! packet offset
                                                    K/server-nonce-prefix-length
                                                    working-nonce
                                                    K/server-nonce-suffix-length)))))
                            ;; Original version sends off the packet, updates
                            ;; msg-len to 0, and goes back to pulling data from child/server.
                            (throw (ex-info "How should this really work?"
                                            {:problem "Need to break out of loop here"})))))
                      (assoc acc :msg-len msg-len))))
        extracted (reduce reducer
                          {:buf (byte-array 4096)
                           :buf-len 0
                           :msg (byte-array 2048)
                           :msg-len 0
                           :i 0
                           :this this}
                          buffer)]
    (assoc this ::state/outgoing-message (:child-msg extracted))))

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
  [{log-state ::log/state
    logger ::log/logger
    cookie ::specs/network-packet
    :as this}]
  (println "client: Top of servers-polled")
  (when-not log-state
    ;; This is an ugly situation.
    ;; Something has gone badly wrong
    ;; TODO: Write to a STDOUT logger instead
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
          ;; will start as a partial built frombuild-initiate-packet!
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

(s/fdef set-up-server-hello-polling!
        :args (s/cat :this ::state/state
                     :timeout (s/and #((complement neg?) %)
                                     int?))
        ;; Hmm.
        ;; This deferrable will get delivered as either
        ;; a) new State, after we get a Cookie response
        ;; b) a Exception, if the hello polling fails
        ;; Option a needs to be refined: we really should
        ;; just get back the log-state and the Cookie (assuming
        ;; it was valid)
        :ret ::specs/deferrable)
(defn set-up-server-hello-polling!
  "Start polling the server(s) with HELLO Packets"
  [{:keys [::log/logger]
    :as this}
   timeout]
  (let [{log-state ::log/state
         outcome ::specs/deferrable}
        ;; Note that this is going to block the calling
        ;; thread. Which is annoying, but probably not
        ;; a serious issue outside of unit tests that
        ;; are mimicking both client and server pieces,
        ;; which need to run this function in a separate
        ;; thread.
        ;; Note 2: Including the cookie/wait-for-cookie! callback
        ;; is the initial, most obvious reason that I haven't
        ;; moved this to the hello ns yet.
        ;; TODO: Convert that to another parameter (soon).
        (hello/poll-servers! this timeout cookie/wait-for-cookie!)]
    (println "client: triggered hello! polling")
    (-> outcome
        (dfrd/chain #(into % (initiate/build-inner-vouch %))
                    servers-polled
                    ;; Based on what's written here, deferrable involves
                    ;; the success of...what? Getting the Cookie from
                    ;; the server?
                    (fn [{:keys [::specs/deferrable
                                 ::log/state]
                          :as this}]
                      (println "client: servers-polled succeeded:" (dissoc this ::log/state))
                      (let [log-state (log/flush-logs! logger state)]
                        ;; This is at least a little twisty.
                        ;; And seems pretty wrong. In the outer context, outcome
                        ;; was a deferrable that got added to this by
                        ;; hello/poll-servers!
                        ;; That returns a ::log/state.
                        ;; Q: How has this ever worked?
                        ;; Alt Q: Has it ever?
                        ;; A: I don't think I've ever gotten this far.
                        ;; It seems like a crash and burn just waiting to happen.
                        ;; FIXME: Get back to this.
                        (dfrd/chain deferrable
                                    (fn [sent]
                                      (if (not (or (= sent ::state/sending-vouch-timed-out)
                                                   (= sent ::state/drained)))
                                        (state/->message-exchange-mode (assoc this
                                                                              ::log/state log-state)
                                                                       sent)
                                        (throw (ex-info "Something about polling/sending Vouch failed"
                                                        {::problem sent})))))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef start!
        :args (s/cat :this ::state/state-agent)
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
    :as this}]
  {:pre [chan->server]}
  (try
    (let [timeout (state/current-timeout this)]
      ;; FIXME: Log this instead
      (println "client/start! Wiring side-effects through chan->server")
      (strm/on-drained chan->server
                       (partial chan->server-closed this))
      (let [this (hello/do-build-packet this)]
        (set-up-server-hello-polling! this timeout)))
    (catch Exception ex
      ;; Knee-jerk reaction is to switch this to a logger.
      ;; But the point is that I can't.
      ;; TODO: At least write to STDERR instead.
      (println "client: Failed before I could even get to a logger:\n"
               (log/exception-details ex)))))

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
       ::shared/work-area (shared/default-work-area))))
