(ns frereth-cp.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [byte-streams :as b-s]
            [clojure.data :as data]
            [clojure.spec.alpha :as s]
            [frereth-cp.client.cookie :as cookie]
            [frereth-cp.client.hello :as hello]
            [frereth-cp.client.initiate :as initiate]
            [frereth-cp.client.state :as state]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.logging :as log]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as util]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
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

(defn server-closed!
  "This seems pretty meaningless in a UDP context"
  [this]
  ;; Maybe send a ::closed message to the client?
  (update this
          ::log/state
          #(log/warn %
                     ::server-closed!
                     "Q: Does it make sense to do anything here?")))

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
    (println "Missing log-state among"
             (keys this)
             "\nin\n"
             this))
  (try
    (let [this (dissoc this ::specs/network-packet)
          log-state (log/info log-state
                              ::servers-polled!
                              "Building/sending Vouch")]
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
      (state/fork! this))
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
  [wrapper]
  (send wrapper (fn [{:keys [::log/logger]
                      :as this}]
                  (println "Getting ready to update ::log/state\n"
                           (::log/state this)
                           "\namong\n"
                           (keys this)
                           "\nTo warn that the chan->server closed.")
                  (update this ::log/state
                          #(log/flush-logs! logger
                                            (log/warn %
                                                      ::chan->server-closed)))))
  (send wrapper server-closed!))

(defn set-up-server-polling!
  [wrapper timeout]
  (let [{log-state ::log/state
         outcome ::specs/deferrable}
        ;; Note that this is going to block the calling
        ;; thread. Which is annoying, but probably not
        ;; a serious issue outside of unit tests that
        ;; are mimicking both client and server pieces,
        ;; which need to run this function in a separate
        ;; thread.
        (hello/poll-servers! @wrapper timeout cookie/wait-for-cookie!)
        _ (println "client: triggered hello! polling")
        result (-> outcome
                   (dfrd/chain servers-polled
                               (fn [{:keys [::specs/deferred
                                            ::log/state]
                                     :as this}]
                                 (println "client: servers-polled succeeded:" this)
                                 (-> deferred
                                     (dfrd/chain
                                      (fn [sent]
                                        (if (not (or (= sent ::state/sending-vouch-timed-out)
                                                     (= sent ::state/drained)))
                                          (send-off wrapper (partial state/->message-exchange-mode wrapper) sent)
                                          (throw (RuntimeException. "FIXME: Do something with that")))))
                                     (dfrd/catch
                                         (fn [ex]
                                           (send wrapper #(throw (ex-info "Server vouch response failed"
                                                                          (assoc % :problem ex)))))))))
                   (dfrd/catch
                       (fn [ex]
                         (println "Failure polling servers with hello!\n"
                                  (log/exception-details ex))
                         ;; Q: Does it make more sense to just tip the agent over
                         ;; into an error state?
                         ;; This *is* a pretty big deal
                         (send wrapper (fn [{log-state ::log/state
                                             :keys [::log/logger]
                                             :as this}]
                                         (let [log-state (log/exception log-state
                                                                        ex
                                                                        ::start!
                                                                        "After servers-polled")
                                               log-state (log/flush-logs! logger log-state)]
                                           (assoc this ::log/state log-state)))))))]
    result))

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
  ;; FIXME: Ditch the client agent completely.
  ;; Take the client state as a standard immutable value parameter.
  ;; Return a deferred that's really a chain of everything that
  ;; happens here, up to the point of switching into message-exchange
  ;; mode.
  "Perform the side-effects to establish a connection with a server"
  [wrapper]
  (println "Client: Top of start!")
  (when-let [failure (agent-error wrapper)]
    (throw (ex-info "Agent failed before we started"
                    {:problem failure})))

  (try
    (let [{:keys [::state/chan->server]
           :as this} @wrapper
          timeout (state/current-timeout this)]
      (assert chan->server)
      (strm/on-drained chan->server
                       (partial chan->server-closed wrapper))
      ;; This feels inside-out and backwards.
      ;; But it probably should, since this is very
      ;; explicitly place-oriented programming working
      ;; with mutable state.
      ;; Any way you look at it, it isn't worth doing
      ;; here.
      ;; This is something that happens once at startup.
      ;; So it shouldn't be slow, but this level of optimization
      ;; simply cannot be worth it.
      ;; (Even if we're talking about something like a web browser
      ;; with dozens of open connections...well, a GC delay of a
      ;; second or two to clean this stuff up would be super-
      ;; annoying)
      ;; FIXME: Prune this back to a pure function (yes, that's
      ;; easier said than done: I probably do need to scrap
      ;; the idea of using an agent for this).
      (send wrapper hello/do-build-hello)
      (println "client: told state-agent to build hello packet" )
      (if (await-for timeout wrapper)
        (set-up-server-polling! wrapper timeout)
        (let [problem (agent-error wrapper)
              {log-state ::log/state
               logger ::log/logger
               :as this} @wrapper]
          (throw (ex-info (str "Timed out after " timeout
                               " milliseconds waiting to build HELLO packet")
                          {::problem problem
                           ::failed-state #(update this ::log/state % (log/flush-logs! logger log-state))})))))
    (catch Exception ex
      (println "client: Failed before I could even get to a logger:\n"
               (log/exception-details ex)))))

(s/fdef stop!
        :args (s/cat :state-agent ::state/state-agent)
        :ret ::state/state)
(defn stop!
  [wrapper]
  (let [local-log-atom (atom (log/init ::stop!))]
    (try
      (swap! local-log-atom #(log/debug %
                                        ::stop!
                                        "Trying to stop a client agent"
                                        {::wrapper wrapper
                                         ::wrapper-class (class wrapper)
                                         ::wrapper-content-class (class @wrapper)}))
      ;; The client state inside the agent is getting
      ;; set to a deferred.
      ;; Somewhere.
      (swap! local-log-atom #(log/debug %
                                        ::stop!
                                        "Current state"
                                        {::state/state (dissoc @wrapper ::log/state)}))
      (if-let [ex (agent-error wrapper)]
        (swap! local-log-atom #(log/exception (log/init ::failed)
                                              ex
                                              ::stop!
                                              "Client Agent was in error state"))
        ;; Somewhere between checking for the agent-error and this next send,
        ;; the client agent is very consistently going into an error state.
        ;; This is worrisome.
        ;; And yet another reason to just ditch the thing.
        (try
          ;; It seems like it might also make sense to make sure the child
          ;; message loop (if any) exits.
          ;; FIXME: Make sure that goes away
          (send wrapper
                (fn [{:keys [::state/chan->server
                             ::log/logger
                             ::shared/packet-management]
                      log-state ::log/state
                      :as this}]
                  (swap! local-log-atom #(log/trace % ::stop! "Made it into the real client stopper"))
                  (if log-state
                    (try
                      (let [log-state (log/debug log-state
                                                 ::stop!
                                                 "Top of the real stopper")
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
                    (try
                      (swap! local-log-atom
                             #(log/warn %
                                        ::stop!
                                        "Missing log-state. Trying to close the channel to server"
                                        {::state/chan->server chan->server}))
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
                                               "Couldn't even do that much"))
                        (assoc this
                               ::chan->server nil
                               ::log/state (log/init ::resurrected-during-stop!)
                               ::shared/packet-management nil))))))
          (catch Exception ex
            (swap! local-log-atom
                   #(log/exception %
                                   ex
                                   "(send)ing the close function to the client agent failed"))
            (assoc @wrapper
                   ::chan->server nil
                   ::log/state (log/init ::resurrected-during-stop!)
                   ::shared/packet-management nil))))
      (finally
        (let [logger (log/std-out-log-factory)]
          (log/flush-logs! logger @local-log-atom))))))

(s/fdef ctor
        :args (s/cat :opts (s/keys :req [::msg-specs/->child
                                         ::state/chan->server
                                         ::specs/message-loop-name
                                         ::shared/my-keys
                                         ::state/server-security])
                     :log-initializer (s/fspec :args nil
                                               :ret ::log/logger))
        :ret ::state/state-agent)
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
       ::shared/work-area (shared/default-work-area))
      ;; Using a core.async go-loop is almost guaranteed
      ;; to be faster.
      ;; TODO: Verify the "almost" with numbers.
      ;; The more I try to switching, the more dubious this
      ;; approach seems.
      ;; pipelines might not make a lot of sense on the client,
      ;; since they're at least theoretically about increasing
      ;; throughput at the expense of latency.
      ;; But they probably make a lot of sense on some servers.
      agent))
