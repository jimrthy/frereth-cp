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
;;; Magic Constants

(set! *warn-on-reflection* true)

(def heartbeat-interval (* 15 shared/millis-in-second))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

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
                                    ::state/vouch
                                    ::shared/work-area]
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
                          (b-t/byte-copy! text 64 64 vouch)
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

(defn hello-succeeded!
  [logger this]
  (as-> (::log/state this) x
    (log/info x
              ::hello-succeeded!
              "Polling complete. Should trigger Initiate/Vouch"
              {::result (dissoc this ::log/state)})
    ;; Note that the log-flush gets discarded, except
    ;; for its side-effects.
    ;; But those side-effects *do* include updating the clock.
    ;; So that seems good enough for rough work.
    (log/flush-logs! logger x)))

(defn hello-failed!
  [this failure]
  (send this #(throw (ex-info "Hello failed"
                              (assoc %
                                     :problem failure)))))

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
        :args (s/cat :wrapper ::state/state-agent
                     :this ::state/state))
(defn servers-polled
  [wrapper
   {log-state ::log/state
    cookie ::specs/network-packet
    :as this}]
  (when-not log-state
    ;; This is an ugly situation.
    ;; Something has gone badly wrong
    (println "Missing log-state among"
             (keys this)
             "\nin\n"
             this
             "\nstate-agent:"
             wrapper))
  (let [this (dissoc this ::specs/network-packet)
        log-state (log/info log-state
                            ::servers-polled!
                            "Building/sending Vouch")]
    ;; This is really where mixing an Agent and Manifold gets tricky.
    (send wrapper (fn [current]
                    ;; This is safe enough for a single-threaded client
                    ;; interaction.
                    ;; At this level, the Client effectively *is*
                    ;; single-threaded.
                    ;; It's its own entity, polling a Seq of servers.
                    ;; Bigger picture, we should have a slew of mostly-
                    ;; independent clients interacting with multiple
                    ;; servers.
                    ;; This is still probably safe in that world.
                    ;; The various Client instances should regularly
                    ;; synchronize their Clocks, possibly when calling
                    ;; flush-logs!, but they should mostly be independent.
                    (merge current (select-keys this [::log/state
                                                      ::shared/packet
                                                      ::state/server-security
                                                      ::state/shared-secrets]))))
    (await wrapper)
    (let [unwrapped @wrapper]
      (when (not= unwrapped this)
        (let [[only-a only-b both] (data/diff unwrapped this)]
          (throw (ex-info "Need to synchronize `this` into wrapper"
                          {::only-in-agent only-a
                           ::only-in-this only-b
                           ::shared both})))))
    ;; Got a Cookie response packet from server.
    ;; Theory in the reference implementation is that this is
    ;; a good signal that it's time to spawn the child to do
    ;; the real work.
    ;; That really seems to complect the concerns.
    ;; But this entire function is a stateful mess.
    ;; At least this helps it stay in one place.
    (send wrapper state/fork! wrapper)
    (initiate/build-and-send-vouch! wrapper cookie)))

(s/fdef poll-servers-with-hello!
        :args (s/cat :this ::state/agent-wrapper
                     :chan->server strm/stream?
                     :timeout nat-int?)
        :ret (s/keys :req [::specs/deferrable
                           ::log/state]))
;; FIXME: This seems like it would make a lot more sense in the
;; hello ns.
;; And broken up into several smaller functions.
(defn poll-servers-with-hello!
  "Send hello packet to a seq of server IPs associated with a single server name."
  ;; In a lot of ways, this amounts to an attempt at load-balancing from the client side.
  ;; Ping a bunch of potential servers (listening on an appropriate port with the
  ;; appropriate public key) in a sequence until you get a response or a timeout.
  ;; In a lot of ways, it was an early attempt at what haproxy does.
  ;; Then again, haproxy doesn't support UDP.
  ;; So maybe this was/is breathtakingly cutting-edge.
  ;; The main point is to avoid waiting 20-ish minutes for TCP connections
  ;; to time out.
  [wrapper timeout]
  (let [{:keys [::log/logger
                ::state/server-ips]
         log-state ::log/state
         {raw-packet ::shared/packet
          :as packet-management} ::shared/packet-management
         :as this} @wrapper
        log-state (log/debug log-state
                             ::poll-servers-with-hello!
                             "Putting hello(s) onto ->server channel"
                             {::raw-hello raw-packet})]
    ;; There's an important break
    ;; with the reference implementation
    ;; here: this should be sending the
    ;; HELLO packet to multiple server
    ;; end-points to deal with them
    ;; going down.
    ;; It's supposed to happen
    ;; in an increasing interval, to give
    ;; each a short time to answer before
    ;; the next, but a major selling point
    ;; is not waiting for TCP buffers
    ;; to expire.
    (let [completion (dfrd/deferred)]
      (dfrd/on-realized completion
                        (partial hello-succeeded! logger)
                        (partial hello-failed! wrapper))
      (loop [this (-> this
                      (assoc ::log/state log-state))
             start-time (System/nanoTime)
             ;; FIXME: The initial timeout needs to be customizable
             timeout (util/seconds->nanos 1)
             ;; Q: Do we really want to max out at 8?
             ;; 8 means over 46 seconds waiting for a response,
             ;; but what if you want the ability to try 20?
             ;; Or don't particularly care how long it takes to get a response?
             ;; Stick with the reference implementation version for now.
             ips (take 8 (cycle server-ips))]
        (let [ip (first ips)
              {log-state ::log/state} this
              log-state (log/info log-state
                                  ::poll-servers-with-hello!
                                  "Polling server"
                                  {::specs/srvr-ip ip})
              cookie-response (dfrd/deferred)
              log-state (log/warn log-state
                                  ::poll-servers-with-hello!
                                  "FIXME: wait-for-cookie! shouldn't need wrapper")
              this (-> this
                       (assoc ::log/state log-state)
                       (assoc-in [::state/server-security ::specs/srvr-ip] ip))
              cookie-waiter (partial cookie/wait-for-cookie!
                                     wrapper
                                     this
                                     cookie-response
                                     timeout)
              dfrd-success (state/do-send-packet this
                                                 cookie-waiter
                                                 identity
                                                 timeout
                                                 ::sending-hello-timed-out
                                                 raw-packet)
              send-packet-success (deref dfrd-success 1000 ::send-response-timed-out)
              actual-success (deref cookie-response timeout ::awaiting-cookie-timed-out)
              now (System/nanoTime)]
          ;; I don't think send-packet-success matters much
          ;; Although...actually, ::send-response-timed-out would be a big
          ;; deal.
          ;; FIXME: Add error handling for that.
          (println "client/poll-servers-with-hello! Sending HELLO returned:"
                   send-packet-success
                   "\nQ: Does that value matter?"
                   "\nactual-success:\n"
                   (dissoc actual-success ::log/state)
                   "\nTop-level keys:\n"
                   (keys actual-success)
                   "\nReceived:\n"
                   (::specs/network-packet actual-success))
          (if (and (not (instance? Throwable actual-success))
                   (not= actual-success ::sending-hello-timed-out)
                   (not= actual-success ::awaiting-cookie-timed-out)
                   (not= actual-success ::send-response-timed-out))
            (let [{log-state ::log/state} actual-success
                  log-state (log/info log-state
                                      ::poll-servers-with-hello!
                                      "Might have found a responsive server"
                                      {::specs/srvr-ip ip})
                  log-state (log/flush-logs! logger log-state)]
              (if-let [{:keys [::specs/network-packet]} actual-success]
                ;; Need to move on to Vouch. But there's already far
                ;; too much happening here.
                ;; So the deferred in completion should trigger servers-polled
                (dfrd/success! completion (assoc actual-success
                                                 ::log/state log-state))
                (let [elapsed (- now start-time)
                      remaining (- timeout elapsed)]
                  (if (< 0 remaining)
                    (recur this
                           start-time
                           ;; Note that this jacks up the orderly timeout progression
                           ;; Not that the progression is quite as orderly as it looked
                           ;; at first glance:
                           ;; there's a modulo against a random 32-byte number involved
                           ;; (line 289)
                           remaining
                           ips)
                    (if-let [remaining-ips (next ips)]
                      (recur this now (* 1.5 timeout) remaining-ips)
                      (dfrd/error! completion (ex-info "Giving up" this)))))))
            (let [this (assoc this (log/warn log-state
                                             ::poll-servers-with-hello!
                                             "Failed to connect"
                                             {::specs/srvr-ip ip
                                              ;; Actually, if this is a Throwable,
                                              ;; we probably don't have a way
                                              ;; to recover
                                              ::outcome actual-success}))]
              (if-let [remaining-ips (next ips)]
                (recur this now (* 1.5 timeout) remaining-ips)
                (dfrd/error! completion (ex-info "Giving up" this)))))))
      {::specs/deferrable completion
       ;; FIXME: Move this back into hello (actually
       ;; that's problematic because it uses a function in
       ;; the cookie ns. And another in here. That really just
       ;; means another indirection layer of callbacks, but
       ;; it's annoying).
       ::log/state log-state})))

(defn chan->server-closed
  [wrapper]
  (send wrapper (fn [{:keys [::log/logger]
                      :as this}]
                  (update this ::log/state
                          #(log/flush-logs! logger
                                            (log/warn %
                                                      ::chan->server-closed)))))
  (send wrapper server-closed!))

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
  "Perform the side-effects to establish a connection with a server"
  ;; This almost seems like it belongs in ctor.

  ;; But not quite, since it's really the first in a chain of side-effects.

  ;; Q: Is there something equivalent I can set up using core.async?

  ;; Actually, this seems to be screaming to be rewritten on top of manifold
  ;; Deferreds.

  ;; For that matter, it seems like setting up a watch on an atom that's
  ;; specifically for something like this might make a lot more sense.

  ;; That way I wouldn't be trying to multi-purpose communications channels.

  ;; OTOH, they *are* the trigger for this sort of thing.

  ;; The reference implementation mingles networking with this code.
  ;; That seems like it might make sense as an optimization,
  ;; but not until I have convincing numbers that it's needed.
  ;; Of course, I might also be opening things up for something
  ;; like a timing attack.

  ;; TODO: Ask for opinions.
  [wrapper]
  (when-let [failure (agent-error wrapper)]
    (throw (ex-info "Agent failed before we started"
                    {:problem failure})))

  (let [{:keys [::state/chan->server]
         :as this} @wrapper
        timeout (state/current-timeout wrapper)]
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
    (if (await-for timeout wrapper)
      (let [{log-state ::log/state
             result ::specs/deferrable}
            ;; Note that this is going to block the calling
            ;; thread. Which is annoying, but probably not
            ;; a serious issue outside of unit tests that
            ;; are mimicking both client and server pieces,
            ;; which need to run this function in a separate
            ;; thread.
            (poll-servers-with-hello! wrapper timeout)]
        (-> result
            (dfrd/chain (partial servers-polled wrapper))
            (dfrd/catch
                (fn [ex]
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
                                    (assoc this ::log/state log-state)))))))
        (dfrd/catch result
            (fn [ex]
              ;; I've seen the deferrable returned by poll-servers-with-hello!
              ;; be an exception at least once.
              ;; Adding this error report seems to have made that problem disapper.
              ;; Maybe I've somehow managed to introduce a race condition.
              (send wrapper (fn [_]
                              (throw (ex-info
                                      "Sending our hello packet to server"
                                      {::this @wrapper}
                                      ex))))))
        (assoc this ::log/state log-state))
      (let [problem (agent-error wrapper)
            {log-state ::log/state
             logger ::log/logger
             :as this} @wrapper]
        (throw (ex-info (str "Timed out after " timeout
                             " milliseconds waiting to build HELLO packet")
                        {::problem problem
                         ::failed-state #(update this ::log/state % (log/flush-logs! logger log-state))}))))))

(s/fdef stop!
        :args (s/cat :state-agent ::state/state-agent)
        :ret any?)
(defn stop!
  [wrapper]
  (println "Trying to stop a client agent\nWrapper:\n"
           wrapper)
  (println "Current state:\n"
           ;; The client state inside the agent is getting
           ;; set to a deferred.
           ;; Somewhere.
           (dissoc @wrapper ::log/state))
  (if-let [ex (agent-error wrapper)]
    (let [logger (log/std-out-log-factory)]
      (log/flush-logs! logger
                       (log/exception (log/init ::failed)
                                      ex
                                      ::stop!
                                      "Client Agent was in error state")))
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
              (println "Made it into the real client stopper")
              (try
                (let [log-state (log/debug log-state
                                           ::stop!
                                           "Top of the real stopper")
                      log-state (state/do-stop (assoc this
                                                      ::log/state log-state))
                      log-state
                      (try
                        (println "Possibly closing the channel to server" chan->server)
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
                         ::shared/packet-management nil)))))
      (catch Exception ex
        (println "(send)ing the close function to the client agent failed\n"
                 ex)))))

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
