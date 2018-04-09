(ns frereth-cp.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.client.cookie :as cookie]
            [frereth-cp.client.hello :as hello]
            [frereth-cp.client.initiate :as initiate]
            [frereth-cp.client.state :as state]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.logging :as log2]
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

(s/def ::deferrable dfrd/deferrable?)

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

(defn hello-failed!
  [this failure]
  (send this #(throw (ex-info "Hello failed"
                              (assoc %
                                     :problem failure)))))

(defn server-closed!
  "This seems pretty meaningless in a UDP context"
  [this]
  (throw (ex-info "Server Closed" this)))

(defn child->server
  "Child sent us (as an agent) a signal to add bytes to the stream to the server"
  [this msg]
  (throw (RuntimeException. "Not translated")))

(defn server->child
  "Received bytes from the server that need to be streamed back to child"
  [this msg]
  (throw (RuntimeException. "Not translated")))

(s/fdef cope-with-successfullo-creation!
        :args (s/cat :this ::state/agent-wrapper
                     :chan->server strm/stream?
                     :timeout nat-int?)
        :ret (s/keys :req [::deferrable
                           ::log2/state]))
(defn cope-with-successful-hello-creation!
  "This name dates back to a time when building a hello packet was problematic"
  ;; FIXME: Refactor to one that's less pessimistic
  [wrapper chan->server timeout]
  (let [{:keys [::shared/packet-management
                ::state/server-security]
         log-state ::log2/state
         :as this} @wrapper
        raw-packet (::shared/packet packet-management)
        log-state (log2/debug log-state
                              ::cope-with-successful-hello-creation
                              "Putting hello onto ->server channel"
                              {::raw-hello raw-packet
                               ::state/chan->server chan->server})]
    ;; There's an important break
    ;; with the reference implementation
    ;; here: this should be sending the
    ;; HELLO packet to multiple server
    ;; end-points to deal with them
    ;; going down.
    ;; I think it's supposed to happen
    ;; in a delayed interval, to give
    ;; each a short time to answer before
    ;; the next, but a major selling point
    ;; is not waiting for TCP buffers
    ;; to expire.
    ;; There's an interesting conundrum here:
    ;; it probably makes more sense to handle that
    ;; sort of detail closer to the network boundary.
    ;; Except that this really *is* the network boundary.
    (let [d (strm/try-put! chan->server
                           {:host (::specs/srvr-name server-security)
                            :message raw-packet
                            :port (::shared/srvr-port server-security)}
                           timeout
                           ::sending-hello-timed-out)]
      {::log2/state log-state
       ;; FIXME: use dfrd/chain instead of manually building
       ;; up the chain using on-realized.
       ;; Although being explicit about the failure
       ;; modes is nice.
       ;; And it's not like this is much of a chain
       ;; ...is it?
       ::deferrable (dfrd/on-realized d
                                      (partial cookie/wait-for-cookie wrapper)
                                      (partial hello-failed! wrapper))})))

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
  "This almost seems like it belongs in ctor.

But not quite, since it's really the first in a chain of side-effects.

Q: Is there something equivalent I can set up using core.async?

Actually, this seems to be screaming to be rewritten on top of manifold
Deferreds.

For that matter, it seems like setting up a watch on an atom that's
specifically for something like this might make a lot more sense.

That way I wouldn't be trying to multi-purpose communications channels.

OTOH, they *are* the trigger for this sort of thing.

The reference implementation mingles networking with this code.
That seems like it might make sense as an optimization,
but not until I have convincing numbers that it's needed.
Of course, I might also be opening things up for something
like a timing attack."
  [wrapper]
  (when-let [failure (agent-error wrapper)]
    (throw (ex-info "Agent failed before we started"
                    {:problem failure})))

  (let [{:keys [::state/chan->server]
         :as this} @wrapper
        timeout (state/current-timeout wrapper)]
    (strm/on-drained chan->server
                     (fn []
                       (send wrapper (fn [{:keys [::log2/logger]
                                           :as this}]
                                       (update this ::log2/state
                                               (log2/flush-logs! logger #(log2/warn %
                                                                                    ::start!
                                                                                    "Channel->server closed")))))
                       (send wrapper server-closed!)))
    ;; This feels inside-out and backwards.
    ;; But it probably should, since this is very
    ;; explicitly place-oriented programming working
    ;; with mutable state.
    ;; Any way you look at it, it isn't worth doing
    ;; here.
    ;; This is something that happens once at startup.
    ;; So it shouldn't be slow, but this level of optimization
    ;; simply cannot be worth it.
    ;; FIXME: Prune this back to a pure function (yes, that's
    ;; easier said than done: I probably do need to scrap
    ;; the idea of using an agent for this).
    (send wrapper hello/do-build-hello)
    (if (await-for timeout wrapper)
      (let [{log-state ::log2/state
             result ::deferrable}
            (cope-with-successful-hello-creation! wrapper chan->server timeout)]
        (dfrd/catch result
            (fn [ex]
              ;; I've seen the deferrable returned by cope-with-successful-hello-creation!
              ;; be an exception at least once.
              ;; Adding this error report seems to have made that problem disapper.
              ;; Maybe I've somehow managed to introduce a race condition.
              (send wrapper (fn [_]
                              (throw (ex-info
                                      "Sending our hello packet to server"
                                      {::this @wrapper}
                                      ex))))))
        (assoc this ::log2/state log-state))
      (let [problem (agent-error wrapper)
            {log-state ::log2/state
                            logger ::log2/logger
                            :as this} @wrapper]
        (throw (ex-info (str "Timed out after " timeout
                             " milliseconds waiting to build HELLO packet")
                        {::problem problem
                         ::failed-state #(update this ::log2/state % (log2/flush-logs! logger log-state))}))))))

(s/fdef stop!
        :args (s/cat :state-agent ::state/state-agent)
        :ret any?)
(defn stop!
  [wrapper]
  (if-let [ex (agent-error wrapper)]
    (let [logger (log2/std-out-log-factory)]
      (log2/exception (log2/init ::failed)
                      ex
                      ::stop!))
    (send wrapper
          (fn [{:keys [::chan->server
                       ::shared/packet-management]
                :as this}]
            (strm/close! chan->server)
            (assoc this
                   ::chan->server nil
                   ::shared/packet-management nil)))))

(s/fdef ctor
        :args (s/cat :opts (s/keys :req [::msg-specs/->child
                                         ::state/chan->server
                                         ::specs/message-loop-name
                                         ::shared/my-keys
                                         ::state/server-security])
                     :log-initializer (s/fspec :args nil
                                               :ret ::log2/logger))
        :ret ::state/state-agent)
(defn ctor
  [opts logger-initializer]
  (-> opts
      (state/initialize-immutable-values logger-initializer)
      ;; This really belongs in state/initialize-immutable-values
      ;; But that would create circular imports.
      ;; This is a red flag.
      ;; FIXME: Come up with a better place for it to live.
      (assoc ::packet-builder initiate/build-initiate-packet!)
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
