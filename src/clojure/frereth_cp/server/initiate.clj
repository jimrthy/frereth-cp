(ns frereth-cp.server.initiate
  "For coping with Initiate packets

This is the part that possibly establishes a 'connection'"
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.server
             [message :as message]
             [state :as state]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log2]
             [serialization :as serial]
             [specs :as specs]
             [templates :as templates]]
            [frereth-cp.util :as util]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import clojure.lang.ExceptionInfo
           com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           [io.netty.buffer ByteBuf Unpooled]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Named Constants

;; This number is based on the basic Client Initiate packet details spec:
;; (+ 8 96 32 16 16 8 368)
(def packet-header-length 544)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(s/def ::handled? boolean?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal implementation

(s/fdef decrypt-initiate-vouch!
        :args (s/cat :nonce :shared/client-nonce
                     :box (s/and bytes?
                                 #(< (count %) K/minimum-vouch-length)))
        :ret (s/nilable bytes?))
;; TODO: Write server-test/vouch-extraction to gain confidence that
;; this works
(defn decrypt-initiate-vouch!
  [shared-key nonce-suffix box nonce]
  (b-t/byte-copy! nonce K/initiate-nonce-prefix)
  (b-t/byte-copy! nonce
                  specs/client-nonce-prefix-length
                  specs/client-nonce-suffix-length
                  nonce-suffix)
  (try
    (let [plain-vector (crypto/open-after box 0 (count box) nonce shared-key)]
      ;; Stuffing this into a vector and then extracting it back to a
      ;; byte-array is a wasted round-trip.
      ;; FIXME: Add a crypto routine to avoid that.
      ;; It may be premature optimization that clutters the API,
      ;; but it cuts out the extra conversion here, and it certainly
      ;; won't hurt performance.
      (byte-array plain-vector))
    (catch ExceptionInfo ex
      (log/error ex (util/pretty (.getData ex))))))

(s/fdef possibly-re-initiate-existing-client-connection!
        :args (s/cat :state ::state
                     :initiate-packet ::K/initiate-packet-spec)
        :ret (s/keys :req [::log2/state]
                     :opt [::handled?]))
(defn possibly-re-initiate-existing-client-connection!
  "Client can send as many Initiate packets as it likes.

  If this matches a connection we've already seen, append the Message
  portion to the child-handler's queue.

  returns (handled?):
    true:  Handled here
    false: Not handled. Propagate the event

  This seems like it ought to be part of a bigger, more comprehensive
  event handling system.

  To be fair, this ns *is* pretty special."
  [{log-state ::log2/state
    :as state} initiate]
  ;; In the reference implementation, this basically corresponds to
  ;; lines 341-358.
  ;; Find the matching client (if any).
  (let [client-short-key (::clnt-short-pk initiate)]
    ;; This seems scary.
    ;; It's an under-the-hood implementation detail, but seems
    ;; worth mentioning that, under the hood, state converts the
    ;; byte-array to a vec.
    (if-let [client (state/find-client state client-short-key)]
      ;; If there is one, extract the message portion
      (let [log-state (log2/info log-state
                                 ::possibly-re-initiate-existing-client-connection!
                                 "Initiate packet from known client")
            packet-nonce-bytes (::specs/nonce initiate)
            packet-nonce (b-t/uint64-unpack packet-nonce-bytes)
            last-packet-nonce (::state/received-nonce client)]
        (if (< last-packet-nonce packet-nonce)  ; line 343
          ;; This is an address in the stream that we haven't seen yet.
          ;; Need to forward it along
          (let [vouch (:K/vouch initiate)
                shared-key (::state/client-short<->server-short client)]
            (if-let [plain-text (decrypt-initiate-vouch! shared-key
                                                         packet-nonce-bytes
                                                         vouch)]
              ;; Line 351
              (let [state (update-in state [client-short-key ::state/received-nonce] packet-nonce)]
                ;; That takes us down to line 352.
                ;; Q: What's going on there?
                ;; text[383] = (r - 544) >> 4;
                ;; Translation:
                ;; The message associated with the Initiate packet starts
                ;; at byte 384.
                ;; The reference implementation inserts a prefix byte
                ;; (length/16)
                ;; before sending the array to the associated child
                ;; process in the next line:
                ;; writeall(activeclients[i].tochild, text+383, r-543)
                (throw (RuntimeException. "start back here")))
              {::log/state (log2/warn log-state

                                      "Unable to decrypt incoming vouch")
               ::handled? true}))
          {::log2/state (log2/debug log-state
                                    "Discarding obsolete nonce"
                                    {::shared/packet-nonce packet-nonce
                                     ::last-packet-nonce last-packet-nonce})
           ::handled? true}))
      {::log2/state log-state})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef decrypt-inner-vouch!
        :args (s/cat :cookie-cutter ::state/cookie-cutter
                     :dst any?
                     :hello-cookie any?)
        :ret boolean?)
;; FIXME: Have this return the logs.
;; And possibly the extracted cookie bytes, if we managed to
;; decrypt them.
(defn decrypt-inner-vouch!
  [cookie-cutter dst hello-cookie]
  (log/debug "Trying to extract cookie based on current minute-key")
  ;;; Set it up to extract from the current minute key

  ;; Start with the initial 0-padding
  (b-t/zero-out! dst 0 K/box-zero-bytes)
  ;; Copy over the 80 bytes of crypto text from the initial cookie.
  ;; Note that this part is tricky:
  ;; The "real" initial cookie is 96 bytes long:
  ;; * 32 bytes of padding
  ;; * 32 bytes of client short-term key
  ;; * 32 bytes of server short-term key
  ;; That's 80 bytes crypto text.
  ;; But then the "crypto black box" that just round-tripped
  ;; through the client includes 16 bytes of a nonce, taking
  ;; it back up to 96 bytes.
  (b-t/byte-copy! dst
                  K/box-zero-bytes
                  K/hello-crypto-box-length
                  hello-cookie
                  specs/server-nonce-suffix-length)
  (let [;; Q: How much faster/more efficient is it to have a
        ;; io.netty.buffer.PooledByteBufAllocator around that
        ;; I could use for either .heapBuffer or .directBuffer?
        ;; (as opposed to creating my own local in the let above)
        nonce (byte-array K/nonce-length)]
    (try
      (b-t/byte-copy! nonce K/cookie-nonce-minute-prefix)
      (b-t/byte-copy! nonce
                      specs/server-nonce-prefix-length
                      specs/server-nonce-suffix-length
                      hello-cookie)
      (crypto/secret-unbox dst dst K/server-cookie-length nonce (::state/minute-key cookie-cutter))
      true
      (catch ExceptionInfo _
        ;; Try again with the previous minute-key
        (log/debug "That failed. Try again with the previous minute-key")
        (shared/zero-out! dst 0 K/box-zero-bytes)
        (b-t/byte-copy! dst
                        K/box-zero-bytes
                        K/hello-crypto-box-length
                        hello-cookie
                        specs/server-nonce-suffix-length)

        (try
          (crypto/secret-unbox dst
                               dst
                               K/server-cookie-length
                               nonce
                               (::state/last-minute-key cookie-cutter))
          true
          (catch ExceptionInfo _
            ;; Reference implementation just silently discards the
            ;; failure.
            ;; That's more efficient at this level, but seems to
            ;; discard the possibilities of attack mitigation.
            (log/warn "Extracting the original crypto-box failed")
            ;; Be explicit about returning failure
            false))))))

(s/fdef verify-client-pk-in-vouch
        :args (s/cat :destructured-initiate-packet ::K/initiate-packet-spec
                     :inner-vouch-decrypted-box (s/and bytes?
                                                       #(= K/key-length
                                                           (count %))))
        :ret boolean?)
(defn verify-client-pk-in-vouch
  [initiate hidden-pk]
  (let [expected (bytes (::K/clnt-short-pk initiate))]
    ;; This is disconcerting.
    ;; The values I'm seeing here very obviously do not match.
    ;; But apparently bytes= thinks they do.
    ;; FIXME: What are the odds that I'm missing a
    ;; box-opening step? And that, somehow, the crypto
    ;; text (?) evaluates as bytes= to the clear text?
    (throw (RuntimeException. "Start back with this"))
    (log/debug "Cookie extraction succeeded. Q: Do the contents match?"
               "\nExpected:\n"
               (shared/bytes->string expected)
               "\nActual:\n"
               (shared/bytes->string hidden-pk))
    (b-t/bytes= hidden-pk expected)))

(s/fdef update-state-with-new-active-client
  :args (s/cat :state ::state/state
               :server-short-sk bytes?
               :nearly-active-client ::state/client-state
               :client-short-pk any?)
  :ret ::state/state)
(defn update-state-with-new-active-client
  [state
   server-short-sk
   nearly-active-client
   client-short-pk]
  (let [active-client (state/configure-shared-secrets nearly-active-client
                                                      client-short-pk
                                                      server-short-sk)]
    (state/alter-client-state state active-client)))

(s/fdef configure-new-active-client
  :args (s/cat :state ::state/state
               :client-short-pk ::shared/short-pk
               :cookie ::templates/cookie-spec)
  :ret (s/keys :req [::shared/secret-key
                     ::state/client-state
                     ::state/state]))
(defn configure-new-active-client
  "Update the active-client in state. Juggle around some other values"
  [state
   client-short-pk
   cookie]
  (let [active-client (state/find-client state
                                         client-short-pk)
        {:keys [::templates/srvr-short-sk]}  cookie
        server-short-sk (bytes srvr-short-sk)]
    (assert server-short-sk (str "Missing ::templates/srvr-short-sk among "
                                 (keys cookie)))
    {::state/client-state active-client
     ::shared/secret-key server-short-sk
     ::state/state (update-state-with-new-active-client server-short-sk
                                                        active-client
                                                        client-short-pk)}))

(s/fdef extract-cookie
        :args (s/cat :cookie-cutter ::state/cookie-cutter
                     :initiate-packet ::K/initiate-packet-spec)
        :ret (s/nilable ::templates/cookie-spec))
(defn extract-cookie
  "Verify we can open our secret crypto box

  ...using either the current or previous minute-key.

  This corresponds to lines 359-368. "
  [{:keys [::state/minute-key
           ::state/last-minute-key]
    :as cookie-cutter}
   initiate]

  ;; Errors here get logged (Q: Do they?), but there's no good way
  ;; for the caller to know that there was a problem.
  ;; Well, the "client" that put the message onto the stream.
  ;; This is annoying for unit tests, but realistic for
  ;; the real world.
  ;; Outside the unit test scenario, the "client" is whatever
  ;; pulled data from the UDP socket.
  ;; And that shouldn't be coping with problems at this level.
  ;; In a way, this beats the reference implementation, which
  ;; just silently discards the packet.
  ;; Although that approach is undeniably faster than throwing
  ;; an exception and logging the problem
  (let [hello-cookie (bytes (::K/cookie initiate))
        inner-vouch-bytes (byte-array K/server-cookie-length)]
    (when (decrypt-inner-vouch! cookie-cutter inner-vouch-bytes hello-cookie)
      ;; Reference code:
      ;; Verifies that the "first" 32 bytes (after the 32 bytes of
      ;; decrypted 0 padding) of the 80 bytes it decrypted
      ;; out of the inner vouch match the client short-term
      ;; key in the outer initiate packet.
      (let [full-decrypted-vouch (vec inner-vouch-bytes)
            ;; Round-tripping through a vector seems pretty ridiculous.
            ;; I really just want to verify that the first 32 bytes match
            ;; the supplied key.
            ;; Except that it's really bytes 16-47, isn't it?
            key-array (byte-array (subvec full-decrypted-vouch 0 K/key-length))]
        ;; This hasn't decrypted the "real" inner crypto box.
        ;; That really happens in verify-client-public-key-triad.
        ;; TODO: Need to untangle the chain of logic and nested
        ;; function calls.
        (throw (RuntimeException. "I'm expecting too much here"))
        (when (verify-client-pk-in-vouch initiate key-array)
          ;; TODO: Need to add a Pooled Allocator to the server state
          ;; for this.
          ;; Q: Don't I?
          (let [vouch-buf (Unpooled/wrappedBuffer inner-vouch-bytes)]
            (serial/decompose templates/black-box-dscr vouch-buf)))))))

(s/fdef open-client-crypto-box
  :args (s/cat :log-state ::log2/state
               :initiate ::K/initiate-packet-spec
                     :current-client ::client-state)
  :ret (s/keys :req [::log2/state]
               :opt [::K/initiate-client-vouch-wrapper]))
(defn open-client-crypto-box
  [log-state
   {:keys [::K/outer-i-nonce]
    ^bytes vouch-wrapper ::K/vouch-wrapper
    :as initiate}
   current-client]

  (println "Mark: top of open-client-crypto-box")
  (let [log-state (log2/info log-state
                             ::open-client-crypto-box
                             "Opening the Crypto box we just received from the client")
        vouch-length (count vouch-wrapper)
        log-state (log2/debug log-state
                              ::open-client-crypto-box
                              (str "The box we're opening is " vouch-length " bytes long"))
        message-length (- vouch-length K/minimum-vouch-length)
        {log-state ::log2/state
         clear-text ::crypto/unboxed
         :as unboxed} (try
                        (crypto/open-box log-state
                                         K/initiate-nonce-prefix
                                         outer-i-nonce
                                         vouch-wrapper
                                         (get-in current-client [::state/shared-secrets
                                                                 ::state/client-short<->server-short]))
                        (catch Exception ex
                          (println "Mark: Opening crypto-box failed")
                          {::log2/state (log2/exception log-state ex
                                                        ::open-client-crypto-box)}))]
    (println (str "Mark: crypto-box open succeeded. unboxed: '" (dissoc unboxed ::log2/state) "'."))
    (if clear-text
      {::log2/state (log2/info log-state
                               ::open-client-crypto-box
                               "Decomposing...")
       ::K/initiate-client-vouch-wrapper (serial/decompose (assoc-in K/initiate-client-vouch-wrapper
                                                                     [::K/message ::K/length]
                                                                     message-length)
                                                           clear-text)}
      {::log2/state (log2/warn log-state
                               ::open-client-crypto-box
                               "Opening client crypto vouch failed")})))

(s/fdef validate-server-name
        :args (s/cat :state ::state/state
                     :inner-client-box ::K/initiate-client-vouch-wrapper)
        :ret boolean?)
(defn validate-server-name
  [state inner-client-box]
  (let [rcvd-name (::specs/srvr-name inner-client-box)
        rcvd-name (bytes rcvd-name)
        my-name (get-in state [::shared/my-keys ::specs/srvr-name])
        match (b-t/bytes= rcvd-name my-name)]
    (when-not match
      (log/warn (str "Message was intended for another server\n"
                     "Sent to:\n"
                     (b-t/->string rcvd-name)
                     "My name:\n\""
                     (b-t/->string my-name)
                     "\"\nout of:\n"
                     (keys (::shared/my-keys state)))))
    match))

(s/fdef verify-client-public-key-triad
        :args (s/cat :state ::state/state
                     :supplied-client-short-key ::shared/short-pk
                     ;; TODO: This should be covered in constants or spec.
                     ;; Assuming it isn't already.
                     ;; Note that it's already been decomposed to include
                     ;; the long-term-pk
                     ::client-message-box any?)
        :ret (s/nilable boolean?))
(defn verify-client-public-key-triad
  "We unwrapped the our original cookie, using the minute-key.

And the actual message box using the client's short-term public key.
That box included the client's long-term public key.

Now there's a final box nested that contains the short-term key again,
encrypted with the long-term key.

This step verifies that the client really does have access to that key.

It's flagged as \"optional\" in the reference implementation, but that seems
a bit silly.

This corresponds, roughly, to lines 382-391 in the reference implementation.

Note that that includes TODOs re:
* impose policy limitations on clients: known, maxconn
* for known clients, retrieve shared secret from cache
"
  [{log-state ::log2/state
    :as state}
   short-pk
   client-message-box]
  (let [^bytes client-long-key (::K/long-term-public-key client-message-box)]
    (let [^TweetNaclFast$Box$KeyPair long-pair (get-in state [::shared/my-keys ::shared/long-pair])
          my-long-secret (.getSecretKey long-pair)
          shared-secret (crypto/box-prepare client-long-key
                                            my-long-secret)
          ^TweetNaclFast$Box$KeyPair long-pair (get-in state [::shared/my-keys ::shared/long-pair])
          log-state (log2/info log-state
                               ::verify-client-public-key-triad
                               (str "Getting ready to decrypt the inner-most hidden public key\n"
                                    "FIXME: Don't log any secret keys")
                               {::client-long-pk (b-t/->string client-long-key)
                                ::my-long-sk (b-t/->string my-long-secret)
                                ::my-long-pk (b-t/->string (.getPublicKey long-pair))
                                ::shared-long-secret (b-t/->string shared-secret)})]
      ;; I'm almost positive that open-crypto-box returns something different.
      ;; Or at least that it should.
      ;; FIXME: Tackle that.
      ;; And write a unit test to verify this.
      ;; Even though it's an implementation detail deep in the guts, this
      ;; seems worth covering.
      (when-let [^ByteBuf inner-pk-buf (crypto/open-box
                                        K/vouch-nonce-prefix
                                        (::K/inner-i-nonce client-message-box)
                                        (::K/hidden-client-short-pk client-message-box)
                                        shared-secret)]
        (let [inner-pk (byte-array K/key-length)]
          (.getBytes inner-pk-buf 0 inner-pk)
          (b-t/bytes= short-pk inner-pk))))))

(s/fdef do-fork-child
  :args (s/cat :state ::state/state
               :active-client ::state/client-state
               :client-long-pk ::shared/public-key
               :client-short-pk ::shared/public-key
               :server-short-sk ::shared/secret-key
               :host ::shared/host
               :port ::shared/port
               :initiate ::serial/decomposed
               :client-message-box ::K/initiate-client-vouch-wrapper)
  :ret ::state/state)
(defn do-fork-child
  [{log-state ::log2/state
    :as state}
   active-client
   client-long-pk
   client-short-pk
   server-short-sk
   host
   port
   initiate
   client-message-box]
  (let [^ByteBuf rcvd-nonce-buffer (::K/outer-i-nonce initiate)
        rcvd-nonce-array (byte-array specs/client-nonce-suffix-length)
        _ (.getBytes rcvd-nonce-buffer 0 rcvd-nonce-array)
        _ (.release rcvd-nonce-buffer)
        rcvd-nonce (b-t/uint64-unpack rcvd-nonce-array)
        active-client (assoc active-client
                             ;; Seems very likely that I should convert this
                             ;; to a byte-array
                             ::client-extension (::K/clnt-xtn initiate)
                             ::client-ip host
                             ::client-port port
                             ::state/received-nonce rcvd-nonce)
        ;; API/design Q: Does it make sense for me to supply this?
        ;; I'm responsible for writing to it, which means I should control
        ;; when it closes...but it feels more than a little silly
        writer (strm/stream)
        ;; Q: Does it make sense to share the child-spawing code with
        ;; the client?
        ;; A: If not, then update that code to make it sensible.
        spawner (::state/child-spawner! state)
        child (spawner writer)
        client-with-child (assoc active-client
                                 ::state/child-interaction (assoc child
                                                                  ::state/reader-consumed (message/add-listener! state child))
                                 ;; Q: What is this for?
                                 ;; It doesn't seem to match
                                 ::state/message-len 0
                                 ;; Reference implementation stores the client-short<->server-short
                                 ;; keypair here again.
                                 ;; But I already did that during a call to configure-shared-secrets
                                 ::state/client-security (into (::state/client-security state)
                                                               #:frereth-cp.shared.specs {:public-long client-long-pk
                                                                                          :public-short client-short-pk
                                                                                          :frereth-cp.server/server-short-sk server-short-sk}))
        child-reader (::state/write->child child)
        ;; This doesn't actually matter. That field should probably be
        ;; considered a private black-box member from our perspective.
        ;; But it seems helpful for keeping which is what straight
        _ (assert (= writer child-reader))
        state (state/alter-client-state state client-with-child)
        ;; And then forward the message to our new(?) child
        log-state (log2/debug log-state
                              ::do-handle
                              "Trying to send child-message from "
                              {::message-box-keys (keys client-message-box)})
        sent (strm/try-put! writer
                            (::K/message client-message-box)
                            K/send-child-message-timeout
                            ::timeout)
        forked-logs (log2/clean-fork log-state ::initiate-forwarded)
        logger (::log2/logger state)]
    (dfrd/on-realized sent
                      (fn [x]
                        (let [log-state
                              (if (not= x ::timeout)
                                (log2/info forked-logs
                                           ::do-handle
                                           "Message forwarded to new child"
                                           {::success x})
                                (log2/error forked-logs
                                            ::do-handle
                                            "Timed out trying to send message"
                                            {::destination child}))]
                          (log2/flush-logs! logger log-state)))
                      (fn [x]
                        (log2/flush-logs! logger
                                          (log2/info forked-logs
                                                     ::do-handle
                                                     "Forwarding message to new child failed"
                                                     {::problem x}))))
    (assoc state ::log2/state log-state)))

(s/fdef decompose-initiate-packet
  :args (s/cat :packet-length nat-int?
               :message-packet ::shared/message)
  :ret ::serial/decomposed)
(defn decompose-initiate-packet
  [packet-length
   message-packet]
  ;; Note the extra 16 bytes
  ;; The minimum packet length is actually
  ;; (+ 544 K/box-zero-bytes)
  ;; Because the message *has* to have the bytes for 0
  ;; padding, even if it's 0 length.
  (let [tmplt (update-in K/initiate-packet-dscr
                         [::K/vouch-wrapper ::K/length]
                         +
                         (- packet-length packet-header-length))]
    (serial/decompose-array tmplt message-packet)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef do-handle
  :args (s/cat :state ::state/state
               :packet ::shared/network-packet)
  :ret ::state/delta)
(defn do-handle
  "Deal with an incoming initiate packet

  Called mostly for side-effects, but the return value matters."
  [{log-state ::log2/state
    :keys [::log2/logger]
    :as state}
   {:keys [:host :port]
    message :message
    :as packet}]
  (let [log-state (log2/info log-state
                             ::handle!
                             "Handling incoming initiate packet"
                             packet)
        message (bytes message)]
    (println "Mark: top of initiate/do-handle")
    (let [n (count message)]
      (if (>= n (+ K/box-zero-bytes packet-header-length))
        (let [initiate (decompose-initiate-packet n message)
              client-short-pk (bytes (::K/clnt-short-pk initiate))]
          (println "Mark: Check for re-initiate")
          (let [{:keys [::handled]
                 log-state ::log2/state} (possibly-re-initiate-existing-client-connection! state initiate)]
            (if-not handled
              (if-let [cookie (extract-cookie (::state/cookie-cutter state)
                                              initiate)]
                (let [log-state (log2/info log-state
                                           ::handle!
                                           "Succssfully extracted cookie")
                      {active-client ::state/client-state
                       server-short-sk ::shared/secret-key
                       {log-state ::log2/state
                        :as state} ::state/state} (configure-new-active-client (assoc state ::log2/state log-state)
                                                                               client-short-pk
                                                                               cookie)]
                  ;; It included a secret cookie that we generated sometime within the
                  ;; past couple of minutes.
                  ;; Now we're ready to tackle handling the main message body cryptobox.
                  ;; This corresponds to line 373 in the reference implementation.
                  (try
                    (println "Mark: trying to open the client's crypto box")
                    (let [{log-state ::log2/state
                           client-message-box ::K/initiate-client-vouch-wrapper} (open-client-crypto-box log-state
                                                                                                         initiate
                                                                                                         active-client)]
                      (if client-message-box
                        (let [client-long-pk (bytes (::K/long-term-public-key client-message-box))
                              log-state (log2/info log-state
                                                   "Extracted message box from client's Initiate packet"
                                                   ;; This matches both the original log
                                                   ;; message and what we see below when we
                                                   ;; try to extract the inner hidden key
                                                   {::message-box-keys (keys client-message-box)
                                                    ::client-public-long-key (b-t/->string client-long-pk)})]
                          (try
                            (println "Mark: validating server name")
                            (if (validate-server-name state client-message-box)
                              ;; This takes us down to line 381
                              (if (verify-client-public-key-triad state client-short-pk client-message-box)
                                ;; TODO: Limit the state parameter and return value to what's actually needed
                                (do-fork-child state
                                               active-client
                                               client-long-pk
                                               client-short-pk
                                               server-short-sk
                                               host
                                               port
                                               initiate
                                               client-message-box)
                                {::log2/state (log2/warn log-state
                                                         ::do-handle
                                                         "Mismatched public keys"
                                                         {::FIXME "Show the extracted versions"
                                                          ::state/state state
                                                          ::client-short-pk client-short-pk
                                                          ::shared/message client-message-box})}))
                            (catch ExceptionInfo ex
                              {::log2/state (log2/exception log-state
                                                            ex
                                                            ::do-handle
                                                            "Failure after decrypting inner client cryptobox")})))
                        (assoc state ::log2/state log-state)))
                    (catch ExceptionInfo ex
                      {::log2/state (log2/exception log-state
                                                    ex
                                                    ::do-handle
                                                    "Initiate packet looked good enough to establish client session, but failed later")})))
                ;; Just log a quick message about the failure for now.
                ;; It seems likely that we should really gather more info, especially in terms
                ;; of identifying the source of garbage.
                {::log2/state (log2/error log-state
                                          ::do-handle
                                          "FIXME: Debug only: cookie extraction failed")})
              (throw (RuntimeException. "TODO: Handle additional Initiate packets from " client-short-pk)))))
        {::log2/state (log2/warn log-state
                                 ::do-handle
                                 (str "Truncated initiate packet. Only received " n " bytes"))}))))
