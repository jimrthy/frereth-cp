(ns frereth-cp.server.initiate
  "For coping with Initiate packets

This is the part that possibly establishes a 'connection'"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.server
             ;; FIXME: Don't want to depend on this
             [message :as message]
             [state :as state]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [logging :as log]
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

(s/def ::child-fork-prereqs (s/keys :req [::log/state
                                          ::state/child-spawner!]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal implementation

(s/fdef decrypt-initiate-box
  :args (s/cat :log-state ::log/state
               :shared-key ::specs/crypto-key
               :nonce-suffix :shared/client-nonce
               :box (s/and bytes?
                           #(< (count %) K/minimum-vouch-length)))
  :ret (s/keys :req [::log/state]
               :opt [::K/initiate-client-vouch-wrapper]))
;; TODO: Write server-test/vouch-extraction to gain confidence that
;; this works
(defn decrypt-initiate-box
  "Decrypts the final 368+M byte box at packet's end

  There's a lot of data in here."
  [log-state
   shared-key
   nonce-suffix
   box]
  (crypto/decompose-box log-state
                        templates/initiate-client-vouch-wrapper
                        K/initiate-nonce-prefix
                        nonce-suffix
                        box
                        shared-key))

(s/fdef possibly-re-initiate-existing-client-connection
        :args (s/cat :state ::state
                     :initiate-packet ::K/initiate-packet-spec)
        :ret (s/keys :req [::log/state]
                     :opt [::specs/handled?
                           ::state/client-state]))
(defn possibly-re-initiate-existing-client-connection
  "Client can send as many Initiate packets as it likes.

  If this matches a connection we've already seen, append the Message
  portion to the child-handler's queue.

  returns (handled?):
    true:  Handled here
    false: Not handled. Propagate the event

  This seems like it ought to be part of a bigger, more comprehensive
  event handling system.

  To be fair, this ns *is* pretty special."
  [{log-state ::log/state
    :as state}
   {packet-nonce-bytes ::specs/nonce
    :as initiate}]
  ;; In the reference implementation, this basically corresponds to
  ;; lines 341-358.
  ;; Find the matching client (if any).
  (let [client-short-key (::clnt-short-pk initiate)
        log-label ::possibly-re-initiate-existing-client-connection]
    ;; This seems scary.
    ;; It seems worth mentioning an under-the-hood implementation detail,
    ;; to alleviate that.
    ;; state converts the byte-array to a vec before using it as a key
    (if-let [client (state/find-client state client-short-key)]
      ;; If there is one, extract the message portion
      (let [log-state (log/info log-state
                                log-label
                                "Initiate packet from known client")
            packet-nonce (b-t/uint64-unpack packet-nonce-bytes)
            last-packet-nonce (::state/received-nonce client)]
        (if (< last-packet-nonce packet-nonce)  ; line 343
          ;; This is an address in the stream that we haven't seen yet.
          ;; Need to forward it along

          ;; In a way, this will take us down to line 352.
          ;; But, really, this is starting to diverge from
          ;; the reference, sort of.
          ;; There's no reason to write the "send" code twice.

          ;; Q: What's going on there (i.e. line 352)?
          ;; text[383] = (r - 544) >> 4;
          ;; Translation:
          ;; The message associated with the Initiate packet winds
          ;; up in text at byte 384.
          ;; The reference implementation inserts a prefix byte
          ;; (length/16)
          ;; before sending the array to the associated child
          ;; process in the next line:
          ;; writeall(activeclients[i].tochild, text+383, r-543)
          ;; 544 is the offset in the source block where the
          ;; actual message bytes start.
          ;; But the message writing code is the same whether this
          ;; is a new connection or another Initiate to an existing
          ;; client. So don't duplicate that code.
          {::specs/handled? false
           ::state/client-state client
           ::log/state log-state}
          {::log/state (log/debug log-state
                                  log-label
                                  "Discarding already-written nonce"
                                  {::shared/packet-nonce packet-nonce
                                   ::last-packet-nonce last-packet-nonce})
           ::specs/handled? true}))
      {::log/state (log/debug log-state
                              log-label
                              "Not an existing client")
       ::specs/handled? false})))

(s/fdef decrypt-cookie
  :args (s/cat :log-state ::log/state
               :cookie-cutter ::state/cookie-cutter
               :hello-cookie ::K/cookie)
  :ret (s/keys :req [::log/state]
               :opt [::crypto/unboxed]))
(defn decrypt-cookie
  "Open the cookie we sent the client"
  [log-state cookie-cutter hello-cookie]
  (throw (RuntimeException. "Revisit the approaches here."))
  (comment
    ;; This approach seems much cleaner.
    ;; Or possibly more succint.
    ;; TODO: Consider.
    (try
      (let [opener #(crypto/open-box %1 K/initiate-nonce-prefix nonce-suffix box %2)
            {log-state ::log/state
             clear-text ::crypto/unboxed} (opener log-state minute-key)
            ;; It seems like there must be a more elegant way to handle this
            {log-state ::log/state
             clear-text ::crypto/unboxed} (if-not clear-text
                                            (opener log-state last-minute-key)
                                            {::log/state log-state
                                             ::crypto/unboxed clear-text})]
        ;; This is another area where it really seems like I should just
        ;; skip the conversion to a ByteBuf
        {::log/state log-state
         ::crypto/unboxed clear-text})
      (catch Exception ex
        {::log/state (log/exception log-state ex ::decrypt-initiate-vouch)})))
  (let [log-state (log/debug log-state
                             ::decrypt-inner-vouch
                             "Trying to extract cookie based on current minute-key")
        src (byte-array K/hello-crypto-box-length)
        ;; Q: How much faster/more efficient is it to have a
        ;; io.netty.buffer.PooledByteBufAllocator around that
        ;; I could use for either .heapBuffer or .directBuffer?
        ;; (as opposed to creating my own local in the let above)
        nonce-suffix (byte-array specs/server-nonce-suffix-length)]
    ;; the 80 bytes of
    ;; We're trying to decrypt  the 80 bytes of crypto text from the
    ;; initial cookie.
    ;; Note that this part is tricky:
    ;; The "real" initial cookie is 96 bytes long:
    ;; * 32 bytes of padding
    ;; * 32 bytes of client short-term key
    ;; * 32 bytes of server short-term key
    ;; That's 80 bytes of crypto text (because 16
    ;; bytes of padding sticks around).
    ;; But then the "crypto black box" that just round-tripped
    ;; through the client includes 16 bytes of the nonce, taking
    ;; it back up to 96 bytes.
    (b-t/byte-copy! src
                    0
                    K/hello-crypto-box-length
                    hello-cookie
                    specs/server-nonce-suffix-length)
    (b-t/byte-copy! nonce-suffix
                    0
                    specs/server-nonce-suffix-length
                    hello-cookie)
    (try
      (println "FIXME: Switch to decompose-box")
      (let [opener #(crypto/open-box %1
                                     K/cookie-nonce-minute-prefix
                                     nonce-suffix
                                     src
                                     %2)
            {log-state ::log/state
             unboxed ::crypto/unboxed
             :as opened} (opener log-state
                                 (::state/minute-key cookie-cutter))]
        (if-not unboxed
          ;; Try again with the previous minute-key
          (let [log-state (log/debug log-state
                                     ::decrypt-inner-vouch
                                     "Couldn't decrypt w/ current minute-key")]
            (opener log-state
                    (::state/last-minute-key cookie-cutter)))
          opened)))))

(s/fdef client-short-pk-matches-cookie?
        :args (s/cat :destructured-initiate-packet ::K/initiate-packet-spec
                     :inner-vouch-decrypted-box ::specs/crypto-key)
        :ret (s/keys :req [::log/state]
                     :opt [::specs/matched?]))
(defn client-short-pk-matches-cookie?
  "Does the claimed short-term public key match our cookie?

  i.e. Does this client even pretend that it's the one to which we sent
  that cookie?"
  [log-state
   {:keys [::K/clnt-short-pk]
    :as initiate}
   hidden-pk]
  (let [expected (bytes clnt-short-pk)
        ;; This is disconcerting.
        ;; The values I'm seeing here very obviously do not match.
        ;; But apparently bytes= thinks they do.

        ;; The root problem is that I jumped the gun on calling this.
        ;; I haven't actually opened the inner cryptobox yet, so
        ;; of course they don't match.

        ;; A bigger concern is that, somehow, the crypto
        ;; text (?) evaluates as bytes= to the clear text.

        ;; I have that staged off in its own branch to tackle in
        ;; isolation, but I don't think I can justify going much
        ;; further down this road until I understand what's going
        ;; on there.
        result (b-t/bytes= hidden-pk expected)]
    {::log/state (log/debug log-state
                            ::client-short-pk-matches-cookie?
                            "Cookie extraction succeeded. Q: Do the contents match?"
                            {::expected (shared/bytes->string expected)
                             ::actual (shared/bytes->string hidden-pk)
                             ::specs/matched? result})
     ::specs/matched? result}))

(s/fdef extract-cookie
  :args (s/cat :log-state ::log/state
               :cookie-cutter ::state/cookie-cutter
               :initiate-packet ::K/initiate-packet-spec)
  :ret (s/keys :req [::log/state]
               :opt [::templates/cookie-spec]))
(defn extract-cookie
  "Verify we can open our original cookie and secrets match

  This corresponds to lines 359-368. "
  [log-state
   {:keys [::state/minute-key
           ::state/last-minute-key]
    :as cookie-cutter}
   initiate]

  ;; Errors here get logged, but there's no good way
  ;; for the caller to know that there was a problem.
  ;; Well, the "client" that put the packet onto the stream.
  ;; This is annoying for unit tests, but realistic for
  ;; the real world.
  ;; Outside the unit test scenario, the caller is whatever
  ;; pulled data from the UDP socket.
  ;; And that shouldn't be coping with problems at this level.
  ;; In a way, this beats the reference implementation, which
  ;; just silently discards the packet.
  ;; Although that approach is undeniably faster
  (let [hello-cookie (bytes (::K/cookie initiate))
        {log-state ::log/state
         ^ByteBuf inner-vouch-buffer ::crypto/unboxed} (decrypt-cookie log-state
                                                                       cookie-cutter
                                                                       hello-cookie)]
    (println "decrypt-cookie returned:" inner-vouch-buffer)
    (if inner-vouch-buffer
      ;; Yet again: Converting this to a ByteBuf was a mistake
      (let [inner-vouch-bytes (byte-array (.readableBytes inner-vouch-buffer))]
        (.readBytes inner-vouch-buffer inner-vouch-bytes)
        ;; Reference code:
        ;; Verifies that the "first" 32 bytes (after the 32 bytes of
        ;; decrypted 0 padding) of the 80 bytes it decrypted
        ;; out of the inner vouch match the client short-term
        ;; key in the outer initiate packet.
        (let [full-decrypted-vouch (vec inner-vouch-bytes)
              ;; Round-tripping through a vector seems pretty ridiculous.
              ;; I really just want to verify that the first 32 bytes match
              ;; the supplied key.
              ;; Note that the initial padding has been discarded
              key-array (byte-array (subvec full-decrypted-vouch 0 K/key-length))
              {log-state ::log/state
               :keys [::specs/matched?]} (client-short-pk-matches-cookie? log-state
                                                                          initiate
                                                                          key-array)]
          {::log/state log-state
           ::templates/cookie-spec (when matched?
                                     (serial/decompose-array templates/black-box-dscr
                                                             inner-vouch-bytes))}))
      {::log/state log-state})))

(s/fdef open-client-crypto-box
  :args (s/cat :log-state ::log/state
               :initiate ::K/initiate-packet-spec
               :client-short<->server-short ::state/client-short<->server-short)
  :ret (s/keys :req [::log/state]
               :opt [::K/initiate-client-vouch-wrapper]))
(defn open-client-crypto-box
  [log-state
   {:keys [::K/outer-i-nonce]
    vouch-wrapper ::K/vouch-wrapper
    :as initiate}
   client-short<->server-short]

  (let [log-state (log/info log-state
                            ::open-client-crypto-box
                            "Opening the Crypto box we just received from the client")
        vouch-wrapper (bytes vouch-wrapper)]
    (try
      (let [vouch-length (count vouch-wrapper)
            log-state (log/debug log-state
                                 ::open-client-crypto-box
                                 (str "The box we're opening is " vouch-length " bytes long"))
            message-length (- vouch-length K/minimum-vouch-length)
            shared-key (bytes client-short<->server-short)
            _ (when-not shared-key
                (throw (RuntimeException. "Missing shared key")))
            {log-state ::log/state
             clear-text ::crypto/unboxed
             :as unboxed} (try
                            (crypto/open-box log-state
                                             K/initiate-nonce-prefix
                                             outer-i-nonce
                                             vouch-wrapper
                                             shared-key)

                            (catch Throwable ex
                              {::log/state (log/exception log-state
                                                          ex
                                                          ::open-client-crypto-box)}))]
        (try
          (if clear-text
            {::log/state (log/info log-state
                                   ::open-client-crypto-box
                                   "Decomposing...")
             ::K/initiate-client-vouch-wrapper (serial/decompose (assoc-in templates/initiate-client-vouch-wrapper
                                                                           [::K/message ::K/length]
                                                                           message-length)
                                                                 clear-text)}
            {::log/state (log/warn log-state
                                   ::open-client-crypto-box
                                   "Opening client crypto vouch failed")})
          ;; Q: Does this extra layer of exception handling gain anything?
          ;; A: Well, we won't lose logs that were written before we hit
          ;; this try block
          (catch Exception ex
            {::log/state (log/exception log-state
                                        ex
                                        ::open-client-crypto-box)})))
      (catch Exception ex
        {::log/state (log/exception log-state
                                    ex
                                    ::open-client-crypto-box)}))))

(s/fdef validate-server-name
        :args (s/cat :state ::state/state
                     :inner-client-box ::templates/initiate-client-vouch-wrapper)
        :ret (s/keys :req [::log/state]
                     :opt [::specs/matched?]))
(defn validate-server-name
  [log-state
   {my-name ::specs/srvr-name
    :as my-keys}
   {rcvd-name ::K/srvr-name
    :as inner-client-box}]
  (when-not rcvd-name
    (throw (ex-info "Missing srvr-name"
                    {::K/initiate-client-vouch-wrapper inner-client-box
                     ::inner-box-keys (keys inner-client-box)})))
  (let [rcvd-name (bytes rcvd-name)
        match? (b-t/bytes= rcvd-name my-name)
        base-result {::log/state (if match?
                                    log-state
                                    (log/warn log-state
                                              ::validate-server-name
                                              "Message was intended for another server"
                                              {::specs/srvr-name (b-t/->string rcvd-name)
                                               ::my-name (b-t/->string my-name)
                                               ::shared/my-keys my-keys}))}]
    (if match?
      (assoc base-result ::specs/matched? match?)
      base-result)))

(s/fdef verify-client-public-key-triad
  :args (s/cat :log-state ::log/state
               :my-keys ::shared/my-keys
               :supplied-client-short-key ::shared/short-pk
               ::client-message-box ::templates/initiate-client-vouch-wrapper)
  :ret (s/keys :req [::log/state] :opt [::specs/matched?]))
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
  [log-state
   my-keys
   short-pk
   client-message-box]
  (let [client-long-key (bytes (::K/long-term-public-key client-message-box))
        ^TweetNaclFast$Box$KeyPair long-pair (::shared/long-pair my-keys)
        my-long-secret (.getSecretKey long-pair)
        shared-secret (crypto/box-prepare client-long-key
                                          my-long-secret)
        ^TweetNaclFast$Box$KeyPair long-pair (::shared/long-pair my-keys)
        log-state (log/info log-state
                              ::verify-client-public-key-triad
                              (str "Getting ready to decrypt the inner-most hidden public key\n"
                                   "FIXME: Don't log any secret keys")
                              {::client-long-pk (b-t/->string client-long-key)
                               ::my-long-sk (b-t/->string my-long-secret)
                               ::my-long-pk (b-t/->string (.getPublicKey long-pair))
                               ::shared-long-secret (b-t/->string shared-secret)})
        {log-state ::log/state
         ;; It seems use decompose-box here.
         ;; That would be pointless: the clear text is just the client's
         ;; short-term public key.
         :keys [::crypto/unboxed]} (crypto/open-box log-state
                                                    K/vouch-nonce-prefix
                                                    (::K/inner-i-nonce client-message-box)
                                                    (::K/hidden-client-short-pk client-message-box)
                                                    shared-secret)]
    {::log/state log-state
     ::specs/matched? (when unboxed
                        (let [inner-pk-buf ^ByteBuf unboxed
                              inner-pk (byte-array K/key-length)]
                          (.getBytes inner-pk-buf 0 inner-pk)
                          (b-t/bytes= short-pk inner-pk)))}))

(s/fdef do-fork-child!
  :args (s/cat :prereqs ::child-fork-prereqs
               :active-client ::state/client-state)
  :ret (s/keys :req [::log/state ::state/client-state]))
(defn do-fork-child!
  [{log-state ::log/state
    spawner ::state/child-spawner!
    :as state}
   active-client]
  (throw (RuntimeException. "Integrate this with the approach used by Client"))
  (let [;; Note that this is a pretty vital piece of the puzzle
        writer (strm/stream)
        ;; Q: Does it make sense to share the child-spawing code with
        ;; the client?
        ;; A: If not, then update that code to make it sensible.
        child (spawner writer)
        ;; FIXME: Really don't want to know anything about the
        ;; state.message ns in here. Worst-case scenario: have
        ;; state inject this dependency before it calls do-handle.
        ;; Or just pass it as a parameter to that.
        _ (throw (RuntimeException. "Use dependency injection for this"))
        listener-stream (message/add-listener! child)
        client-with-child (assoc active-client
                                 ::state/child-interaction (assoc child
                                                                  ::state/reader-consumed listener-stream))
        child-reader (::state/write->child child)
        ;; This doesn't actually matter. That field should probably be
        ;; considered a private black-box member from our perspective.
        ;; But it seems helpful for keeping which is what straight
        _ (assert (= writer child-reader))]
    {::log/state log-state
     ::state/client-state client-with-child}))

;;; FIXME: This belongs under shared.
;;; It's pretty much universal to client/server
;;; and initiate/message, and almost definitely
;;; already has an implementation there.
;;; It seems highly likely there's also something
;;; very similar in client.
(s/fdef forward-message-portion!
  :args (s/cat :state ::state/state
               :active-client ::state/client-state
               :initiate ::K/initiate-packet-spec)
  :ret ::log/state)
(defn forward-message-portion!
  "Forward the message to our new(?) child"
  [{:keys [::log/logger]
    log-state ::log/state
    :as state}
   {shared-key ::state/client-short<->server-short
    :keys [::state/child-interaction]
    :as client}
   {packet-nonce-bytes ::specs/nonce
    :keys [::K/vouch]
    :as initiate}]
  (throw (RuntimeException. "This does not belong here"))
  (let [writer (::state/write->child child-interaction)
        {log-state ::log/state
         client-message-box ::serial/decomposed} (decrypt-initiate-box shared-key
                                                                       packet-nonce-bytes
                                                                       vouch)
        log-label ::forward-message-portion!]
    (if client-message-box
      ;; Line 351 (if this is a new connection)
      (let [packet-nonce (b-t/uint64-unpack packet-nonce-bytes)
            client (assoc client
                          ::state/received-nonce packet-nonce)
            log-state (log/debug log-state
                                 log-label
                                 "Trying to send child-message from "
                                 {::message-box-keys (keys client-message-box)})
            sent (strm/try-put! writer
                                (::K/message client-message-box)
                                K/send-child-message-timeout
                                ::timeout)
            forked-logs (log/clean-fork log-state ::initiate-forwarded)]
        (dfrd/on-realized sent
                          (fn [x]
                            (let [log-state
                                  (if (not= x ::timeout)
                                    (log/info forked-logs
                                              log-label
                                              "Message forwarded to new child"
                                              {::success x})
                                    (log/error forked-logs
                                               log-label
                                               "Timed out trying to send message"
                                               {::destination client}))]
                              (log/flush-logs! logger log-state)))
                          (fn [x]
                            (log/flush-logs! logger
                                             (log/info forked-logs
                                                       log-label
                                                       "Forwarding message to new child failed"
                                                       {::problem x}))))
        log-state)
      (log/warn log-state
                log-label
                "Unable to decrypt incoming vouch"))))

(s/fdef build-new-client
  :args (s/cat :state ::state/state
               :packet ::shared/network-packet
               :initiate ::K/initiate-packet-spec)
  :ret (s/keys :req [::log/state]
               :opt [::state/client-state]))
;; FIXME: Refactor chunks of this into their own functions
;; FIXME: Trim back the state parameter
(defn build-new-client
  [{log-state ::log/state
    :keys [::state/cookie-cutter state
           ::shared/my-keys]
    :as state}
   {:keys [:host :port]
    :as packet}
   {:keys [::K/clnt-short-pk]
    :as initiate}]
  (let [{{:keys [::templates/clnt-short-pk
                 ::templates/srvr-short-sk]
          :as cookie} ::templates/cookie-spec
         log-state ::log/state
         :as cookie-extraction} (extract-cookie log-state
                                                cookie-cutter
                                                initiate)]
    (if cookie
      (let [log-state (log/info log-state
                                ::build-new-client
                                "Succssfully extracted cookie")
            client-short-pk (bytes clnt-short-pk)
            {{client-short-pk ::shared/short-pk} ::state/client-security
             :as active-client} (state/new-client packet
                                                  cookie
                                                  initiate)
            server-short-sk (bytes srvr-short-sk)
            active-client (state/configure-shared-secrets active-client
                                                          clnt-short-pk
                                                          srvr-short-sk)
            client-short<->server-short (get-in active-client
                                                [::state/shared-secrets
                                                 ::state/client-short<->server-short])]
        ;; It included a secret cookie that we generated sometime within the
        ;; past couple of minutes.
        ;; Now we're ready to tackle handling the main message body cryptobox.
        ;; This corresponds to line 373 in the reference implementation.
        (try
          (when-not client-short<->server-short
            (throw (ex-info "Missing shared short key"
                            {::state/active-client active-client
                             ::log/state log-state})))
          (let [{log-state ::log/state
                 {client-long-pk ::K/long-term-public-key
                  :as client-message-box} ::K/initiate-client-vouch-wrapper} (open-client-crypto-box log-state
                                                                                                     initiate
                                                                                                     client-short<->server-short)]
            (if client-message-box
              (let [client-long-pk (bytes client-long-pk)
                    active-client (assoc-in active-client
                                            [::state/client-security ::shared/long-pk] client-long-pk)
                    log-state (log/info log-state
                                        "Extracted message box from client's Initiate packet"
                                        ;; This matches both the original log
                                        ;; message and what we see below when we
                                        ;; try to extract the inner hidden key
                                        {::message-box-keys (keys client-message-box)
                                         ::client-public-long-key (b-t/->string client-long-pk)})]
                (try
                  (let [{:keys [::specs/matched?]
                         log-state ::log/state} (validate-server-name log-state
                                                                      my-keys
                                                                      client-message-box)]
                    (if matched?
                      ;; This takes us down to line 381
                      (let [{log-state ::log/state
                             matched? ::specs/matched?} (verify-client-public-key-triad log-state
                                                                                        (::shared/my-keys state)
                                                                                        client-short-pk
                                                                                        client-message-box)]
                        (if matched?
                          {::log/state log-state
                           ::state/current-client active-client}
                          {::log/state (log/warn log-state
                                                 ::build-new-client
                                                 "Mismatched public keys"
                                                 {::FIXME "Show the extracted versions"
                                                  ::state/state state
                                                  ::client-short-pk client-short-pk
                                                  ::shared/message client-message-box})}))
                      {::log/state log-state}))
                  (catch ExceptionInfo ex
                    {::log/state (log/exception log-state
                                                ex
                                                ::build-new-client
                                                "Failure after decrypting inner client cryptobox")})))
              {::log/state log-state}))
          (catch Exception ex
            {::log/state (log/exception log-state
                                        ex
                                        ::build-new-client
                                        "Initiate packet looked good enough to establish client session, but failed later")})))
      ;; Just log a quick message about the failure for now.
      ;; It seems likely that we should really gather more info, especially in terms
      ;; of identifying the source of garbage.
      {::log/state (log/error log-state
                              ::build-new-client
                              "FIXME: More logs! cookie extraction failed")})))

(s/fdef decompose-initiate-packet
  :args (s/cat :packet-length nat-int?
               :message-packet ::shared/message)
  :ret ::K/initiate-packet-spec)
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
  [{log-state ::log/state
    :keys [::log/logger]
    :as state}
   {:keys [:host
           :port
           :message]
    :as packet}]
  (let [log-state-atom (atom (log/info log-state
                                        ::do-handle
                                        "Handling incoming initiate packet"
                                        packet))
        message (bytes message)]
    (try
      (let [n (count message)]
        (if (>= n (+ K/box-zero-bytes packet-header-length))
          (let [initiate (decompose-initiate-packet n message)
                {:keys [::specs/handled?
                        ::state/client-state]
                 log-state ::log/state
                 ;; Q: Do we have to extract this during re-initiate?
                 ;; A: No. Definitely not.
                 ;; We have to decrypt it, no matter what, *if*
                 ;; the cookie's valid.
                 ;; Actually, if we've already established a "connection,"
                 ;; the cookie doesn't matter. It's something that could
                 ;; have been encrypted years ago, and its minute key is
                 ;; long dead-and-buried.
                 ;; It seems as thought it would be nice for the server
                 ;; to have a way to request a new key exchange handshake
                 ;; from the client under those sort of circumstances,
                 ;; short of terminating the "connection" (which, really,
                 ;; is outside the scope of this layer).
                 client-message-box ::templates/initiate-client-vouch-wrapper
                 :as re-inited} (possibly-re-initiate-existing-client-connection (assoc state
                                                                                        ::log/state @log-state-atom)
                                                                                 initiate)]
            (reset! log-state-atom log-state)
            (if-not handled?
              (let [{:keys [::state/client-state]
                     log-state ::log/state} (if client-state
                                              re-inited
                                              (let [{log-state ::log/state
                                                     active-client ::state/current-client} (build-new-client (assoc state
                                                                                                                    ::log/state log-state)
                                                                                                             packet
                                                                                                             initiate)]
                                                (reset! log-state-atom log-state)
                                                (when-not active-client
                                                  (throw (RuntimeException. "Unable to build a new client.")))
                                                ;; STARTED: Limit the state parameter and return value to what's actually needed
                                                (do-fork-child! (-> state
                                                                    (assoc ::log/state log-state)
                                                                    (select-keys [::log/state
                                                                                  ::state/child-spawner!]))
                                                                active-client)
                                                {::state/client-state active-client
                                                 ::log-state log-state}))
                    delta (state/alter-client-state client-state)
                    log-state (forward-message-portion! (into state delta)
                                                        client-state
                                                        initiate)]
                (assoc delta
                       ::log/state log-state))
              (throw (RuntimeException. "TODO: Handle additional Initiate packets from " (-> initiate
                                                                                             ::K/clnt-short-pk
                                                                                             bytes
                                                                                             vec)))))
          {::log/state (log/warn log-state
                                 ::do-handle
                                 (str "Truncated initiate packet. Only received " n " bytes"))}))
      (catch Exception ex
        {::log/state (log/exception @log-state-atom
                                    ex
                                    ::do-handle)}))))
