(ns frereth-cp.server.initiate
  "For coping with Initiate packets

This is the part that possibly establishes a 'connection'"
  (:require [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.server
             ;; FIXME: Don't want these siblings to have any
             ;; dependencies on each other.
             [message :as message]
             [state :as state]]
            [frereth-cp
             [message :as root-message]
             [shared :as shared]]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [child :as child]
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

(s/def ::child-fork-prereqs (s/keys :req [::log/logger
                                          ::log/state
                                          ::msg-specs/->child
                                          ::msg-specs/child-spawner!
                                          ::msg-specs/message-loop-name]))

(s/def ::client-builder (s/keys :req [::state/cookie-cutter
                                      ::shared/my-keys
                                      ::log/state]))

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

  If this matches a connection we've already seen, caller
  can/should skip client initialization and just append the
  Message portion to the child-handler's queue.

  returns:
    handled?
      true: client has already seen this message. Discard it.
      false: Need to forward this message along
    clint-state
      truthy: forward message to this existing client
      falsey: have to allocate/configure a new client

  This seems like it ought to be part of a bigger, more comprehensive
  event handling system.

  To be fair, this ns *is* pretty special."
  ;; Note that the return value pair of
  ;; #_{::specs/handled? true ::state/client-state nil}
  ;; would be/is utter nonsense.
  ;; There's no way for a non-existent client to have already seen
  ;; a packet.
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
          ;; client. Don't duplicate that code.
          ;; That's the entire point to the handled? == false case
          {::specs/handled? false
           ::state/client-state client
           ::log/state log-state}
          ;; Existing client has already seen this packet.
          ;; Throw it out.
          {::log/state (log/debug log-state
                                  log-label
                                  "Discarding already-written nonce"
                                  {::shared/packet-nonce packet-nonce
                                   ::last-packet-nonce last-packet-nonce})
           ::specs/handled? true}))
      ;; Need to forward along to a new client.
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
  [log-state
   {:keys [::state/minute-key
           ::state/last-minute-key]
    :as cookie-cutter}
   hello-cookie]
  (let [log-state (log/debug log-state
                             ::decrypt-cookie
                             "Trying to extract cookie based on current minute-key")
        crypto-text (byte-array K/hello-crypto-box-length)
        ;; Q: How much faster/more efficient is it to have a
        ;; io.netty.buffer.PooledByteBufAllocator around that
        ;; I could use for either .heapBuffer or .directBuffer?
        ;; (as opposed to creating my own local in the let above)
        nonce-suffix (byte-array specs/server-nonce-suffix-length)]
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

    ;; Start with the first 16 bytes, which is the nonce suffix
    (b-t/byte-copy! nonce-suffix
                    0
                    specs/server-nonce-suffix-length
                    hello-cookie)
    ;; The remaining 80 bytes should get decrypted
    (b-t/byte-copy! crypto-text
                    0
                    K/hello-crypto-box-length
                    hello-cookie
                    specs/server-nonce-suffix-length)
    (try
      (let [opener #(crypto/open-box %1
                                     K/cookie-nonce-minute-prefix
                                     nonce-suffix
                                     crypto-text
                                     %2)
            {log-state ::log/state
             unboxed ::crypto/unboxed
             :as opened} (opener log-state
                                 minute-key)]
        (if-not unboxed
          ;; Try again with the previous minute-key
          (opener (log/debug log-state
                             ::decrypt-inner-vouch
                             "Couldn't decrypt w/ current minute-key")
                  last-minute-key)
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
                (throw (ex-info "Missing shared key"
                                {::log/state log-state})))
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

(s/fdef unbox-innermost-key
  :args (s/cat :log-state ::log/state
               :my-keys ::shared/my-keys
               :client-message-box ::templates/initiate-client-vouch-wrapper)
  :ret (s/keys :req [::log/state]
               :opt [::specs/public-short]))
(defn unbox-innermost-key
  "We unwrapped the our original cookie, using the minute-key.

  And the actual message box using the client's short-term public key.
  That box included the client's long-term public key.

  Now there's a final box nested that contains the short-term key again,
  encrypted with the long-term key.

  This step verifies that the client really does have access to that long-term
  key.

  It's flagged as \"optional\" in the reference implementation, but that seems
  a bit silly.

  This corresponds, roughly, to lines 382-391 in the reference implementation.

  Note that that includes TODOs re:
  * impose policy limitations on clients: known, maxconn
  * for known clients, retrieve shared secret from cache"
  [log-state
   {:keys [::shared/long-pair] :as my-keys}
   {:keys [::K/hidden-client-short-pk
           ::K/inner-i-nonce
           ::K/long-term-public-key]
    :as client-message-box}]
  {:pre [long-term-public-key]}
  (let [client-long-key (bytes long-term-public-key)
        ^TweetNaclFast$Box$KeyPair long-pair long-pair
        my-long-secret (.getSecretKey long-pair)
        shared-secret (crypto/box-prepare client-long-key
                                          my-long-secret)
        log-state (log/info log-state
                            ::unbox-innermost-key
                            (str "Getting ready to decrypt the inner-most hidden public key\n"
                                 "FIXME: Don't log any secret keys")
                            {::client-long-pk (b-t/->string client-long-key)
                             ::my-long-sk (b-t/->string my-long-secret)
                             ::shared-long-secret (b-t/->string shared-secret)
                             ::K/inner-i-nonce (b-t/->string inner-i-nonce)
                             ::specs/crypto-text (b-t/->string hidden-client-short-pk)})
        {log-state ::log/state
         ;; It seems tempting to use decompose-box here.
         ;; That would be pointless: the clear text is just the client's
         ;; short-term public key.
         :keys [::crypto/unboxed]} (crypto/open-box log-state
                                                    K/vouch-nonce-prefix
                                                    inner-i-nonce
                                                    hidden-client-short-pk
                                                    shared-secret)]
    (if unboxed
      (let [inner-pk-buf ^ByteBuf unboxed
            inner-pk (byte-array K/key-length)]
        (.getBytes inner-pk-buf 0 inner-pk)
        {::log/state log-state
         ::specs/public-short inner-pk})
      {::log/state (log/warn log-state
                             ::unbox-innermost-key
                             "Unboxing innermost key failed"
                             {::long-client-pk (b-t/->string client-long-key)
                              ;; FIXME: Don't log secrets!!
                              ::long-server-sk (b-t/->string my-long-secret)
                              ::shared-secret (b-t/->string shared-secret)})})))

(s/fdef client-public-key-triad-matches?
  :args (s/cat :log-state ::log/state
               :my-keys ::shared/my-keys
               ;; This arrived in the public part of the Initiate
               :supplied-client-short-key ::shared/short-pk
               :client-message-box ::templates/initiate-client-vouch-wrapper)
  :ret (s/keys :req [::log/state] :opt [::specs/matched?]))
(defn client-public-key-triad-matches?
  [log-state
   {:keys [::shared/long-pair]
    :as my-keys}
   client-short-pk
   client-message-box]
  {:pre [client-short-pk]}
  (let [{log-state ::log/state
         inner-pk ::specs/public-short} (unbox-innermost-key log-state
                                                             my-keys
                                                             client-message-box)]
    (if inner-pk
      (let [matched? (b-t/bytes= client-short-pk inner-pk)]
        {::log/state (if matched?
                       (log/debug log-state
                                  ::client-public-key-triad-matches?
                                  "Matched.")
                       (log/warn log-state
                                 ::client-public-key-triad-matches?
                                 "Inner pk doesn't match outer"
                                 {::outer (b-t/->string client-short-pk)
                                  ::inner (b-t/->string inner-pk)}))
         ::specs/matched? matched?})
      {::log/state (log/warn log-state
                             ::client-public-key-triad-matches?
                             "Unable to open inner cryptobox")})))

;;; It's tempting to try to consolidate this with the way the
;;; client handles these packets.
;;; That seems really complex due to the way it has to flip
;;; state in the middle.
;;; Which, honestly, means that I've implemented it incorrectly.
;;; FIXME: This needs a spec
(defn child->
  "Callback for handling message packets from the child"
  [message-bytes]
  (throw (RuntimeException. "So, what should this do?")))

(s/fdef do-fork-child!
  :args (s/cat :builder-params ::child-fork-prereqs
               :active-client ::state/client-state)
  :ret (s/keys :req [::log/state]
               :opt [::state/client-state]))
(defn do-fork-child!
  [{log-state ::log/state
    :as builder-params}
   active-client]
  (try
      (let [{child-state ::child/state
           log-state ::log/state} (child/fork! builder-params child->)]
      (try
        {::log/state log-state
         ::state/client-state (assoc active-client
                                     ::child/state child-state)}
        (catch Exception ex
          {::log/state (log/exception log-state
                                      ex
                                      ::do-fork-child!
                                      "Trying to assoc new child with client")})))
    ;; Q: Why isn't this catching the RuntimeException from child/fork! ?
    (catch Exception ex
      {::log/state (log/exception log-state
                                  ex
                                  ::do-fork-child!
                                  "Trying to fork!")})
    (catch Throwable ex
      {::log/state (log/exception log-state
                                  ex
                                  ::do-fork-child!
                                  "Trying to fork! failed badly")})))

;;; FIXME: This belongs under shared.
;;; It's pretty much universal to client/server
;;; and initiate/message, and almost definitely
;;; already has an implementation there.
;;; It seems highly likely there's also something
;;; very similar in client.
(s/fdef forward-message-portion!
  :args (s/cat :state ::state/state
               :active-client ::state/client-state
               :client-message-box ::templates/initiate-client-vouch-wrapper)
  :ret ::log/state)
(defn forward-message-portion!
  "Forward the message to our new(?) child"
  [{:keys [::log/logger]
    log-state ::log/state
    :as state}
   {:keys [::state/client-security]
    child-state ::child/state
    :as client}
   {child-message ::K/message
    :as client-message-box}]
  (println "Mark decrypt-initiate-box" client-message-box)
  (let [log-label ::forward-message-portion!
        ;; Line 351 (if this is a new connection)
        log-state (log/debug log-state
                             log-label
                             "Trying to send child-message from "
                             {::client-message-box-keys (keys client-message-box)})
        sent (root-message/parent->! child-state
                                     child-message)
        forked-logs (log/clean-fork log-state ::initiate-forwarded)]
    (dfrd/on-realized sent
                      (fn [x]
                        (let [log-state
                              (if (not= x ::root-message/timeout)
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
    log-state))

(s/fdef build-and-configure-client-basics
  :args (s/cat :log-state ::log/state
               ;; There have been a couple of times
               ;; when I've been skeptical about the
               ;; utility of the packet parameter
               ;; here.
               ;; But it's vital.
               ;; This is how the server knows where to
               ;; send its own Messages.
               :packet ::shared/network-packet
               :initiate ::K/initiate-packet-spec)
  :ret (s/keys :req [::log/state]
               :opt [::state/client-state]))
(defn build-and-configure-client-basics
  [log-state
   packet
   {:keys [::templates/srvr-short-sk]
    :as cookie}
   initiate]
  (let [log-state (log/info log-state
                            ::build-and-configure-client-basics
                            "Succssfully extracted cookie")
        {{client-short-pk ::shared/short-pk} ::state/client-security
         :as active-client} (state/new-client packet
                                              cookie
                                              initiate)
        client-short-pk (bytes client-short-pk)
        server-short-sk (bytes srvr-short-sk)
        active-client (state/configure-shared-secrets active-client
                                                      client-short-pk
                                                      server-short-sk)]
    {::log/state log-state
     ::state/client-state active-client}))

(s/fdef build-new-client
  :args (s/cat :state ::client-builder
               :packet ::shared/network-packet
               :initiate ::K/initiate-packet-spec)
  :ret (s/keys :req [::log/state]
               :opt [::state/client-state
                     ::templates/initiate-client-vouch-wrapper]))
(defn build-new-client
  [{log-state ::log/state
    :keys [::state/cookie-cutter state
           ::shared/my-keys]}
   packet
   {:keys [::K/clnt-short-pk]
    :as initiate}]
  (let [{cookie ::templates/cookie-spec
         log-state ::log/state
         :as cookie-extraction} (extract-cookie log-state
                                                cookie-cutter
                                                initiate)]
    (if cookie
      ;; It included a secret cookie that we generated sometime within the
      ;; past couple of minutes.
      ;; Now we're ready to tackle handling the main message body cryptobox.
      ;; This corresponds to line 373 in the reference implementation.
      (let [{log-state ::log/state
             {{:keys [::state/client-short<->server-short]} ::state/shared-secrets
              {client-short-pk ::shared/short-pk} ::state/client-security
              :as active-client} ::state/client-state} (build-and-configure-client-basics log-state
                                                                                          packet
                                                                                          cookie
                                                                                          initiate)]
        (if client-short-pk
          (if client-short<->server-short
            (try
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
                                 :keys [::specs/matched?]} (client-public-key-triad-matches? log-state
                                                                                             my-keys
                                                                                             client-short-pk
                                                                                             client-message-box)]
                            {::log/state log-state
                             ::templates/initiate-client-vouch-wrapper client-message-box
                             ::state/client-state (when matched?
                                                    active-client)})
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
                                            "Initiate packet looked good enough to establish client session, but failed later")}))
            {::log/state (log/error log-state
                                    ::build-new-client
                                    "Failed to set up short key"
                                    {::state/active-client active-client})})
          {::log/state (log/error log-state
                                  ::build-new-client
                                  "Missing the short-pk"
                                  {::state/client-state active-client})}))
      ;; Just log a quick message about the failure for now.
      ;; It seems likely that we should really gather more info, especially in terms
      ;; of identifying the source of garbage.
      {::log/state (log/error log-state
                              ::build-new-client
                              "FIXME: More logs! cookie extraction failed")})))

(s/fdef create-child
  :args (s/cat :log-state ::log/state
               :state (s/keys :req [::state/cookie-cutter
                                    ::shared/my-keys])
               :packet ::shared/network-packet
               :initiate ::K/initiate-packet-spec)
  :ret (s/keys :req [::log/state]
               :opt [::state/client-state
                     ::templates/initiate-client-vouch-wrapper]))
(defn create-child
  [log-state
   {:keys [::state/cookie-cutter
           ::shared/my-keys]}
   packet
   initiate]
  (let [{log-state-2 ::log/state
         :as built} (build-new-client {::state/cookie-cutter cookie-cutter
                                       ::shared/my-keys my-keys
                                       ::log/state log-state}
                                      packet
                                      initiate)
        log-state (if log-state-2
                    log-state-2
                    (log/warn log-state
                              ::do-create-forked-child!
                              (str "Log state disappeared"
                                   "  trying to build-new-client")
                              {::built built}))]
    (assoc built ::log/state log-state)))

(s/fdef decompose-initiate-packet
  :args (s/cat :packet-length nat-int?
               :message-packet ::shared/message)
  :ret ::K/initiate-packet-spec)
(defn decompose-initiate-packet
  "Extract the raw outer portions of a Client Initiate Packet"
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
                 :as re-inited} (possibly-re-initiate-existing-client-connection (assoc state
                                                                                        ::log/state @log-state-atom)
                                                                                 initiate)]
            (assert log-state)
            (reset! log-state-atom log-state)
            ;; Careful. This next part gets clever.
            ;; handled? in this sense really means "swallowed" because
            ;; it's a packet from the stream that we've already seen.
            ;; Based upon the nonce.
            ;; This detail is hidden in the Nonces page of the spec.
            ;; The client must generate nonces in increasing order.
            ;; The server is free to discard any packets with a
            ;; smaller nonce than the last one it's seen (though
            ;; it's also legal to track the last few that were
            ;; received to handle network reordering).

            ;; And the boolean for client-state is a member of re-inited

            ;; Actually, given modern technology, it probably isn't
            ;; clever enough.
            ;; A major reason to resend an Initiate packet is an IP
            ;; address change.
            ;; Assuming mobile clients can even detect such a thing.
            ;; It would be awesome to make this sort of transition
            ;; seamless.
            ;; TODO: Yet again, check with an expert to see whether
            ;; that's a terrible idea.
            (if-not handled?
              (let [{:keys [::state/client-state]
                     log-state ::log/state
                     client-message-box ::templates/initiate-client-vouch-wrapper
                     :as built} (if client-state
                                  re-inited
                                  (let [child-creation-params (select-keys state [::shared/my-keys
                                                                                  ::state/cookie-cutter])]
                                    (create-child log-state
                                                  child-creation-params
                                                  packet
                                                  initiate)))]
                (reset! log-state-atom log-state)
                ;; Note that client-state shifted around in that let just above.
                ;; More unfortunate cleverness.
                (if client-state
                  (try
                    (let [base-builder-params (select-keys state [::log/logger
                                                                  ::log/state
                                                                  ::msg-specs/->child
                                                                  ::msg-specs/child-spawner!])
                          loop-name-base (str (get state
                                                   ::msg-specs/message-loop-name-base
                                                   "child")
                                              "-")
                          client-pk-short (get-in client-state [::state/client-security
                                                                ::shared/short-pk])
                          message-loop-name (format "%s/%x"
                                                    (gensym loop-name-base)
                                                    (biginteger client-pk-short))
                          builder-params (assoc base-builder-params
                                                ::msg-specs/message-loop-name message-loop-name)
                          {log-state ::log/state
                           client-state ::state/client-state
                           :as delta} (do-fork-child! builder-params
                                                       client-state)]
                      (if client-state
                        (let [delta' (state/alter-client-state state
                                                               (::state/client-state client-state))
                              state (into state (assoc delta' ::log/state log-state))]
                          (assoc delta' ::log-state (forward-message-portion! state
                                                                              client-state
                                                                              client-message-box)))
                        delta))
                    (catch Exception ex
                      {::log/state (log/exception log-state
                                                  ex
                                                  ::do-handle)}))
                  {::log/state (log/warn log-state
                                         ::do-handle
                                         "Unable to build a new client"
                                         {::shared/network-packet packet
                                          ::K/initiate-packet-spec initiate
                                          ::client-builder (select-keys state [::state/cookie-cutter
                                                                               ::shared/my-keys])
                                          ::built (dissoc built ::log/state)
                                          ::built-keys (keys built)})}))
              (throw (RuntimeException. "TODO: Handle additional Initiate packets from " (-> initiate
                                                                                             ::K/clnt-short-pk
                                                                                             bytes
                                                                                             vec)))))
          {::log/state (log/warn log-state
                                 ::do-handle
                                 (str "Truncated initiate packet. Only received " n " bytes"))}))
      (catch Exception ex
        (let [log-state-acc @log-state-atom
              log-state (or log-state-acc log-state)]
          {::log/state (log/exception (if log-state-acc
                                        log-state
                                        (log/error log-state
                                                   ::do-handle
                                                   "nil log-state-atom"))
                                      ex
                                      ::do-handle)})))))
