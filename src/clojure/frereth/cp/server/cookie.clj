(ns frereth-cp.server.cookie
  "For dealing with cookie packets on the server side"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [frereth-cp.server
             [shared-specs :as srvr-specs]
             [state :as state]]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [crypto :as crypto]
             [serialization :as serial]
             [specs :as specs]
             [templates :as templates]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [manifold
             [deferred :as dfrd]
             [stream :as strm]])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal Helpers

(s/fdef build-inner-cookie
        :args (s/or :sans-nonce (s/cat :log-state ::weald/state
                                       :other-short-pk ::specs/public-short
                                       :my-short-sk ::specs/secret-short
                                       :minute-key ::specs/crypto-key)
                    :with-nonce (s/cat :log-state ::weald/state
                                       :client-short-pk ::specs/public-short
                                       :my-short-sk ::specs/secret-short
                                       :minute-key ::specs/crypto-key
                                       :nonce-suffix ::specs/server-nonce-suffix))
        :ret (s/keys :req [::specs/byte-array
                           ::weald/log-state
                           ::specs/server-nonce-suffix]))
(defn build-inner-cookie
  "Build the inner black-box Cookie portion of the Cookie Packet"
  ([log-state
    client-short-pk
    my-short-sk
    minute-key]
   (let [{log-state ::weald/state
          nonce-suffix ::specs/server-nonce-suffix
          :as safe-nonce} (crypto/get-safe-server-nonce-suffix log-state)
         log-state (log/debug log-state
                              ::build-inner-cookie
                              "Building inner cookie from "
                              {::nonce-suffix-length (count nonce-suffix)
                               ::safe-nance (dissoc safe-nonce ::weald/state)})]
     (build-inner-cookie log-state client-short-pk my-short-sk minute-key nonce-suffix)))
  ;; This arity really only exists for the sake of testing:
  ;; Being able to reproduce the nonce makes life much easier in that regard
  ([log-state
    client-short-pk
    my-short-sk
    minute-key
    nonce-suffix]
   ;; I feel like my problems start later, around line 87 when I start
   ;; running byte-copy.
   ;; STARTED: Verify that this approach generates the same output as the
   ;; original.
   ;; Currently, it does not.
   ;; Q: What are the odds that this has something to do with the 0 padding
   ;; and the extra 16 bytes the test needs to drop from the return value here?
   (let [log-state (log/debug log-state
                              ::build-inner-cookie
                              "Encrypting inner cookie"
                              {::specs/server-nonce-suffix (vec nonce-suffix)})
         ;; In theory, this should be using secret-box.
         ;; The implementation's the same, so it doesn't matter.
         boxed-cookie (crypto/build-box templates/black-box-dscr
                                        {::templates/clnt-short-pk client-short-pk
                                         ::templates/srvr-short-sk my-short-sk}
                                        minute-key
                                        K/cookie-nonce-minute-prefix
                                        nonce-suffix)
         ;; This is similar to what the reference implementation
         ;; does when it just overwrites the garbage portion of the zero-padding
         ;; with it on line 321.
         ;; It's tempting to use serialize again, but that would be terribly
         ;; silly.
         ;; Note that using concat *is* problematic.
         ;; Especially for something this small.
         ;; Every alternative I've tried so far is uglier.
         nonced-cookie (byte-array (concat nonce-suffix boxed-cookie))]
     {::specs/byte-array nonced-cookie
      ::weald/state log-state
      ;; It seems silly to return this, since it was a parameter.
      ;; But this probably won't be called as a pure function.
      ;; Most callers will use the other arity that calls safe-nonce.
      ;; OK, there's probably only one caller. It reuses half of
      ;; this suffix.
      ::specs/server-nonce-suffix nonce-suffix})))

(s/fdef build-cookie-wrapper
        :args (s/cat :log-state ::weald/state
                     :shared-key ::state/client-short<->server-long
                     :nonce-suffix ::crypto/srvr-nonce-suffix
                     :pk-session ::specs/public-short
                     :black-box ::templates/inner-cookie)
        :ret (s/keys :req [::weald/state]
                     :opt [::templates/encrypted-cookie]))
(defn build-cookie-wrapper
  "Put together the real payload for the cookie packet

  This builds the 144-byte crypto box that wraps the server's
  public session key and the actual cookie black-box"
  [log-state
   shared-key
   nonce-suffix
   pk-session
   black-box]
  ;; It almost doesn't seem worth having a stand-alone
  ;; function for this.
  ;; Then again, a semantically meaningful wrapper with logging
  ;; isn't a bad thing
  (let [log-state (log/debug log-state
                             ::build-cookie-wrapper
                             "Trying to encrypt the real cookie"
                             {::templates/s' pk-session
                              ::templates/inner-cookie black-box
                              ::inner-box-size (count black-box)})]
    (try
      (let [result
            (crypto/build-box templates/cookie
                              {::templates/s' pk-session
                               ::templates/inner-cookie black-box}
                              shared-key
                              K/cookie-nonce-prefix
                              nonce-suffix)]
        {::weald/state (log/debug log-state
                                ::build-cookie-wrapper
                                "Encrypting the real cookie succeeded")
         ::templates/encrypted-cookie result})
      (catch Throwable ex
        {::weald/state (log/exception log-state ex ::build-cookie-wrapper
                                      "Trying to build the crypto box")}))))

(s/fdef prepare-packet!
        :args (s/cat :this ::state/state)
        :ret (s/keys :req [::weald/state]
                     :opt [::templates/encrypted-cookie
                           ::specs/server-nonce-suffix]))
(defn prepare-packet!
  "Set up the inner cookie"
  [{:keys [::state/client-short<->server-long
           ::weald/logger
           ::state/minute-key]
     client-short-pk ::state/client-short-pk
    log-state ::weald/state}]
  (let [client-short-pk (bytes client-short-pk)
        ^com.iwebpp.crypto.TweetNaclFast$Box$KeyPair session-keys (crypto/random-key-pair)
        {black-box ::specs/byte-array
         log-state ::weald/state
         nonce-suffix ::specs/server-nonce-suffix} (build-inner-cookie log-state
                                                                       client-short-pk
                                                                       (.getSecretKey session-keys)
                                                                       minute-key)
        {cookie ::templates/encrypted-cookie
         log-state ::weald/state} (build-cookie-wrapper log-state
                                                        client-short<->server-long
                                                        nonce-suffix
                                                        (.getPublicKey session-keys)
                                                        black-box)
        log-state (log/info log-state
                            ::prepare-cookie!
                            "Full cookie going to client that it should be able to decrypt"
                            {::templates/inner-cookie
                             (try (with-out-str (b-s/print-bytes cookie))
                                  (catch Exception ex
                                    (log/exception (log/clean-fork log-state ::print-cookie)
                                                   ex
                                                   ::prepare-cookie!
                                                   "Trying to show cookie contents"
                                                   {::templates/inner-cookie (vec cookie)})))
                              ::shared-secret (str "FIXME: Don't log this!\n"
                                                   (try
                                                     (with-out-str (b-s/print-bytes client-short<->server-long))
                                                     (catch Exception ex
                                                       (log/exception (log/clean-fork log-state ::print-client-short<->server-long)
                                                                      ex
                                                                      ::prepare-cookie!
                                                                      "Trying to show shared key"
                                                                      {::state/client-short<->server-long (vec client-short<->server-long)}))))})]
    {::templates/encrypted-cookie cookie
     ::K/srvr-nonce-suffix nonce-suffix
     ::weald/state log-state}))

(s/fdef build-cookie-packet
        :args (s/cat)
        :ret ::K/cookie-packet)
(defn build-cookie-packet
  [{client-extension ::K/clnt-xtn
    server-extension ::K/srvr-xtn}
   nonce-suffix
   crypto-cookie]
  (let [nonce-suffix (bytes nonce-suffix)]
    (let [fillers {::templates/client-extension client-extension
                   ::templates/server-extension server-extension
                   ::templates/client-nonce-suffix nonce-suffix
                   ::templates/cookie crypto-cookie}
          ^ByteBuf composed (serial/compose templates/cookie-frame fillers)]
      (b-s/convert composed specs/byte-array-type))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-build-response
        :args (s/cat :state ::state/state
                     :recipe (s/keys :req [::srvr-specs/cookie-components ::K/hello-spec]))
        :ret (s/keys :req [::weald/state]
                     :opt [::K/cookie-packet]))
(defn do-build-response
  [{:keys [::weald/logger]
    log-state ::weald/state
    :as state}
   {:keys [::srvr-specs/cookie-components
           ::K/hello-spec]}]
  (let [log-state (log/info log-state
                             ::do-build-response
                             "Preparing cookie")
        {crypto-box ::templates/encrypted-cookie
         nonce-suffix ::K/srvr-nonce-suffix
         log-state ::weald/state} (prepare-packet! (assoc cookie-components
                                                          ::weald/logger logger
                                                          ::weald/state log-state))]
    ;; Note that the reference implementation overwrites this incoming message in place.
    ;; That seems dangerous, but the HELLO is very deliberately longer than
    ;; our response.
    ;; And it does save a malloc/GC.
    ;; I can't do that, because of the way compose works.
    ;; TODO: Revisit this decision if/when the GC turns into a problem.
    {::K/cookie-packet (build-cookie-packet hello-spec nonce-suffix crypto-box)
     ::weald/state log-state}))
