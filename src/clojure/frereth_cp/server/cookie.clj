(ns frereth-cp.server.cookie
  "For dealing with cookie packets on the server side"
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.server
             [shared-specs :as srvr-specs]
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

(defn build-inner-cookie-original
  "This is the way it used to be done"
  [log-state
   client-short-pk
   my-sk
   minute-key
   nonce-suffix]
  (let [^ByteBuf buffer (Unpooled/buffer K/server-cookie-length)
        client-short-pk (bytes client-short-pk)
        working-nonce (byte-array K/nonce-length)
        my-sk (bytes my-sk)]
    (b-t/byte-copy! working-nonce 8 specs/server-nonce-suffix-length nonce-suffix)
    (try
      ;; Set up the raw plaintext cookie
      (.writeBytes buffer K/all-zeros 0 K/decrypt-box-zero-bytes) ; line 315
      (.writeBytes buffer client-short-pk 0 K/key-length)
      (.writeBytes buffer my-sk 0 K/key-length)

      (b-t/byte-copy! working-nonce K/cookie-nonce-minute-prefix)

      (let [actual (.array buffer)
            result (byte-array K/server-cookie-length)]
        (println )
        (crypto/secret-box actual actual K/server-cookie-length working-nonce minute-key)
        ;; Original needs to leave 0 padding up front
        ;; Note that the first 16 of those 32 bytes are garbage.
        ;; They're meant to be overwritten by the nonce-suffix
        (comment (.getBytes buffer 0 text 32 K/server-cookie-length))
        (.getBytes buffer 0 result)
        (b-t/byte-copy! result nonce-suffix)
        result))))

(s/fdef build-inner-cookie
        :args (s/or :sans-nonce (s/cat :log-state ::log2/state
                                       :other-short-pk ::specs/public-short
                                       :my-short-sk ::specs/secret-short
                                       :minute-key ::specs/crypto-key)
                    :with-nonce (s/cat :log-state ::log2/state
                                       :client-short-pk ::specs/public-short
                                       :my-short-sk ::specs/secret-short
                                       :minute-key ::specs/crypto-key
                                       :working-nonce ::specs/nonce))
        :ret (s/keys :req [::specs/byte-array
                           ::log2/log-state
                           ::specs/server-nonce-suffix]))
(defn build-inner-cookie
  "Build the inner black-box Cookie portion of the Cookie Packet"
  ([log-state
    client-short-pk
    my-short-sk
    minute-key]
   (let [{log-state ::log2/state
          working-nonce ::crypto/safe-nonce} (crypto/get-safe-nonce log-state)]
     (build-inner-cookie log-state client-short-pk my-short-sk minute-key working-nonce)))
  ;; This arity really only exists for the sake of testing:
  ;; Being able to reproduce the nonce makes like much easier in that regard
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
   (let [boxed-cookie (crypto/build-box templates/black-box-dscr
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
      ::log2/state log-state
      ;; It seems silly to return this, since it was a parameter.
      ;; But this probably won't be called as a pure function.
      ;; Most callers will use the other arity that calls safe-nonce.
      ;; OK, there's probably only one caller. It reuses half of
      ;; this suffix.
      ::specs/server-nonce-suffix nonce-suffix})))

;; FIXME: Write this spec
(s/fdef prepare-packet!
        :args (s/cat :this ::state/state)
        :ret {::log2/state
              ::specs/byte-array})
(defn prepare-packet!
  "Set up the inner cookie"
  [{:keys [::state/client-short<->server-long
           ::log2/logger
           ::state/minute-key
           ::shared/working-nonce]
     client-short-pk ::state/client-short-pk
    log-state ::log2/state}]
  (let [client-short-pk (bytes client-short-pk)
        ^com.iwebpp.crypto.TweetNaclFast$Box$KeyPair key-pair (crypto/random-key-pair)
        {black-box ::specs/byte-array
         log-state ::log2/state
         working-nonce ::specs/server-nonce-suffix} (build-inner-cookie log-state
                                                                   client-short-pk
                                                                   (.getSecretKey key-pair)
                                                                   minute-key)
        black-box (bytes black-box)
        _ (throw (RuntimeException. "Need to restore code that built the cookie around the black-box"))
        cookie nil
        log-state (log2/info log-state
                             ::prepare-cookie!
                             "Full cookie going to client that it should be able to decrypt"
                             {::specs/byte-array (try (with-out-str (b-s/print-bytes cookie))
                                                      (catch Exception ex
                                                        (log/error ex "Trying to show cookie contents")
                                                        (vec cookie)))
                              ::shared-secret (str "FIXME: Don't log this!\n"
                                                   (try
                                                     (with-out-str (b-s/print-bytes client-short<->server-long))
                                                     (catch Exception ex
                                                       (log/error ex "Trying to show shared key")
                                                       (vec client-short<->server-long))))})]
    {::specs/byte-array cookie
     ::log2/state log-state}))

(s/fdef build-cookie-packet
        :args (s/cat)
        ;; FIXME: Just return a B]
        :ret ::specs/byte-buf)
(defn build-cookie-packet
  [{client-extension ::K/clnt-xtn
    server-extension ::K/srvr-xtn}
   working-nonce
   crypto-cookie]
  (let [working-nonce (bytes working-nonce)
        nonce-suffix (byte-array specs/server-nonce-suffix-length)]
    (b-t/byte-copy! nonce-suffix 0
                    specs/server-nonce-suffix-length
                    working-nonce
                    specs/server-nonce-prefix-length)
    ;; Big nope on crypto-cookie.
    ;; What I have here is the 96 byte inner cookie (what I'm calling
    ;; the black-box).
    ;; It's lost the portion that converts it to a boxed "cookie"
    (throw (RuntimeException. "Start back here"))
    (let [fillers {::templates/header K/cookie-header
                   ::templates/client-extension client-extension
                   ::templates/server-extension server-extension
                   ::templates/client-nonce-suffix nonce-suffix
                   ::templates/cookie crypto-cookie}
          ^ByteBuf composed (serial/compose templates/cookie-frame fillers)]
      ;; I really shouldn't need to do this
      ;; FIXME: Make sure it gets released
      ;; Better: extract the byte array and return that
      (.retain composed)
      composed)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef do-build-response
        :args (s/cat :state ::state/state
                     :recipe (s/keys :req [::srvr-specs/cookie-components ::K/hello-spec]))
        :ret ::specs/byte-buf)
(defn do-build-response
  [{:keys [::log2/logger]
    log-state ::log2/state
    :as state}
   {{:keys [::shared/working-nonce]
     :as cookie-components} ::srvr-specs/cookie-components
    hello-spec ::K/hello-spec}]
  (log/info "Preparing cookie")
  (let [{crypto-box ::specs/byte-array
         log-state ::log2/state} (prepare-packet! (assoc cookie-components
                                                         ::log2/logger logger
                                                         ::log2/state log-state))
        ;; FIXME: Don't just throw this away
        log-state (log2/flush-logs! logger log-state)]
    ;; Note that the reference implementation overwrites this incoming message in place.
    ;; That seems dangerous, but the HELLO is very deliberately longer than
    ;; our response.
    ;; And it does save a malloc/GC.
    ;; I can't do that, because of the way compose works.
    ;; TODO: Revisit this decision if/when the GC turns into a problem.
    (build-cookie-packet hello-spec working-nonce crypto-box)))
