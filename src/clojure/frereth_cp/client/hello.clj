(ns frereth-cp.client.hello
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as shared-specs]
            [frereth-cp.util :as util])
  (:import com.iwebpp.crypto.TweetNaclFast$Box$KeyPair))

(set! *warn-on-reflection* true)

(defn build-raw
  [{:keys [::state/server-extension
           ::shared/extension
           ::shared/my-keys
           ::state/shared-secrets]
    :as this}
   short-term-nonce
   working-nonce]
  (if-let [{:keys [::state/server-security]} this]
    (log/debug "server-security for raw-hello:" server-security)
    (log/warn "Missing server-security among" (keys this)
              "\nin\n" this))

  (let [my-short<->their-long (::state/client-short<->server-long shared-secrets)
        _ (assert my-short<->their-long)
        ;; Note that this definitely inserts the 16-byte prefix for me
        boxed (crypto/box-after my-short<->their-long
                                K/all-zeros (- K/hello-crypto-box-length K/box-zero-bytes) working-nonce)
        ^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
        msg (str "Hello crypo-box:\n"
                 (b-t/->string boxed)
                 "\nencrypted with nonce\n"
                 (b-t/->string working-nonce)
                 "\nfrom\n"
                 (-> my-short-pair
                     .getPublicKey
                     b-t/->string)
                 "\nto\n"
                 (b-t/->string (get-in this [::state/server-security
                                             ::shared-specs/public-long]))
                 "\nshared\n"
                 (b-t/->string my-short<->their-long))]
    (log/info msg)
    {::K/hello-prefix nil
     ::K/srvr-xtn server-extension
     ::K/clnt-xtn extension
     ::K/clnt-short-pk (.getPublicKey my-short-pair)
     ::K/zeros nil
     ::K/client-nonce-suffix (b-t/sub-byte-array working-nonce K/client-nonce-prefix-length)
     ::K/crypto-box boxed}))

(s/fdef build-actual-hello-packet
        :args (s/cat :this ::state/state
                     ;; TODO: Verify that this is a long
                     :short-nonce integer?
                     :working-nonce bytes?)
        :ret ::state/state)
(defn build-actual-packet
  [{log-state ::log2/state
    :as this}
   short-term-nonce
   working-nonce]
  (let [raw-hello (build-raw this short-term-nonce working-nonce)
        log-state (log2/info log-state
                             ::build-actual-packet
                             "Building Hello"
                             {::description (util/pretty K/hello-packet-dscr)
                              ::raw (util/pretty raw-hello)})]
    {::shared/packet (serial/compose K/hello-packet-dscr raw-hello)
     ::log2/state log-state}))

(defn do-build-hello
  "Puts plain-text hello packet into packet-management

  Note that this is really called for side-effects"
  ;; A major part of the way this is written revolves around
  ;; updating packet-management and work-area in place.
  ;; That seems like premature optimization here.
  ;; Though it seems as though it might make sense for
  ;; sending messages.
  ;; Then again, if the implementation isn't shared...can
  ;; it possibly be worth the trouble?
  [{:keys [::shared/packet-management
           ::shared/work-area]
    log-state ::log2/state
    :as this}]
  (let [this (state/clientextension-init this) ; There's a good chance this updates my extension
        working-nonce (::shared/working-nonce work-area)
        {:keys [::shared/packet-nonce ::shared/packet]} packet-management
        short-term-nonce (state/update-client-short-term-nonce packet-nonce)]
    (b-t/byte-copy! working-nonce shared/hello-nonce-prefix)
    (b-t/uint64-pack! working-nonce K/client-nonce-prefix-length short-term-nonce)

    (let [log-state (log2/info log-state
                               ::do-build-hello
                               "Packed short-term- into working- -nonces"
                               {::short-term-nonce short-term-nonce
                                ::shared/working-nonce (b-t/->string working-nonce)})
          {:keys [::shared/packet]
           log-state ::log2/state} (build-actual-packet (assoc this ::log2/state log-state)
                                                        short-term-nonce
                                                        working-nonce)
          log-state (log2/info log-state
                               ::do-build-hello
                               "hello packet built inside the agent. Returning/updating")]
      (-> this
          (update ::shared/packet-management
                  (fn [current]
                    (assoc current
                           ::shared/packet-nonce short-term-nonce
                           ::shared/packet (b-s/convert packet io.netty.buffer.ByteBuf))))
          (assoc ::log2/state log-state)))))
