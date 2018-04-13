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
  (:import com.iwebpp.crypto.TweetNaclFast$Box$KeyPair
           io.netty.buffer.ByteBuf))

(set! *warn-on-reflection* true)

(s/fdef build-raw
        :args (s/cat :this ::state/state
                      :short-term-nonce any?
                      :working-nonce ::shared/working-nonce)
        :ret (s/keys :req [::K/hello-spec ::log2/state]))
(defn build-raw
  [{:keys [::state/server-extension
           ::shared/extension
           ::shared/my-keys
           ::state/shared-secrets]
    log-state ::log2/state
    :as this}
   short-term-nonce
   working-nonce]
  (let [log-state
        (if-let [{:keys [::state/server-security]} this]
          (log2/debug log-state
                      ::build-raw
                      "server-security for raw-hello:" server-security)
          (log2/warn log-state
                     ::build-raw
                     "Missing server-security"
                     {::keys (keys this)
                      ::state/state this}))
        my-short<->their-long (::state/client-short<->server-long shared-secrets)
        _ (assert my-short<->their-long)
        ;; Note that this definitely inserts the 16-byte prefix for me
        boxed (crypto/box-after my-short<->their-long
                                K/all-zeros (- K/hello-crypto-box-length K/box-zero-bytes) working-nonce)
        ^TweetNaclFast$Box$KeyPair my-short-pair (::shared/short-pair my-keys)
        log-state (log2/info log-state
                             ::build-raw
                             "Details"
                             {::crypto-box (b-t/->string boxed)
                              ::shared/working-nonce (b-t/->string working-nonce)
                              ::my-short-pk (-> my-short-pair
                                                .getPublicKey
                                                b-t/->string)
                              ::server-long-pk (b-t/->string (get-in this [::state/server-security
                                                                           ::shared-specs/public-long]))
                              ::state/client-short<->server-long (b-t/->string my-short<->their-long)})]
    {::template {::K/hello-prefix nil  ; This is a constant, so there's no associated value
                 ::K/srvr-xtn server-extension
                 ::K/clnt-xtn extension
                 ::K/clnt-short-pk (.getPublicKey my-short-pair)
                 ::K/zeros nil
                 ::K/client-nonce-suffix (b-t/sub-byte-array working-nonce K/client-nonce-prefix-length)
                 ::K/crypto-box boxed}
     ::log2/state log-state}))

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
  (let [{raw-hello ::template
         log-state ::log2/state} (build-raw this short-term-nonce working-nonce)
        log-state (log2/info log-state
                             ::build-actual-packet
                             "Building Hello"
                             {::raw raw-hello})
        ^ByteBuf result (serial/compose K/hello-packet-dscr raw-hello)
        n (.readableBytes result)]
    (when (not= K/hello-packet-length n)
      (throw (ex-info "Built a bad HELLO"
                      {::expected-length K/hello-packet-length
                       ::actual n})))
    {::shared/packet result
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
  (let [;; There's a good chance this updates my extension
        ;; That doesn't get set into stone until/unless I
        ;; manage to handshake with a server
        this (state/clientextension-init this)
        working-nonce (::shared/working-nonce work-area)
        {:keys [::shared/packet-nonce ::shared/packet]} packet-management
        short-term-nonce (state/update-client-short-term-nonce packet-nonce)]
    (b-t/byte-copy! working-nonce K/hello-nonce-prefix)
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
