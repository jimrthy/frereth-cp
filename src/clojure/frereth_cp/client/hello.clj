(ns frereth-cp.client.hello
  (:require [byte-streams :as b-s]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.client.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.util :as util]))

(defn build-raw-hello
  [{:keys [::state/server-extension
           ::shared/extension
           ::shared/my-keys
           ::state/shared-secrets]
    :as this}
   short-term-nonce
   working-nonce]

  (let [my-short<->their-long (::state/client-short<->server-long shared-secrets)
        _ (assert my-short<->their-long)
        ;; Note that this definitely inserts the 16-byte prefix for me
        boxed (crypto/box-after my-short<->their-long
                                shared/all-zeros (- K/hello-crypto-box-length K/box-zero-bytes) working-nonce)
        msg (str "Hello crypo-box:\n"
                 (b-t/->string boxed)
                 "\nencrypted with nonce\n"
                 (b-t/->string working-nonce)
                 "\nfrom\n"
                 (-> my-keys
                     ::shared/short-pair
                     .getPublicKey
                     b-t/->string)
                 "\nto\n"
                 (b-t/->string (get-in this [::state/server-security
                                             ::state/server-long-term-pk]))
                 "\nshared\n"
                 (b-t/->string my-short<->their-long))]
    (log/info msg)
    {::K/prefix shared/hello-header
     ::K/srvr-xtn server-extension
     ::K/clnt-xtn extension
     ::K/clnt-short-pk (.getPublicKey (::shared/short-pair my-keys))
     ::K/zeros nil
     ::K/client-nonce-suffix (b-t/sub-byte-array working-nonce K/client-nonce-prefix-length)
     ::K/crypto-box boxed}))

(s/fdef build-actual-hello-packet
        :args (s/cat :this ::state/state
                     ;; TODO: Verify that this is a long
                     :short-nonce integer?
                     :working-nonce bytes?)
        :ret ::state/state)
(defn build-actual-hello-packet
  [{:keys [::shared/packet-management]
    :as this}
   short-term-nonce
   working-nonce]
  (assert packet-management)
  (let [raw-hello (build-raw-hello this short-term-nonce working-nonce)
        {packet ::shared/packet} packet-management]
    (assert packet)
    (log/info (str "Building Hello based on\n"
                   "Description:\n\t" (util/pretty K/hello-packet-dscr)
                   "\nRaw:\n\t" (util/pretty raw-hello)
                   "\nPacket:\n\t" packet))
    (shared/compose K/hello-packet-dscr raw-hello packet)))

(defn do-build-hello
  "Puts plain-text hello packet into packet-management

Note that this is really called for side-effects"
  [{:keys [::shared/packet-management
           ::shared/work-area]
    :as this}]
  (let [this (state/clientextension-init this) ; There's a good chance this updates my extension
        working-nonce (::shared/working-nonce work-area)
        {:keys [::shared/packet-nonce ::shared/packet]} packet-management
        short-term-nonce (state/update-client-short-term-nonce packet-nonce)]
    (b-t/byte-copy! working-nonce shared/hello-nonce-prefix)
    (b-t/uint64-pack! working-nonce K/client-nonce-prefix-length short-term-nonce)
    (log/info (str short-term-nonce " packed into\n"
                   (b-t/->string working-nonce)))

    (let [packet (build-actual-hello-packet this short-term-nonce working-nonce)]
      (log/info "hello packet built inside the agent. Returning/updating")
      (update this ::shared/packet-management
              (fn [current]
                (assoc current
                       ::shared/packet-nonce short-term-nonce
                       ::shared/packet (b-s/convert packet io.netty.buffer.ByteBuf)))))))
