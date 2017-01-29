(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach gets complicated
  on the server side. At least half the point there is
  reducing DoS."
  (:require [byte-streams :as b-s]
            [clojure.core.async :as async]
            [clojure.pprint :refer (pprint)]
            [clojure.spec :as s]
            [com.frereth.common.curve.shared :as shared]
            [com.frereth.common.schema :as schema]
            [com.stuartsierra.component :as cpt]
            [manifold.deferred :as deferred]
            ;; Mixing this and core.async seems dubious, at best
            [manifold.stream :as stream]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def default-timeout 2500)
(def heartbeat-interval (* 15 shared/millis-in-second))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::chan->child ::schema/manifold-stream)
(s/def ::chan<-child ::schema/manifold-stream)
(s/def ::chan->server ::schema/manifold-stream)
(s/def ::chan<-server ::schema/manifold-stream)

;; Periodically pull the client extension from...wherever it comes from.
;; Q: Why?
;; A: Has to do with randomizing and security, like sending from a random
;; UDP port. This will pull in updates when and if some mechanism is
;; added to implement that sort of thing.
;; Actually doing anything useful with this seems like it's probably
;; an exercise that's been left for later
(s/def ::client-extension-load-time integer?)

(s/def ::server-long-term-pk ::shared/public-key)
(s/def ::server-cookie any?)  ; TODO: Needs a real spec
(s/def ::server-short-term-pk ::shared/public-key)
(s/def ::server-security (s/keys :req [::server-long-term-pk
                                       ;; Q: Is there a valid reason for this to live here?
                                       ;; I can discard it after sending the vouch, can't I?
                                       ::server-cookie
                                       ::shared/server-name
                                       ::server-short-term-pk]))

(s/def ::client-long<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-long ::shared/shared-secret)
(s/def ::client-short<->server-short ::shared/shared-secret)
(s/def ::shared-secrets (s/keys :req [::client-long<->server-long
                                      ::client-short<->server-long
                                      ::client-short<->server-short]))

;; Q: What is this, and how is it used?
;; A: Well, it has something to do with messages from the Child to the Server.
(s/def ::outgoing-message any?)

;; The parts that change really need to be stored in a mutable
;; data structure.
;; An agent really does seem like it was specifically designed
;; for this.
;; Parts of this mutate over time. Others advance with the handshake
;; FSM. And others are really just temporary members.
;; I could also handle this with refs, but combining STM with
;; mutable byte arrays (which is where the "real work"
;; happens) seems like a recipe for disaster.
(s/def ::mutable-state (s/keys :req [::client-extension-load-time
                                     ::shared/extension
                                     ::outgoing-message
                                     ::shared/packet-management
                                     ::shared/recent
                                     ::server-security
                                     ::shared-secrets
                                     ::shared/work-area]
                               :opt [::chan->child
                                     ::chan<-child
                                     ;; Q: Why am I tempted to store this at all?
                                     ;; A: Well...I might need to resend it if it
                                     ;; gets dropped initially.
                                     ::vouch]))
(s/def ::immutable-value (s/keys :req [::shared/my-keys
                                       ;; Q: How do these mesh with netty's pipeline model?
                                       ;; For that matter, how much sense does the idea of
                                       ;; spawning a child process here?
                                       ::chan->server
                                       ::chan<-server
                                       ::child-spawner
                                       ::server-extension
                                       ::timeout]))
(s/def ::state (s/merge ::mutable-state
                        ::immutable-value))

(s/def ::state-agent (s/and #(instance? clojure.lang.Agent %)
                            #(s/valid? ::state (deref %))))

;; Accepts the agent that owns "this" and returns a channel we can
;; use to send messages to the child.
;; The child will send messages back to us using the standard agent
;; (send...)
;; Or maybe it should notify us about changes to a shared ring buffer.
;; This is where the reference implementation seems to get murky.
;; And, really, this approach is wrong.
;; It seems much wiser to let the caller control the child creation
;; and just supply us with the communication channel(s).
;; Although it might be a lot more sensible for this to own
;; ::chan->child and ::chan->server since it's the central
;; location that will first get the indication that ::chan<-child
;; or ::chan<-server has closed.
(s/def ::child-spawner (s/fspec :args (s/cat :this ::state-agent)
                                :ret ::chan<-child))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn current-timeout
  "How long should next step wait before giving up?"
  [wrapper]
  (-> wrapper deref ::timeout
      (or default-timeout)))

(defn hide-long-arrays
  "Make pretty printing a little less verbose"
  [this]
  (-> this
      ;; TODO: Write a mirror image version of dns-encode to just show this
      (assoc-in [::server-security :server-name] "name")
      (assoc-in [::shared/packet-management ::shared/packet] "...packet bytes...")
      (assoc-in [::shared/work-area ::shared/working-nonce] "...FIXME: Decode nonce bytes")
      (assoc-in [::shared/work-area ::shared/text] "...plain/cipher text")))

(defn clientextension-init
  "Starting from the assumption that this is neither performance critical
nor subject to timing attacks because it just won't be called very often."
  [{:keys [::client-extension-load-time
           ::shared/extension
           ::recent]
    :as this}]
  {:pre [(and client-extension-load-time recent)]}
  (let [reload (>= recent client-extension-load-time)
        _ (println "Reloading extension:" reload "(currently:" extension  ") in"
                   #_(with-out-str (pprint (hide-long-arrays this)))
                   (keys (hide-long-arrays this)))
        client-extension-load-time (if reload
                                     (+ recent (* 30 shared/nanos-in-second)
                                        client-extension-load-time))
        extension (if reload
                    (try (-> "/etc/curvecpextension"
                             ;; This is pretty inefficient...we really only want 16 bytes.
                             ;; Should be good enough for a starting point, though
                             slurp
                             (subs 0 16)
                             .getBytes)
                         (catch java.io.FileNotFoundException _
                           (println "Missing extension file")
                           (shared/zero-bytes 16)))
                    extension)]
    (assert (= (count extension) shared/extension-length))
    (println "Loaded extension:" (vec extension))
    (assoc this
           ::client-extension-load-time client-extension-load-time
           ::shared/extension extension)))

(defn update-client-short-term-nonce
  "Note that this can loop right back to a negative number."
  [^Long nonce]
  (let [result (unchecked-inc nonce)]
    (when (= result 0)
      (throw (ex-info "nonce space expired"
                      {:must "End communication immediately"})))
    result))

(defn build-raw-hello
  [{:keys [::server-extension
           ::shared/extension
           ::shared/my-keys
           ::shared-secrets]}
   short-term-nonce
   working-nonce]
  {::shared/prefix shared/hello-header
   ::shared/srvr-xtn server-extension
   ::shared/clnt-xtn extension
   ::shared/clnt-short-pk (.getPublicKey (::shared/short-pair my-keys))
   ::shared/zeros nil
   ::shared/nonce short-term-nonce
   ::shared/crypto-box (.after (::client-short<->server-long shared-secrets)
                               shared/all-zeros 0 64 working-nonce)})

(s/fdef build-actual-hello-packet
        :args (s/cat :this ::state
                     ;; TODO: Verify that this is a long
                     :short-nonce integer?
                     :working-nonce bytes?)
        :ret ::state)
(defn build-actual-hello-packet
  [{:keys [::shared/packet-management]
    :as this}
   short-term-nonce
   working-nonce]
  (assert packet-management)
  (let [raw-hello (build-raw-hello this short-term-nonce working-nonce)
        {packet ::shared/packet} packet-management
        _ (assert packet)]
    (shared/compose shared/hello-packet-dscr raw-hello packet)))
(comment
  (let [my-short (shared/random-key-pair)
        server-long (shared/random-key-pair)
        my<->server (shared/crypto-box-prepare (.getPublicKey server-long)
                                               (.getSecretKey my-short))
        this {::server-extension (byte-array [0x01 0x02 0x03 0x04
                                              0x05 0x06 0x07 0x08
                                              0x09 0x0a 0x0b 0x0b
                                              0x0c 0x0d 0x0e 0x0f])
              ::shared/extension (byte-array [0x10 0x20 0x30 0x40
                                              0x50 0x60 0x70 0x80
                                              0x90 0xa0 0xb0 0xb0
                                              0xc0 0xd0 0xe0 0xf0])
              ::shared/my-keys {::shared/short-pair my-short}
              ::shared/packet-management (shared/default-packet-manager)
              ::shared-secrets {::client-short<->server-long my<->server}}
        short-nonce 0x03
        ;; Q: How close is this?
        working-nonce (byte-array [(byte \C) (byte \u) (byte \r) (byte \v) (byte \e)
                                   (byte \C) (byte \P) (byte \-) (byte \c) (byte \l)
                                   (byte \i) (byte \e) (byte \n) (byte \t) (byte \-)
                                   (byte \H)
                                   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x03])]
    (comment
      (-> this ::shared/packet-management ::shared/packet .capacity)

      (build-raw-hello this short-nonce working-nonce))
    (def hello-sample
      (try
        (build-actual-hello-packet this
                                   short-nonce
                                   working-nonce)
        (catch clojure.lang.ExceptionInfo ex
          (println "Details:" (.getData ex))
          (throw ex)))))
  hello-sample
  (.readableBytes hello-sample)
  (shared/decompose shared/hello-packet-dscr hello-sample)
  )

(defn do-build-hello
  "Puts plain-text hello packet into packet-management

Note that this is really called for side-effects"
  [{:keys [
           ::shared/packet-management

           ::shared/work-area]
    :as this}]
  (let [this (clientextension-init this) ; There's a good chance this updates my extension
        working-nonce (::shared/working-nonce work-area)
        {:keys [::shared/packet-nonce ::shared/packet]} packet-management
        short-term-nonce (update-client-short-term-nonce packet-nonce)]
    (shared/byte-copy! working-nonce shared/hello-nonce-prefix)
    (shared/uint64-pack! working-nonce shared/client-nonce-prefix-length short-term-nonce)

    (let [packet (build-actual-hello-packet this short-term-nonce working-nonce)]
      (update this ::shared/packet-management
              (fn [current]
                (assoc current
                       ::shared/packet-nonce short-term-nonce
                       ::shared/packet (b-s/convert packet io.netty.buffer.ByteBuf)))))))

(defn decrypt-actual-cookie
  [{:keys [::shared/packet-management
           ::shared-secrets
           ::server-security
           ::shared/text]
    :as this}
   rcvd]
  (let [nonce (::shared/nonce packet-management)]
    (shared/byte-copy! nonce shared/cookie-nonce-prefix)
    (shared/byte-copy! nonce
                       shared/server-nonce-prefix-length
                       shared/server-nonce-suffix-length
                       ;; This one is neither namespaced (for now)
                       ;; nor part of shared
                       (:nonce rcvd))
    ;; Wait...what?
    ;; Where's :cookie coming from?!
    ;; (I can see it coming from the packet after I've used gloss to decode it,
    ;; but this doesn't seem to make any sense
    (shared/byte-copy! text 0 144 (-> packet-management ::shared/packet :cookie))
    (let [decrypted (.open_after (::client-short<->server-long shared-secrets) text 0 144 nonce)
          extracted (shared/decompose shared/cookie decrypted)
          server-short-term-pk (byte-array shared/key-length)
          server-cookie (byte-array 96)
          server-security (assoc (:server-security this)
                                 ::server-short-term-pk server-short-term-pk
                                 ::server-cookie server-cookie)]
      (shared/byte-copy! server-short-term-pk (:s' extracted))
      (shared/byte-copy! server-cookie (:cookie extracted))
      (assoc this ::server-security server-security))))

(defn decrypt-cookie-packet
  [{:keys [::shared/extension
           ::shared/packet-management
           ::server-extension]
    :as this}]
  (let [packet (::shared/packet packet-management)]
    ;; Q: How does packet length actually work?
    ;; A: We used to have the full length of the byte array here
    ;; Now that we don't, what's the next step?
    (when-not (= (.readableBytes packet) shared/cookie-packet-length)
      (let [err {:expected-length shared/cookie-packet-length
                 :actual-length (.readableBytes packet)
                 :packet packet}]
        (throw (ex-info "Incoming cookie packet illegal" err))))
    (let [rcvd (shared/decompose shared/cookie-frame packet)]
      ;; Reference implementation starts by comparing the
      ;; server IP and port vs. what we received.
      ;; Which we don't have here.
      ;; That's a really important detail.
      ;; We have access to both org.clojure/tools.logging
      ;; (from aleph)
      ;; and commons.logging (looks like I added this one)
      ;; here.
      ;; TODO: Really should log to one or the other
      (println "WARNING: Verify that this packet came from the appropriate server")
      ;; Q: How accurate/useful is this approach?
      ;; A: Not at all.
      ;; (i.e. mostly comparing byte arrays
      (when (and (shared/bytes= shared/cookie-header
                                (String. (:header rcvd)))
                 (shared/bytes= extension (:client-extension rcvd))
                 (shared/bytes= server-extension (:server-extension rcvd)))
        (decrypt-actual-cookie this rcvd)))))

(defn build-vouch
  [{:keys [packet-management
           my-keys
           shared-secrets
           text]
    :as this}]
  (let [nonce (::shared/nonce packet-management)
        keydir (::keydir my-keys)]
    (shared/byte-copy! nonce shared/vouch-nonce-prefix)
    (shared/safe-nonce nonce keydir shared/client-nonce-prefix-length)

    ;; Q: What's the point to these 32 bytes?
    (shared/byte-copy! text (shared/zero-bytes 32))
    (shared/byte-copy! text shared/key-length shared/key-length (.getPublicKey (::short-pair my-keys)))
    (let [encrypted (.after (::client-long<->server-long shared-secrets) text 0 64 nonce)
          vouch (byte-array 64)]
      (shared/byte-copy! vouch
                         0
                         shared/server-nonce-suffix-length
                         nonce
                         shared/server-nonce-prefix-length)
      (shared/byte-copy! vouch
                         shared/server-nonce-suffix-length
                         48
                         encrypted
                         shared/server-nonce-suffix-length)
      vouch)))

(defn extract-child-message
  "Pretty much blindly translated from the CurveCP reference
implementation. This is code that I don't understand yet"
  [this buffer]
  (let [reducer (fn [{:keys [buf
                             buf-len
                             msg
                             msg-len
                             i
                             this]
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
                      (let [{:keys [extension
                                    my-keys
                                    packet-management
                                    server-extension
                                    shared-secrets
                                    server-security
                                    text
                                    vouch
                                    work-area]
                             :as this} (clientextension-init this)
                            {:keys [::shared/packet
                                    ::shared/packet-nonce]} packet-management
                            _ (throw (RuntimeException. "this Component nonce isn't updated"))
                            short-term-nonce (update-client-short-term-nonce
                                              packet-nonce)
                            working-nonce (:shared/working-nonce work-area)]
                        (shared/uint64-pack! working-nonce shared/client-nonce-prefix-length
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
                        (let [r (dec msg-len)]
                          (when (or (< r 16)
                                    (> r 640))
                            (throw (ex-info "done" {})))
                          (shared/byte-copy! working-nonce 0 shared/client-nonce-prefix-length
                                             shared/initiate-nonce-prefix)
                                    ;; Reference version starts by zeroing first 32 bytes.
                                    ;; I thought we just needed 16 for the encryption buffer
                                    ;; And that doesn't really seem to apply here
                                    ;; Q: What's up with this?
                                    ;; (it doesn't seem to match the spec, either)
                                    (shared/byte-copy! text 0 32 shared/all-zeros)
                                    (shared/byte-copy! text 32 shared/key-length
                                                       (.getPublicKey (::long-pair my-keys)))
                                    (shared/byte-copy! text 64 64 vouch)
                                    (shared/byte-copy! text
                                                       128
                                                       shared/server-name-length
                                                       (::server-name server-security))
                                    ;; First byte is a magical length marker
                                    (shared/byte-copy! text 384 r msg 1)
                                    (let [box (.after (::client-short<->server-short shared-secrets)
                                                      text
                                                      0
                                                      (+ r 384)
                                                      working-nonce)]
                                      (shared/byte-copy! packet
                                                         0
                                                         shared/server-nonce-prefix-length
                                                         shared/initiate-header)
                                      (let [offset shared/server-nonce-prefix-length]
                                        (shared/byte-copy! packet offset
                                                           shared/extension-length server-extension)
                                        (let [offset (+ offset shared/extension-length)]
                                          (shared/byte-copy! packet offset
                                                             shared/extension-length extension)
                                          (let [offset (+ offset shared/extension-length)]
                                            (shared/byte-copy! packet offset shared/key-length
                                                               (.getPublicKey (::short-pair my-keys)))
                                            (let [offset (+ offset shared/key-length)]
                                              (shared/byte-copy! packet
                                                                 offset
                                                                 shared/server-cookie-length
                                                                 (::server-cookie server-security))
                                              (let [offset (+ offset shared/server-cookie-length)]
                                                (shared/byte-copy! packet offset
                                                                   shared/server-nonce-prefix-length
                                                                   working-nonce
                                                                   shared/server-nonce-suffix-length))))))
                                      ;; Actually, the original version sends off the packet, updates
                                      ;; msg-len to 0, and goes back to pulling date from child/server.
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
    (assoc this :outgoing-message (:child-msg extracted))))

(defn load-keys
  [my-keys]
  (let [long-pair (shared/do-load-keypair (::shared/keydir my-keys))
        short-pair (shared/random-key-pair)]
    (assoc my-keys
           ::shared/long-pair long-pair
           ::shared/short-pair short-pair)))

(defn initialize-immutable-values
  "Sets up the immutable value that will be used in tandem with the mutable agent later"
  [this]
  ;; In theory, it seems like it would make sense to -> this through a chain of
  ;; these sorts of initializers.
  ;; In practice, as it stands, it seems a little silly.
  (update this ::shared/my-keys load-keys))

(defn initialize-mutable-state!
  [{:keys [::shared/my-keys
           ::server-security]
    :as this}]
  {:pre [(::server-long-term-pk server-security)]}
  (let [server-long-term-pk (::server-long-term-pk server-security)
        long-pair (::shared/long-pair my-keys)
        short-pair (::shared/short-pair my-keys)]
    (into this
          {::client-extension-load-time 0
           ::recent (System/nanoTime)
           ;; This seems like something that we should be able to set here.
           ;; djb's docs say that it's a security matter, like connecting from a
           ;; random port.
           ;; Hopefully, someday, operating systems will have some mechanism for
           ;; rotating these automatically
           ;; Q: Is this really better than just picking something random here?
           ;; A: Who am I to argue with an expert?
           ::server-security server-security
           ::shared/extension nil
           ::shared-secrets {::client-long<->server-long (shared/crypto-box-prepare
                                                          server-long-term-pk
                                                          (.getSecretKey short-pair))
                             ::client-short<->server-long (shared/crypto-box-prepare
                                                           server-long-term-pk
                                                           (.getSecretKey long-pair))}})))

(defn child-exited!
  [this]
  (throw (ex-info "child exited" this)))

(defn hello-failed!
  [this failure]
  (send this #(throw (ex-info "Hello failed"
                              (assoc %
                                     :problem failure)))))

(defn hello-response-timed-out!
  [this failure]
  (send this #(throw (ex-info "Timed out waiting for hello response"
                              (assoc %
                                     :problem failure)))))

(defn server-closed!
  "This seems pretty meaningless in a UDP context"
  [this]
  (throw (ex-info "Server Closed" this)))

(defn child->server
  [this msg]
  (throw (RuntimeException. "Not translated")))

(defn server->child
  [this msg]
  (throw (RuntimeException. "Not translated")))

(defn ->message-exchange-mode
  [wrapper
   initial-server-response]
  (let [{:keys [::chan<-server
                ::chan->server
                ::chan<-child
                ::chan->child]
         :as this} @wrapper]
    ;; Forward that initial "real" message
    (send wrapper server->child initial-server-response)
    ;; Q: Do I want to block this thread for this?
    (comment (await-for (current-timeout wrapper) wrapper))

    ;; And then wire this up to pretty much just pass messages through
    ;; Actually, this seems totally broken from any angle, since we need
    ;; to handle decrypting, at a minimum
    (stream/connect-via chan<-child #(send wrapper chan->server %) chan->server)

    ;; I'd like to just do this in final-wait and take out an indirection
    ;; level.
    ;; But I don't want children to have to know the implementation detail
    ;; that they have to wait for the initial response before the floodgates
    ;; can open.
    ;; So go with this approach until something better comes to mind
    (stream/connect-via chan<-server #(send wrapper chan->child %) chan->child)))

(defn final-wait
  "We've received the cookie and responded with a vouch.
  Now waiting for the server's first real message
  packet so we can switch into the message exchange
  loop"
  [wrapper _]
  (let [timeout (current-timeout wrapper)
        chan<-server (::chan<-server @wrapper)
        taken (stream/try-take! chan<-server ::drained timeout ::initial-response-timed-out)]
    (deferred/on-realized taken
      #(send-off wrapper ->message-exchange-mode %)
      (fn [ex]
        (send wrapper #(throw (ex-info "Server vouch response failed"
                                       (assoc % :problem ex))))))))

(s/fdef fork
        :args (s/cat :wrapper ::state-agent
                       :this ::state)
        :ret ::state)
(defn fork
  "This has to 'fork' a child with access to the agent, and update the agent state

So, yes, it *is* weird.

It happens in the agent processing thread pool, during a send operation.

It's the child's responsibility to return a manifold.stream we can use to send it
bytes from the server.

It notifies us that it has bytes ready to process via the standard agent (send)
mechanism.

Although send-off might seem more appropriate, it probably isn't.

TODO: Need to ask around about that."
  [wrapper
   {:keys [::child-spawner]
    :as this}]
  (assoc this ::chan->child (child-spawner wrapper)))

(defn cookie->vouch
  "Got a cookie from the server.

  Replace those bytes
  in our packet buffer with the vouch bytes we'll use
  as the response.

  Handling an agent (send)"
  [this cookie-packet]
  ;; Q: What is really in cookie-packet now?
  ;; (I think it's a netty ByteBuf)
  (let [this (assoc-in this [:packet-management ::shared/packet] cookie-packet)]
    (if (decrypt-cookie-packet this)
      (let [{:keys [::my-keys]} this
            this (assoc-in this
                           [::shared-secrets ::client-short<->server-short]
                           (shared/crypto-box-prepare
                            (get-in this
                                    [::server-security
                                     ::server-short-term-pk])
                            (.getSecretKey (::short-pair my-keys))))]
        ;; Note that this supplies new state
        ;; Though whether it should is debatable
        (assoc this ::vouch (build-vouch this)))
      (throw (ex-info
              "Unable to decrypt server cookie"
              this)))))

(defn send-vouch!
  "Send the Vouch/Initiate packet (along with an initial Message sub-packet)"
  [wrapper]
  (let [timeout (current-timeout wrapper)
        chan->server (::chan->server @wrapper)
        d (stream/try-put! chan->server
                      timeout
                      ::timedout)]
    (deferred/on-realized d (partial final-wait wrapper)
      (fn [failure]
        ;; Extremely unlikely, but
        ;; just for the sake of paranoia
        (send wrapper
              (fn [this]
                (throw (ex-info "Timed out sending cookie->vouch response"
                                (assoc this
                                       :problem failure)))))))))

(defn build-and-send-vouch
  [wrapper cookie-packet]
  (send wrapper (partial fork wrapper))
  (send wrapper cookie->vouch cookie-packet)
  (let [timeout (current-timeout wrapper)]
    (if (await-for timeout wrapper)
      (send-vouch! wrapper)
      (send wrapper
            #(throw (ex-info "cookie->vouch timed out"
                             %))))))

(defn wait-for-cookie
  [wrapper _]
  (let [chan<-server (::chan<-server @wrapper)
        timeout (current-timeout wrapper)
        d (deferred/timeout! (stream/take! chan<-server)
            timeout
            ::hello-timed-out)]
    (deferred/on-realized d
      (partial build-and-send-vouch wrapper)
      (partial hello-response-timed-out! wrapper))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef start!
        :args (s/cat :this ::state-agent)
        ;; Q: Does this return anything meaningful at all?
        :ret any?)
(defn start!
  "This almost seems like it belongs in ctor.

But not quite, since it's really a side-effect that sets up another.

Q: Is there something equivalent I can set up using core.async?

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
    (throw (ex-info "Agent already failed"
                    {:problem failure})))

  (let [this @wrapper
        {:keys [::chan->server]} this
        timeout (current-timeout wrapper)]
    (stream/on-drained chan->server
                       #(send wrapper server-closed!))
    ;; This feels inside-out and backwards.
    ;; But it probably should, since this is very
    ;; explicitly place-oriented programming working
    ;; with mutable state.
    (send wrapper do-build-hello)
    (if (await-for timeout wrapper)
      (let [packet (-> wrapper
                       deref
                       ::shared/packet-management
                       ::shared/packet)
            ;; Major flaw in this implementation: I only want to
            ;; put 224 bytes here.
            ;; Pretty sure that needs to be a ByteBuf, since
            ;; that's what netty speaks.
            ;; Really need to just break down and do that translation
            ;; while I know how many bytes I'm sending.
            _ (println "Putting" packet "onto" chan->server)
            ;; There's still an important break
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
            d (stream/try-put! chan->server packet timeout ::hello-timed-out)]
        (deferred/on-realized d
          (partial wait-for-cookie wrapper)
          (partial hello-failed! wrapper)))
      (throw (ex-info "Building the hello failed" {:problem (agent-error wrapper)})))))

(s/fdef ctor
        :args (s/keys :req [::chan<-server
                            ::chan->server
                            ::shared/my-keys
                            ::server-security])
        :ret ::state-agent)
(defn ctor
  [opts]
  (-> (initialize-immutable-values opts)
      (initialize-mutable-state!)
      (assoc
       ;; This seems very cheese-ball, but they
       ;; *do* need to be part of the agent.
       ;; We definitely don't want multiple threads
       ;; messing with them
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
