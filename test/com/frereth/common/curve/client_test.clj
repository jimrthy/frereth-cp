(ns com.frereth.common.curve.client-test
  (:require [clojure.test :refer (deftest is)]
            [com.frereth.common.curve.client :as clnt]
            [com.frereth.common.curve.shared :as shared]
            [manifold.stream :as strm]))

(defn raw-client
  []
  (let [server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                      0x0d 0x0e 0x0f 0x10])
        server-long-pk (byte-array [37 108 -55 -28 25 -45 24 93
                                    51 -105 -107 -125 -120 -41 83 -46
                                    -23 -72 109 -58 -100 87 115 95
                                    89 -74 -21 -33 20 21 110 95])
        server-name (shared/encode-server-name "hypothet.i.cal")]
    (clnt/ctor {::clnt/chan<-server (strm/stream)
                ::clnt/chan->server (strm/stream)
                ::clnt/server-extension server-extension
                ;; Q: Where do I get the server's public key?
                ;; A: Right now, I just have the secret key's 32 bytes encoded as
                ;; the alphabet.
                ;; TODO: Really need to mirror what the code does to load the
                ;; secret key from a file.
                ;; Then I can just generate a random key pair for the server.
                ;; Use the key-put functionality to store the secret, then
                ;; hard-code the public key here.
                :server-security {::clnt/server-long-term-pk server-long-pk
                                  ::shared/server-name server-name}})))

(deftest start-stop
  (let [client (raw-client)
        server-chan (-> client deref :chan<-server)]
    (if server-chan
      (try
        (let [reader (-> client deref :chan->server)]
          (send-off client clnt/start-handshake!)
          ;; TODO: Really should do this, once I know start-handshake! will succeed
          (comment (await client))
          ;; But start with this instead, since I'm 90% certain the current
          ;; implementation will fail
          (let [hello-future (strm/take! reader ::drained)
                hello (deref hello-future 500 ::timeout)]
            (is (not (or (= hello ::timeout)
                         (= hello ::drained))))
            ;; Q: Can we do anything else meaningful here?
            ;; I mean...I have access to the private server key.
            ;; I could decrypt that packet to see what's in it.
            ;; But that seems to belong in the actual interactive
            ;; tests
            (is (bytes? hello))
            ;; Actually, this is an interesting point:
            ;; hello should really be a ByteBuffer.
            ;; Or a portion of a ByteArray that will be
            ;; copied into a ByteBuffer.
            (is (= shared/hello-packet-length (count hello)))
            (is (shared/bytes= shared/hello-header
                               (subvec (vec hello) 0 (count shared/hello-header))))))
        (finally
          (strm/close! server-chan)
          (Thread/sleep 0.2)
          (is (= ::server-closed @client))))
      (is server-chan "No channel to pull data from server"))))

(comment
  (def junk (raw-client))
  (-> junk :extension vec)
  (-> junk :server-extension vec)o
  junk
  (-> junk keys)
  (alter-var-root #'junk #(.start %))
  (alter-var-root #'junk #(.stop %)))

(defn basic-test
  "This should probably go away"
  []
  (let [client-keys (shared/random-key-pair)
        ;; Q: Do I want to use this or TweetNaclFast/keyPair?
        server-keys (shared/random-key-pair)
        msg "Hold on, my child needs my attention"
        bs (.getBytes msg)
        nonce (byte-array [1 2 3 4 5 6 7 8 9 10
                           11 12 13 14 15 16 17
                           18 19 20 21 22 23 24])
        boxer (shared/crypto-box-prepare (.getPublicKey server-keys) (.getSecretKey client-keys))
        ;; This seems likely to get confused due to arity issues
        boxed (.box boxer bs nonce)
        unboxer (shared/crypto-box-prepare (.getPublicKey client-keys) (.getSecretKey server-keys))]
    (String. (.open unboxer boxed nonce))))
(comment (basic-test))
