(ns com.frereth.common.curve.client
  "Implement the client half of the CurveCP protocol.

  It seems like it would be nice if I could just declare
  the message exchange, but that approach seems dubious"
  (:import [com.iwebpp.crypto TweetNaclFast
            TweetNaclFast$Box]))

(defn basic-test
  []
  (let [client-keys (TweetNaclFast$Box/keyPair)
        ;; Q: Do I want to use this or TweetNaclFast/keyPair?
        server-keys (TweetNaclFast$Box/keyPair)
        msg "Hold on, my child needs my attention"
        bs (.getBytes msg)
        ;; This can't possibly be the proper size
        nonce (byte-array [1 2 3 4 5 6 7 8 9 10
                           11 12 13 14 15 16 17
                           18 19 20 21 22 23 24])
        boxer (TweetNaclFast$Box. (.getPublicKey server-keys) (.getSecretKey client-keys))
        ;; This seems likely to get confused due to arity issues
        boxed (.box boxer bs nonce)
        unboxer (TweetNaclFast$Box. (.getPublicKey client-keys) (.getSecretKey server-keys))]
    (String. (.open unboxer boxed nonce))))

(comment (basic-test))
