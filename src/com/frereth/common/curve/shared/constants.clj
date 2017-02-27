(ns com.frereth.common.curve.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec :as s]))

(def extension-length 16)
(def header-length 8)

(def box-zero-bytes 16)
(def decrypt-box-zero-bytes 32)
(def key-length 32)
(def max-random-nonce (long (Math/pow 2 48)))
(def nonce-length 24)
(def server-nonce-suffix-length 16)
(def shared-key-length key-length)

;;; Hello packets
(def hello-crypto-box-length 80)

;;; Cookie packets
(def cookie-header (.getBytes "RL3aNMXK"))
(def cookie-nonce-prefix (.getBytes "CurveCPK"))
(def server-cookie-length 96)
(def cookie-packet-length 200)

(def cookie-frame
  "The boiler plate around a cookie"
  ;; Header is only a "string" in the ASCII sense
  (array-map ::header {::type ::bytes
                       ::length header-length}
             ::client-extension {::type ::bytes
                                 ::length extension-length}
             ::server-extension {::type ::bytes
                                 ::length extension-length}
             ;; Implicitly prefixed with "CurveCPK"
             ::nonce {::type ::bytes
                      ::length server-nonce-suffix-length}
             ::cookie {::type ::bytes
                       ::length 144}))
