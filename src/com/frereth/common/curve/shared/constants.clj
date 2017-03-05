(ns com.frereth.common.curve.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec :as s]))

(def client-nonce-prefix-length 16)
(def client-nonce-suffix-length 8)
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
(def hello-packet-dscr (array-map ::prefix {::type ::bytes ::length header-length}
                                  ::srvr-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-short-pk {::type ::bytes ::length key-length}
                                  ;; TODO: Need a named constant for this
                                  ::zeros {::type ::zeroes ::length 64}
                                  ;; This gets weird/confusing.
                                  ;; It's a 64-bit number, so 8 octets
                                  ;; But, really, that's just integer?
                                  ;; It would probably be more tempting to
                                  ;; just spec this like that if clojure had
                                  ;; a better numeric tower
                                  ::nonce {::type ::bytes
                                           ::length client-nonce-suffix-length}
                                  ::crypto-box {::type ::bytes
                                                ::length hello-crypto-box-length}))

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

(def cookie
  (array-map ::s' {::type ::bytes ::length key-length}
             ::black-box {::type ::zeroes ::length server-cookie-length}))

;;; Vouch/Initiate Packets

(def vouch-nonce-prefix (.getBytes "CurveCPV"))
(def vouch-length (+ server-nonce-suffix-length
                     box-zero-bytes
                     key-length))
