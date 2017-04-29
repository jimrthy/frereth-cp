(ns com.frereth.common.curve.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

(def client-nonce-prefix-length 16)
(def client-nonce-suffix-length 8)
(def extension-length 16)
(def header-length 8)

(def box-zero-bytes 16)
(def decrypt-box-zero-bytes 32)
(def key-length 32)
(def max-random-nonce (long (Math/pow 2 48)))
(def nonce-length 24)
(def server-nonce-prefix-length 8)
(def server-nonce-suffix-length 16)
(def server-name-length 256)
(def shared-key-length key-length)

(def client-header-prefix "QvnQ5Xl")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;; This is a name suitable for submitting a DNS query.
;; 1. Its encoder starts with an array of zeros
;; 2. Each name segment is prefixed with the number of bytes
;; 3. No name segment is longer than 63 bytes
(s/def ::server-name (s/and bytes #(= (count %) server-name-length)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cookie packets

(def cookie-header (.getBytes "RL3aNMXK"))
(def cookie-nonce-prefix (.getBytes "CurveCPK"))
(def cookie-nonce-minute-prefix (.getBytes "minute-k"))
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

(def black-box-dscr (array-map ::padding {::type ::zeroes ::length decrypt-box-zero-bytes}
                               ::clnt-short-pk {::type ::bytes ::length key-length}
                               ::srvr-short-sk {::type ::bytes ::length key-length}))
(def cookie
  (array-map ::s' {::type ::bytes ::length key-length}
             ::black-box {::type ::bytes ::length server-cookie-length}))
;; TODO: Need matching specs for these keys.
(s/def ::cookie-spec (s/keys :req [::s' ::black-box]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Vouch/Initiate Packets

(def vouch-nonce-prefix (.getBytes "CurveCPV"))
(def initiate-nonce-prefix (.getBytes "CurveCP-client-I"))
(def initiate-header (.getBytes (str client-header-prefix "I")))

(def max-vouch-message-length 640)

;; 64 bytes
;; Q: What is this for?
;; A: It's that ::inner-vouch portion of the vouch-wrapper.
;; Really, neither of those is a great name choice.
(def vouch-length (+ server-nonce-suffix-length  ; 16
                     ;; 16
                     box-zero-bytes
                     ;; 32
                     key-length))
;; The way this is wrapped up seems odd.
;; We have a box containing the short-term key encrypted
;; by the long-term public key.
;; The long-term key is part of this outer box, which
;; is encrypted with that short-term key.
;; Which, in turn, is included in the message's plain
;; text.
;; This does let us verify that the client has access
;; to the long-term secret key it's claiming without
;; needing to maintain any state on our part up to this
;; point.
(def minimum-vouch-length (+ box-zero-bytes  ; 16
                             ;; 32
                             key-length
                             ;; 64
                             vouch-length
                             ;; 256
                             server-name-length))
(defn initiate-message-length-filter
  "The maximum length for the message associated with an Initiate packet is 640 bytes.

  However, it must be evenly divisible by 16."
  [n]
  (min (* (quot n 16) 16)
       max-vouch-message-length))

(def vouch-wrapper
  "Template for composing the informational part of an Initiate Packet's Vouch"
  {::client-long-term-key {::type ::bytes
                           ::length key-length}
   ::inner-vouch {::type ::bytes ::length vouch-length}
   ::server-name {::type ::bytes ::length server-name-length}
   ;; Q: Do I want to allow compose to accept parameters for things like this?
   ::child-message {::type ::bytes ::length '?child-message-length}})

(def initiate-packet-dscr
  (array-map ::prefix {::type ::bytes
                       ::length header-length}
             ;; Note that this is really receiver-extension
             ::srvr-xtn {::type ::bytes
                         ::length extension-length}
             ;; And this is sender-extension
             ;; TODO: Get the names refactored
             ;; So I can use this for everything
             ::clnt-xtn {::type ::bytes
                         ::length extension-length}
             ::clnt-short-pk {::type ::bytes
                              ::length key-length}
             ::cookie {::type ::bytes
                       ::length server-cookie-length}
             ::nonce {::type ::bytes
                      ::length client-nonce-suffix-length}
             ;; It seems like it would be nice to enable nested
             ;; definitions.
             ;; This isn't "just" vouch-wrapper.
             ;; It's the cryptographic box that contains vouch-wrapper.
             ::vouch {::type ::bytes
                      ::length minimum-vouch-length}))

(s/def ::cookie (s/and bytes?
                       #(= (count %) server-cookie-length)))
;; TODO: This name doesn't work due to collisions.
;; Really need to make it more fine-grained to indicate whether
;; it comes from the client or server.
(s/def ::nonce (s/and bytes?
                      #(= (count %) client-nonce-suffix-length)))
(s/def ::vouch (s/and bytes?
                      #(< minimum-vouch-length (count %))
                      ;; Evenly divisible by 16
                      #(= 0 (bit-and (count %) 0xf))
                      #(>= 640 (count %))))

(s/def ::initiate-packet-spec (s/keys :req [::prefix
                                            ::srvr-txn
                                            ::clnt-xtn
                                            ::clnt-short-pk
                                            ::cookie
                                            ::nonce
                                            ::vouch]))
