(ns frereth-cp.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec.alpha :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

;; Q: How many of the rest of this could benefit enough by
;; getting a ^:const metadata hint to justify it?
(def ^Integer client-nonce-prefix-length 16)
(def ^Integer client-nonce-suffix-length 8)
(def extension-length 16)
(def header-length 8)

(def box-zero-bytes 16)
(def ^Integer decrypt-box-zero-bytes 32)
(def ^Integer key-length 32)
(def max-random-nonce (long (Math/pow 2 48)))
(def message-len 1104)
(def nonce-length 24)
(def ^Integer server-nonce-prefix-length 8)
(def ^Integer server-nonce-suffix-length 16)
(def server-name-length 256)
(def shared-key-length key-length)

;; Using an ordinary ^bytes type-hint here caused an
;; IllegalArgumentException at compile-time elsewhere
;; with the message "Unable to resolve classname: clojure.core$bytes@4efdc044"
(def ^{:tag 'bytes} client-header-prefix (.getBytes "QvnQ5Xl"))

(def send-child-message-timeout
  "in milliseconds"
  ;; Q: What's realistic?
  ;; (TODO: this should probably be dynamically customizable)
  2500)

(def ^:const max-8-int 128)
(def ^:const max-8-uint 255)
(def ^:const max-16-int 32768)
(def ^:const max-16-uint 65535)
;; (dec (pow 2 32))
(def ^:const max-32-uint 4294967295)
;; (comment (dec (long (Math/pow 2 31))))
(def ^:const max-32-int 2147483647)
(def ^:const max-64-uint 18446744073709551999N)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;; Q: Why are these here instead of top-level shared?
;;; A: Because they're used in here, and I want to avoid
;;; circular dependencies.
;;; Q: Would it make sense to have a dedicated shared.specs ns
;;; that everything could use?
;;; The way these things are split up now is a bit of a mess.

(s/def ::client-nonce-suffix (s/and bytes?
                                    #(= (count %) client-nonce-suffix-length)))
(s/def ::server-nonce-suffix (s/and bytes?
                                    #(= (count %) server-nonce-suffix-length)))

;; This is a name suitable for submitting a DNS query.
;; 1. Its encoder starts with an array of zeros
;; 2. Each name segment is prefixed with the number of bytes
;; 3. No name segment is longer than 63 bytes
(s/def ::server-name (s/and bytes #(= (count %) server-name-length)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Hello packets

(def ^Integer hello-crypto-box-length 80)
(def hello-packet-dscr (array-map ::prefix {::type ::bytes ::length header-length}
                                  ::srvr-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-short-pk {::type ::bytes ::length key-length}
                                  ::zeros {::type ::zeroes ::length (- hello-crypto-box-length box-zero-bytes)}
                                  ;; This gets weird/confusing.
                                  ;; It's a 64-bit number, so 8 octets
                                  ;; But, really, that's just integer?
                                  ;; It would probably be more tempting to
                                  ;; just spec this like that if the jvm had
                                  ;; unsigned ints
                                  ::client-nonce-suffix {::type ::bytes
                                                         ::length client-nonce-suffix-length}
                                  ::crypto-box {::type ::bytes
                                                ::length hello-crypto-box-length}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cookie packets

(def ^Integer ^:const cookie-frame-length 144)
(def cookie-header (.getBytes "RL3aNMXK"))
(def cookie-nonce-prefix (.getBytes "CurveCPK"))
(def cookie-nonce-minute-prefix (.getBytes "minute-k"))
(def ^Integer server-cookie-length 96)
(def ^Integer cookie-packet-length 200)

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
             ::client-nonce-suffix {::type ::bytes
                                    ::length server-nonce-suffix-length}
             ::cookie {::type ::bytes
                       ::length cookie-frame-length}))

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

(s/def ::inner-i-nonce ::server-nonce-suffix)
(s/def ::outer-i-nonce ::client-nonce-suffix)

(def vouch-nonce-prefix (.getBytes "CurveCPV"))
(def initiate-nonce-prefix (.getBytes "CurveCP-client-I"))
(def initiate-header (.getBytes (str client-header-prefix "I")))

(def max-vouch-message-length 640)

;; 48 bytes
;; Q: What is this for?
;; A: It's that ::inner-vouch portion of the vouch-wrapper.
;; Really, neither of those is a great name choice.
(def vouch-length (+ box-zero-bytes ;; 16
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
;; (spoiler: it's
;; (+ 16 32 16 48 256)
;; => 368
(def minimum-vouch-length (+ box-zero-bytes  ; 16
                             ;; 32
                             key-length
                             ;; 16
                             server-nonce-suffix-length
                             ;; 48
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
  "Template for composing the inner part of an Initiate Packet's Vouch that holds everything interesting"
  {::client-long-term-key {::type ::bytes
                           ::length key-length}
   ::inner-i-nonce {::type ::bytes ::length server-nonce-suffix-length}
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
             ::outer-i-nonce {::type ::bytes
                              ::length client-nonce-suffix-length}
             ;; It seems like it would be nice to enable nested
             ;; definitions.
             ;; This isn't "just" vouch-wrapper.
             ;; It's the cryptographic box that contains vouch-wrapper
             ;; and its related message
             ::vouch-wrapper {::type ::bytes
                              ::length minimum-vouch-length}))

(s/def ::cookie (s/and bytes?
                       #(= (count %) server-cookie-length)))

;; Note that this is really the wrapper for the vouch received from the client
(s/def ::vouch-wrapper (s/and bytes?
                              #(< minimum-vouch-length (count %))
                              ;; Evenly divisible by 16
                              #(= 0 (bit-and (count %) 0xf))
                              #(>= 640 (count %))))

(s/def ::initiate-packet-spec (s/keys :req [::prefix
                                            ::srvr-txn
                                            ::clnt-xtn
                                            ::clnt-short-pk
                                            ::cookie
                                            ::outer-i-nonce
                                            ::vouch-wrapper]))

(def initiate-client-vouch-wrapper
  "This is the actual body (368+M) of the Initiate packet

TODO: Rename this to something like initiate-client-vouch-message"
  (array-map ::long-term-public-key {::type ::bytes
                                     ::length key-length}
             ::inner-i-nonce {::type ::bytes
                            ::length server-nonce-suffix-length}
             ::hidden-client-short-pk {::type ::bytes
                                       ::length (+ key-length box-zero-bytes)}
             ::server-name {::type ::bytes
                            ::length server-name-length}
             ::message {::type ::bytes
                        ::length '*}))
(s/def ::initiate-client-vouch-wrapper
  (s/keys :req [::long-term-public-key
                ::inner-i-nonce
                ::hidden-client-short-pk
                ::server-name
                ::message]))
