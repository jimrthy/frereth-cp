(ns frereth-cp.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.specs :as specs]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic Constants

;; Q: How many of the rest of this could benefit enough by
;; getting a ^:const metadata hint to justify it?
(def ^Integer client-nonce-prefix-length 16)
(def ^Integer client-nonce-suffix-length 8)
(def extension-length specs/extension-length)
(def header-length specs/header-length)

(def box-zero-bytes 16)
(def ^Integer decrypt-box-zero-bytes 32)
(def key-length specs/key-length)
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

;; The prefixes are all a series of constant bytes.
;; Callers shouldn't need to know/worry about them.
;; FIXME: Add a ::constant-bytes type that just
;; hard-codes the magic.
(s/def ::prefix ::specs/prefix)

;; This is a name suitable for submitting a DNS query.
;; 1. Its encoder starts with an array of zeros
;; 2. Each name segment is prefixed with the number of bytes
;; 3. No name segment is longer than 63 bytes
(s/def ::server-name (s/and bytes #(= (count %) server-name-length)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Hello packets

(def hello-header-string "QvnQ5XlH")
(def hello-header (.getBytes hello-header-string))
(s/def ::hello-prefix (s/and ::specs/prefix
                             #(= hello-header-string (String. %))))
(def ^Integer hello-crypto-box-length 80)
(def ^Integer ^:const zero-box-length (- hello-crypto-box-length box-zero-bytes))
;; FIXME: It would be really nice to be able to generate this from the spec
;; or vice-versa.
;; Specs, coercion, and serialization are currently a hot topic on the mailing list.
(def hello-packet-dscr (array-map ::hello-prefix {::type ::const ::contents hello-header}
                                  ::srvr-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-short-pk {::type ::bytes ::length key-length}
                                  ::zeros {::type ::zeroes ::length zero-box-length}
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
;; Here's a bit of nastiness:
;; I can define these in shared.specs. But I have to redefine
;; them here because of the namespacing.
;; Unless I want to update my dscr templates, which really is the correct
;; answer.
;; TODO: Make that so
;; (just do it one step at a time)
(s/def ::srvr-xtn ::specs/srvr-xtn)
#_(s/def ::clnt-xtn ::specs/clnt-xtn)
#_(s/def ::clnt-xtn ::specs/extension)
(s/def ::clnt-xtn (s/and bytes?
                         #(= (count %) extension-length)))
(s/def ::clnt-short-pk ::specs/public-short)
(s/def ::zeros (s/and bytes
                        #(= (count %) zero-box-length)
                        (fn [x]
                          (every? #(= 0 %) x))))
(s/def ::crypto-box (s/and bytes
                           #(= (count %) hello-crypto-box-length)))
(s/def ::hello-spec (s/keys :req [::hello-prefix
                                  ::srvr-xtn
                                  ::clnt-xtn
                                  ::clnt-short-pk
                                  ::zeros
                                  ::client-nonce-suffix
                                  ::crypto-box]))

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

(defn zero-bytes
  [n]
  (byte-array n (repeat 0)))

(def ^{:tag 'bytes} all-zeros
  "To avoid creating this over and over.

Q: Refactor this to a function?
(note that that makes life quite a bit more difficult for zero-out!)"
  (zero-bytes 128))

(defn zero-out!
  "Shove zeros into the byte-array at dst, from indexes start to end"
  [dst start end]
  (let [n (- end start)]
    (when (<= (count all-zeros) n)
      (alter-var-root all-zeros
                      (fn [_] (zero-bytes n)))))
  (b-t/byte-copy! dst start end all-zeros))
