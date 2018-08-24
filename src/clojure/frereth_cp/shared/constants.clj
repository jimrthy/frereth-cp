(ns frereth-cp.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.shared.specs :as specs])
  (:import io.netty.buffer.ByteBuf))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants

;; Q: How many of the rest of this could benefit enough by
;; getting a ^:const metadata hint to justify adding it?
;; TODO: benchmarking
(def box-zero-bytes specs/box-zero-bytes)
(def ^Integer decrypt-box-zero-bytes 32)
(def ^Integer key-length specs/key-length)
(def max-random-nonce (long (Math/pow 2 48)))

(def client-key-length specs/client-key-length)
;; Might as well move these into specs for consistency
;; with server-nonce-suffix-length
;; FIXME: Make it so (soon)
(def extension-length specs/extension-length)
(def header-length specs/header-length)

(def message-len 1104)
;; FIXME: Move this into specs, where it's defined
;; based on prefix/suffix lengths
;; Then again, all the constants in there should
;; really move back into here. And then that
;; should require this, instead of vice-versa.
(def nonce-length 24)
(def server-key-length key-length)
(def shared-key-length key-length)

(def client-header-prefix-string "QvnQ5Xl")
;; Using an ordinary ^bytes type-hint here caused an
;; IllegalArgumentException at compile-time elsewhere
;; with the message "Unable to resolve classname: clojure.core$bytes@4efdc044"
(def ^{:tag 'bytes} client-header-prefix (.getBytes client-header-prefix-string))

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
(def ^:const two-pow-48 (bit-shift-left 1 48))

(def ^:const m-1
  "1 Meg"
  1048576)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;; Q: Why are these here instead of top-level shared?
;;; A: Because they're used in here, and I want to avoid
;;; circular dependencies.
;;; Q: Would it make sense to have a dedicated shared.specs ns
;;; that everything could use?
;;; The way these things are split up now is a bit of a mess.

(s/def ::client-nonce-suffix (s/and bytes?
                                    #(= (count %) specs/client-nonce-suffix-length)))

;; The prefixes are all a series of constant bytes.
;; Callers shouldn't need to know/worry about them.
;; FIXME: Add a ::constant-bytes type that just
;; hard-codes the magic.
(s/def ::prefix ::specs/prefix)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Hello packets

(def hello-packet-length 224)
(def hello-header-string (str client-header-prefix-string "H"))
(comment (vec hello-header-string))
(def hello-header (.getBytes hello-header-string))
(s/def ::hello-prefix (s/and ::specs/prefix
                             #(= hello-header-string (String. %))))
(def hello-nonce-prefix (.getBytes "CurveCP-client-H"))
(def ^Integer hello-crypto-box-length 80)
(def ^Integer ^:const zero-box-length (- hello-crypto-box-length box-zero-bytes))
;; FIXME: It would be really nice to be able to generate this from the spec
;; or vice-versa.
;; Specs, coercion, and serialization are currently a hot topic on the mailing list.
(def hello-packet-dscr (array-map ::hello-prefix {::type ::const ::contents hello-header}
                                  ::srvr-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-xtn {::type ::bytes ::length extension-length}
                                  ::clnt-short-pk {::type ::bytes ::length client-key-length}
                                  ::zeros {::type ::zeroes ::length zero-box-length}
                                  ;; This gets weird/confusing.
                                  ;; It's a 64-bit number, so 8 octets
                                  ;; But, really, that's just integer?
                                  ;; It would probably be more tempting to
                                  ;; just spec this like that if the jvm had
                                  ;; unsigned ints
                                  ::client-nonce-suffix {::type ::bytes
                                                         ::length specs/client-nonce-suffix-length}
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
(def unboxed-crypto-cookie-length 128)

(s/def ::srvr-nonce-suffix ::specs/server-nonce-suffix)
(s/def ::cookie-packet (partial specs/counted-bytes cookie-packet-length))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Vouch/Initiate Packets

;; Header, cookie, server name, extensions, keys, nonces
(def vouch-overhead 544)
(def max-vouch-message-length 640)
(def max-initiate-packet-size (+ vouch-overhead max-vouch-message-length))
;; Q: Can this ever be < 16?
;; A: Well, in the reference implementation, trying to write
;; too few (< 16) or too many (> 640 in the Initiatet/Vouch phase)
;; bytes causes the process to exit.
;; And, because of the way those bytes are buffered, it really
;; has to always write a multiple of 16 (Q: What about once
;; EOF hits?)
;; Actually, this part *is* a message.
;; And, according to the spec, that has to be at least 16
;; bytes.
(def min-vouch-message-length 16)

(s/def ::hidden-client-short-pk ::specs/public-short)
(s/def ::inner-i-nonce ::specs/inner-i-nonce)
(s/def ::long-term-public-key ::specs/public-long)
;; FIXME: Actually, this should be a full-blown
;; :frereth-cp.message.specs/packet, with a better
;; name.
;; FIXME: Switch to that name.
(s/def ::message (s/and bytes?
                        ;; This predicate is nonsense.
                        ;; Q: What's wrong with it?
                        ;; A: comparing count against nothing, in last clause
                        ;; FIXME: Switch to something sensible (soon)
                        #(<= max-vouch-message-length (count %))
                        #(<= (count %))))
(s/def ::outer-i-nonce ::client-nonce-suffix)
(s/def ::srvr-name ::specs/srvr-name)

(def vouch-nonce-prefix (.getBytes "CurveCPV"))
(def initiate-nonce-prefix (.getBytes "CurveCP-client-I"))
(def initiate-header (.getBytes (str client-header-prefix-string "I")))

(def vouch-length specs/vouch-length)

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
                             client-key-length ; 32
                             specs/server-nonce-suffix-length ; 16
                             vouch-length ; 48
                             ;; 256
                             specs/server-name-length))

(s/fdef legal-vouch-message-length?
        :args (s/cat :bytes bytes?)
        :ret boolean?)
(defn legal-vouch-message-length?
  "Is a byte array a legal vouch sub-message?"
  ;; The maximum length for the message associated with an Initiate packet is 640 bytes.
  ;; However, it must be evenly divisible by 16.
  ;; This feels a little...odd.
  ;; It leaves the message child tightly coupled with this implementation
  ;; detail.
  ;; And also tied in with the detail that the rules change after
  ;; the server sends back a response.
  ;; I'm not sure there's any way to avoid that.
  [^bytes bs]
  (let [n (count bs)]
    (and (< n max-vouch-message-length)
         (= 0 (rem n 16)))))

;;; FIXME: Move the rest of these into templates

(def vouch-wrapper
  "Template for composing the inner part of an Initiate Packet's Vouch that holds everything interesting"
  {::client-long-term-key {::type ::bytes
                           ::length client-key-length}
   ::inner-i-nonce {::type ::bytes ::length specs/server-nonce-suffix-length}
   ::inner-vouch {::type ::bytes ::length vouch-length}
   ::srvr-name {::type ::bytes ::length specs/server-name-length}
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
                              ::length client-key-length}
             ::cookie {::type ::bytes
                       ::length server-cookie-length}
             ::outer-i-nonce {::type ::bytes
                              ::length specs/client-nonce-suffix-length}
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
                              ;; FIXME: The max size is wrong.
                              #(<= minimum-vouch-length
                                   (count %)
                                   (+ minimum-vouch-length max-vouch-message-length))
                              ;; Evenly divisible by 16
                              #(= 0 (mod (count %) 16))))

(s/def ::initiate-packet-spec (s/keys :req [::prefix
                                            ::srvr-xtn
                                            ::clnt-xtn
                                            ::clnt-short-pk
                                            ::cookie
                                            ::outer-i-nonce
                                            ::vouch-wrapper]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utility helpers

(defn zero-bytes
  [n]
  (byte-array n (repeat 0)))

(def ^{:tag 'bytes} all-zeros
  "To avoid creating this over and over.

Q: Refactor this to a function?
(note that that makes life quite a bit more difficult for zero-out!)"
  (zero-bytes 128))
