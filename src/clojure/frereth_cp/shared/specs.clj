(ns frereth-cp.shared.specs
  "For specs that make sense to share among all the pieces"
  (:require [clojure.spec.alpha :as s]
            [clojure.test.check.generators :as lo-gen]
            [frereth-cp.util :as utils]
            [manifold.deferred :as dfrd])
  (:import [io.aleph.dirigiste Executor]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Magic Constants - don't belong in here
;;;; Warning: Use the versions in shared.constants instead

(def box-zero-bytes 16)

(def ^Integer key-length 32)
(def client-key-length key-length)

;; Really belongs in shared.constants, but we also need it in here.
;; And I want to avoid circular dependencies.
;; TODO: Move the serialization templates out of there so this isn't
;; an issue.
(def ^Integer server-nonce-prefix-length 8)
(def ^Integer server-nonce-suffix-length 16)

;; 48 bytes
;; Q: What is this for?
;; A: It's that ::inner-vouch portion of the vouch-wrapper.
;; Really, neither of those is a great name choice.
(def vouch-length (+ box-zero-bytes ;; 16
                     ;; 32
                     client-key-length))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

(defn class-predicate
  "Returns a predicate to check whether an object is an instance of the supplied class.
This really seems like a bad road to go down."
  [klass]
  #(instance? klass %))

(s/def ::atom (class-predicate (class (atom nil))))
(s/def ::byte-buf (class-predicate io.netty.buffer.ByteBuf))
(s/def ::deferrable dfrd/deferrable?)
(s/def ::exception-instance (class-predicate Exception))
(s/def ::executor (class-predicate Executor))
(s/def ::throwable (class-predicate Throwable))

;; I really don't want to reference generators in here.
;; Much less something like rose-tree.
;; Those sorts of details really belong in a test ns.
;; But it seems to smell to split them up.
(s/def ::crypto-key (s/and bytes?
                           #(= (count %) key-length)))

;; public long-term key
(s/def ::public-long ::crypto-key)
;; public short-term key
(s/def ::public-short ::crypto-key)

;; secret long-term key
(s/def ::secret-long ::crypto-key)
;; secret short-term key
(s/def ::secret-short ::crypto-key)

(s/def ::my-long-keys (s/keys :req [::public-long
                                    ::secret-long]))
(s/def ::my-short-keys (s/keys :req [::public-short
                                     ::secret-short]))

;; Keys of the peer with which we're communicating
(s/def ::peer-keys (s/keys :req [::public-long
                                 ;; Q: Is there any reason to retain this?
                                 ::public-short]))

(def header-length 8)
(defn random-header
  []
  (byte-array (take header-length
                    (repeatedly #(- (rand-int 256) 128)))))
(comment (random-header))

(s/def ::prefix
  (s/and bytes?
         #(= (count %) header-length)))

(def extension-length 16)
(s/def ::extension (s/and bytes?
                          #(= (count %) extension-length)))
(s/def ::srvr-xtn ::extension)
(s/def ::clnt-xtn ::extension)

(s/def ::srvr-ip (class-predicate java.net.SocketAddress))
(def server-name-length 256)
;; This is a name suitable for submitting a DNS query.
;; 1. Its encoder starts with an array of zeros
;; 2. Each name segment is prefixed with the number of bytes
;; 3. No name segment is longer than 63 bytes
(s/def ::srvr-name (s/and bytes #(= (count %) server-name-length)))
(s/def ::port (s/and int?
                     pos?
                     #(< % 65536)))
(s/def ::srvr-port ::port)

;; FIXME: Use this more generally
;; There is some confusion in places where I'm
;; specifying :timeout as nat-int?
;; Q: How many of those need to be that instead of this?
(s/def ::timeout (s/and number?
                        (complement neg?)))

;; Specify it this way because I waffle between
;; a byte-array vs. ByteBuf.
(s/def ::msg-bytes bytes?)

(s/def ::server-nonce-suffix (s/and bytes?
                                    #(= (count %) server-nonce-suffix-length)))
(s/def ::inner-i-nonce ::server-nonce-suffix)
;; The server and client nonces wind up being the same length.
;; The difference is really in the prefix/suffix distribution.
;; Still, this is annoying.
(s/def ::nonce (s/and bytes?
                      #(= (count %) (+ server-nonce-prefix-length
                                       server-nonce-suffix-length))))

(s/def ::crypto-box bytes?)
;; Note that this is really the inner-most crypto-box for the Initiate
;; packet.
;; According to the spec:
;; "a cryptographic box encrypted and authenticated to the server's long-term
;; public key S from the client's long-term public key C using this 24-byte
;; nonce. The 32-byte plaintext inside the box has the following contents:
;; * 32 bytes: the client's short-term public key C'."
;; Note that this is pretty much useless without the corresponding compressed
;; nonce.
;; Which is going into the state map under the ::inner-i-nonce
;; key.
(s/def ::vouch (s/and ::crypto-box
                      #(= (count %) vouch-length)))
