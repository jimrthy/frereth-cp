(ns frereth-cp.shared.templates
  "Descriptions of binary files to marshall"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.shared
             [constants :as K]
             [specs :as specs]]))

;;; FIXME: Add a macro for defining both the template
;;; and the spec at the same time

;;; FIXME: Refactor all the template definitions from constants
;;; into here.

;;; FIXME: Refactor specs back into the specs ns. Or at least constants.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def extension {::K/type ::K/bytes
                ::K/length K/extension-length})

;; Header is only a "string" in the ASCII sense
(def header {::K/type ::K/const
             ::K/contents (.getBytes "override")})

(def message-box {::K/type ::K/bytes
                  ::K/length '*})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs
;;;; FIXME: Lots need to move into here

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cookie Packets

;; server line 315 - tie into the 0 padding that's part of the buffer
;; getting created here.
;; Note that we don't want/need it: box-after in crypto handles that
(def black-box-dscr (array-map ::clnt-short-pk {::K/type ::K/bytes
                                                ::K/length K/client-key-length}
                               ::srvr-short-sk {::K/type ::K/bytes
                                                ::K/length K/server-key-length}))
;; This is the clear text of the black-box cookie.
(s/def ::srvr-cookie (s/keys :req [::clnt-short-pk
                                   ::srvr-short-sk]))
(s/def ::inner-cookie (partial specs/counted-bytes K/server-cookie-length))
(def cookie
  (array-map ::s' {::K/type ::K/bytes ::K/length K/server-key-length}
             ::inner-cookie {::K/type ::K/bytes ::K/length K/server-cookie-length}))

(s/def ::s' ::specs/public-short)
(s/def ::cookie-spec (s/keys :req [::s' ::inner-cookie]))

(s/def ::encrypted-cookie (partial specs/counted-bytes K/cookie-frame-length))

(def cookie-frame
  "The boiler plate around a cookie"
  (array-map ::header (assoc header
                             ::K/content K/cookie-header)
             ::client-extension extension
             ::server-extension extension
             ;; Implicitly prefixed with "CurveCPK"
             ::client-nonce-suffix {::K/type ::K/bytes
                                    ::K/length specs/server-nonce-suffix-length}
             ::cookie {::K/type ::K/bytes
                       ::K/length K/cookie-frame-length}))
(s/def ::cookie-frame (s/keys :req [::header
                                    ::client-extension
                                    ::server-extension
                                    ;; It's tempting to think this is what's
                                    ;; getting assembled around line 321.
                                    ;; It isn't.
                                    ;; This is both part of the cookie black
                                    ;; box and part of the plaintext outer packet.
                                    ;; Which seems like it might offer an attack
                                    ;; vector, similar to something like the
                                    ;; BREACH attack.
                                    ;; security.stackexchange.com assures me
                                    ;; that that only applies to compressed
                                    ;; data in very special circumstances
                                    ;; which include mirroring client data.
                                    ;; So trust the experts on this one.
                                    ::client-nonce-suffix
                                    ::cookie]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Initiate Packets

(def initiate-client-vouch-wrapper
  "This is the actual body (368+M) of the Initiate packet"
  (array-map ::K/long-term-public-key {::K/type ::K/bytes
                                       ::K/length K/client-key-length}
             ::K/inner-i-nonce {::K/type ::K/bytes
                                ::K/length specs/server-nonce-suffix-length}
             ::K/hidden-client-short-pk {::K/type ::K/bytes
                                         ::K/length (+ K/client-key-length
                                                       K/box-zero-bytes)}
             ::K/srvr-name {::K/type ::K/bytes
                            ::K/length specs/server-name-length}
             ::K/message message-box))

(s/def ::initiate-client-vouch-wrapper
  (s/keys :req [::K/long-term-public-key
                ::K/inner-i-nonce
                ::K/hidden-client-short-pk
                ::K/srvr-name
                ::K/message]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Message Packets

;;; Server

(def server-message-nonce-prefix (.getBytes "CurveCP-server-M"))

(def server-message
  (array-map ::header (assoc header
                             ::K/contents (.getBytes "RL3aNMXM"))
             ::client-extension extension
             ::server-extension extension
             ::nonce specs/client-nonce-suffix-length
             ::message message-box))

(s/def ::server-message (s/keys :req [::header
                                      ::client-extension
                                      ::server-extension
                                      ::nonce
                                      ::message]))

;;; Client

(def client-message-nonce-prefix (.getBytes "CurveCP-client-M"))

(def client-message
  (array-map ::header (assoc header
                             ::K/contents (.getBytes "QvnQ5XlM"))
             ::server-extension extension
             ::client-extension extension
             ::client-short-pk {::K/type ::K/bytes
                                ::K/length K/client-key-length}
             ::nonce specs/server-nonce-suffix-length
             ::message message-box))

(s/def ::client-message (s/keys :req [::header
                                      ::server-extension
                                      ::client-extension
                                      ::client-short-pk
                                      ::nonce
                                      ::message]))
