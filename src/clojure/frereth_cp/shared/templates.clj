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
;;; Cookie packets

;; line 315 - tie into the 0 padding that's part of the buffer getting created here
;; Note that we don't want/need it: box-after in crypto handles that
(def black-box-dscr (array-map ::clnt-short-pk {::K/type ::K/bytes ::K/length K/client-key-length}
                               ::srvr-short-sk {::K/type ::K/bytes ::K/length K/server-key-length}))
(s/def ::inner-cookie (partial specs/counted-bytes K/server-cookie-length))
(def cookie
  (array-map ::s' {::K/type ::K/bytes ::K/length K/server-key-length}
             ::inner-cookie {::K/type ::K/bytes ::K/length K/server-cookie-length}))

(s/def ::s' ::specs/public-short)
(s/def ::cookie-spec (s/keys :req [::s' ::inner-cookie]))

(s/def ::encrypted-cookie (partial specs/counted-bytes K/cookie-frame-length))

(def cookie-frame
  "The boiler plate around a cookie"
  ;; Header is only a "string" in the ASCII sense
  (array-map ::header {::K/type ::K/bytes
                       ::K/length K/header-length}
             ::client-extension {::K/type ::K/bytes
                                 ::K/length K/extension-length}
             ::server-extension {::K/type ::K/bytes
                                 ::K/length K/extension-length}
             ;; Implicitly prefixed with "CurveCPK"
             ::client-nonce-suffix {::K/type ::K/bytes
                                    ::K/length specs/server-nonce-suffix-length}
             ::cookie {::K/type ::K/bytes
                       ::K/length K/cookie-frame-length}))
(s/def ::cookie-frame (s/keys :req [::header
                                    ::client-extension
                                    ::server-extension
                                    ::client-nonce-suffix
                                    ::cookie]))
