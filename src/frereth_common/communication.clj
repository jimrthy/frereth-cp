(ns frereth-common.communication
  (:require [schema.core :as s]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

;; Something at least vaguely similar to a REST
;; endpoint. Or maybe just something that would
;; typically go over a fairly standard message
;; queue
(def request {:version {:major s/Int
                        :minor s/Int
                        :detail s/Int}
              :protocol s/Str
              ;; For dispatching messages that arrive on the same socket
              ;; but are really directed toward different end-points
              (s/optional-key :channel) s/Str
              :headers {(s/either s/Str s/Keyword) s/Any}
              :locator s/Str  ; think URL
              (s/optional-key :parameters) {:s/Keyword s/Any}  ; think GET
              ;; It's very tempting for the body to be just another dict like
              ;; :parameters. But it seems like we need to have some justification
              ;; for including them both.
              ;; And sticking GET params in the URL has always seemed pretty suspect
              (s/optional-key :body) s/Str})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

