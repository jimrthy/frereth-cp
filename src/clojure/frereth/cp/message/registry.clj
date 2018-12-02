(ns frereth-cp.message.registry
  "Track active message loops"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.specs :as msg-specs]
            [frereth-cp.shared.specs :as shared-specs]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;;; It's really tempting to make this an atom that holds the map.
;;; But that complects concerns. Keep this ns nice and simple. Let
;;; its callers worry about actually managing the state.
(s/def ::registry (s/map-of ::msg-specs/message-loop-name ::msg-specs/io-handle))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Public

(s/fdef ctor
        :ret ::registry)
(defn ctor
  "Create a new registry"
  []
  {})

(s/fdef register
        :args (s/cat :registry ::registry
                     :io-handle ::msg-specs/io-handle)
        :ret ::registry)
(defn register
  [registry
   {:keys [::msg-specs/message-loop-name]
    :as io-handle}]
  (when (contains? registry message-loop-name)
    (throw (ex-info "Trying to re-register a named message loop"
                    {::msg-specs/io-handle io-handle
                     ::msg-specs/message-loop-name message-loop-name
                     ::registry registry})))
  (assoc registry message-loop-name io-handle))

(s/fdef de-register
        :args (s/cat :registry ::registry
                     :message-loop-name ::msg-specs/message-loop-name)
        :ret ::registry)
(defn de-register
  [registry
   message-loop-name]
  (when-not (contains? registry message-loop-name)
    (throw (ex-info "Trying to de-register an unregistered message loop"
                    {::msg-specs/message-loop-name message-loop-name
                     ::registry registry})))
  (dissoc registry message-loop-name))

(s/fdef look-up
        :args (s/cat :registry ::registry
                     :message-loop-name ::msg-specs/message-loop-name)
        :ret (s/nilable ::msg-specs/io-loop))
(defn look-up
  [registry
   message-loop-name]
  (get registry message-loop-name))
