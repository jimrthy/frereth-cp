(ns frereth-cp.server.shared-specs
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]))

(s/def ::clear-text bytes?)

(s/def ::cookie-components (s/keys :req [::state/client-short<->server-long
                                         ::state/minute-key
                                         ::clear-text
                                         ::shared/working-nonce]))
