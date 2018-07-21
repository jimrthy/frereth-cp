(ns frereth-cp.server.shared-specs
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.logging :as log]))

(s/def ::clear-text bytes?)

(s/def ::cookie-components (s/keys :req [::clear-text
                                         ::log/logger
                                         ::log/state
                                         ::shared/working-nonce
                                         ::state/client-short<->server-long
                                         ::state/minute-key]))
