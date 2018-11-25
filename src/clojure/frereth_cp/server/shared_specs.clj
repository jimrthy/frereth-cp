(ns frereth-cp.server.shared-specs
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.server.state :as state]
            [frereth-cp.shared :as shared]
            [frereth.weald.specs :as weald]))

(s/def ::clear-text bytes?)

(s/def ::cookie-components (s/keys :req [::clear-text
                                         ::weald/logger
                                         ::weald/state
                                         ::state/client-short<->server-long
                                         ::state/minute-key]))
