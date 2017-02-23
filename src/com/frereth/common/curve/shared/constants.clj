(ns com.frereth.common.curve.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec :as s]))

(def box-zero-bytes 16)
(def decrypt-box-zero-bytes 32)
(def key-length 32)
(def max-random-nonce (long (Math/pow 2 48)))
(def shared-key-length key-length)
