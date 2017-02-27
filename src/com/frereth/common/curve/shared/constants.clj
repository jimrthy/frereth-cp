(ns com.frereth.common.curve.shared.constants
  "Magical names, numbers, and data structures"
  (:require [clojure.spec :as s]))

(def extension-length 16)

(def box-zero-bytes 16)
(def decrypt-box-zero-bytes 32)
(def key-length 32)
(def max-random-nonce (long (Math/pow 2 48)))
(def nonce-length 24)
(def shared-key-length key-length)

;;; Hello packets
(def hello-crypto-box-length 80)

;;; Cookie packets
(def server-cookie-length 96)
