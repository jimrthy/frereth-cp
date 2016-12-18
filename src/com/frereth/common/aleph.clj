(ns com.frereth.common.aleph
  "Wrappers for my aleph experiments"
  (:require [clojure.edn :as edn]
            [gloss.io :as io]
            [manifold.stream :as stream]))

(defn wrap-gloss-protocol
  "Use the gloss library as middleware to apply a protocol to a raw stream"
  [protocol s]
  (let [out (stream/stream)]
    (stream/connect
     (stream/map #(io/encode protocol %) out)
     s)
    (stream/splice out
              (io/decode-stream s protocol))))

(defn simplest
  "Encode a length and a string into a packet
Then translate the string into EDN.
This approach is rife for abuse. What happens
if one side lies about the string length? Or
sends garbage?"
  [stream]
  (let [protocol (gloss/compile-frame
                  (gloss/finite-stream :uint32
                                       (gloss/string :utf-8))
                  pr-str
                  edn/read-string)]
    (wrap-gloss-protocol protocol stream)))
