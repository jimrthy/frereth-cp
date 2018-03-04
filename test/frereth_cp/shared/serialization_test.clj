(ns frereth-cp.serializationy-test
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer (are deftest is testing)]
            [clojure.test.check.generators :as lo-gen]
            [clojure.test.check.rose-tree :as rose]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.serialization :as serial]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as utils]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helpers

(defn fixed-length-byte-array-generator
  [n]
  (gen/fmap byte-array (gen/vector (gen/choose -128 127) n)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(deftest serialization-round-trip
  ;; initiate-packet-spec probably isn't a good choice for starting,
  ;; since it has the variable-length message field
  (let [vouch-descriptions (gen/sample (s/gen #_::K/initiate-packet-spec
                                              (s/keys :req [#_::K/prefix
                                                            ::K/srvr-xtn
                                                            ::K/clnt-xtn
                                                            #_::K/clnt-short-pk
                                                            #_::K/cookie
                                                            #_::K/outer-i-nonce
                                                            #_::K/vouch-wrapper])
                                              {::specs/extension (partial fixed-length-byte-array-generator K/extension-length)
                                               #_::K/clnt-xtn (partial fixed-length-byte-array-generator K/extension-length)
                                               #_::K/srvr-xtn (partial fixed-length-byte-array-generator K/extension-length)
                                               ::specs/crypto-key #(lo-gen/->Generator (fn [_ _]
                                                                                         (rose/make-rose (utils/random-secure-bytes K/key-length) [])))
                                               ::K/cookie (partial fixed-length-byte-array-generator K/server-cookie-length)
                                               ::K/vouch-wrapper (fn []
                                                                   (gen/fmap byte-array
                                                                             (gen/such-that #(<= K/min-vouch-message-length
                                                                                                 (count %)
                                                                                                 K/max-vouch-message-length)
                                                                                            (gen/such-that #(= 0 (mod (count %) 16))
                                                                                                           (gen/vector (gen/choose -128 127))))))}))
        encoded (map (fn [fields]
                       (serial/compose K/initiate-packet-dscr fields))
                     vouch-descriptions)]
    #_(dorun (map #(= %1
                    (serial/decompose ::K/initiate-packet-dscr %2))
                  encoded))
    (doseq [x vouch-descriptions]
      (is x))))

(comment
  (gen/sample (s/gen #_::K/initiate-packet-spec
                     (s/keys :req [::K/prefix
                                   ;;
                                   #_::K/srvr-xtn
                                   ;; Note that using this key works fine
                                   ::specs/extension])
                     ;; This is the work-around that I thought I'd found.
                     ;; However, it isn't really working for ::srvr-xtn
                     ;; Although declaring the function inline works better than using
                     ;; fixed-length-byte-array-generator
                     {::specs/extension #(fixed-length-byte-array-generator K/extension-length)
                      #_(gen/fmap byte-array (gen/vector (gen/choose -128 127) K/extension-length))}))
  (gen/sample (s/gen ::K/clnt-short-pk))
  )

(deftest hello-round-trip
  ;; FIXME: The code for generating a specific byte array needs to
  ;; be moved somewhere generally useful
  (let [hellos (gen/sample (s/gen
                            ::K/hello-spec
                            {::K/hello-prefix #(gen/return K/hello-header)
                             ::specs/extension (partial fixed-length-byte-array-generator K/extension-length)
                             ;; It seems like the next line is the way this
                             ;; should be handled, but the previous one seems
                             ;; to work more often.
                             ;; Sadly, neither approach seems to actually work with any consistency.
                             #_[::K/clnt-xtn #(gen/vector lo-gen/byte K/extension-length)]
                             ::K/clnt-short-pk #(lo-gen/->Generator (fn [_ _]
                                                                      (rose/make-rose (utils/random-secure-bytes K/key-length) [])))
                             ::K/zeros #(gen/return (byte-array (take K/zero-box-length (repeat 0))))
                             ::K/client-nonce-suffix (partial fixed-length-byte-array-generator K/client-nonce-suffix-length)
                             ::K/crypto-box (partial fixed-length-byte-array-generator K/hello-crypto-box-length)}))
        buffers (map (partial serial/compose K/hello-packet-dscr) hellos)
        ;; FIXME: Make this go back away
        serialized (map (fn [buffer]
                          (let [dst (byte-array (.readableBytes buffer))]
                            (.readBytes buffer dst)
                            dst))
                        buffers)]
    ;; each hello is a map of field names to byte arrays
    ;; decompose returns a similar map, but the values are ByteBuf instances.
    ;; Which seems wrong.
    ;; However, even if it round-tripped seamlessly (and, realistically, it needs to),
    ;; I couldn't get a decent comparison using plain =
    (let [a (first hellos)
          ;; Sometimes I get an error about trying to read past the end
          ;; of the buffer.
          ;; FIXME: Why?
          b (serial/decompose K/hello-packet-dscr (first buffers))]
      (println "First raw: " a
               "\nFirst decomposed: " b))
    (dorun (map #(is (= %1 (serial/decompose K/hello-packet-dscr %2)))
                hellos
                ;; decompose does expect a ByteBuf
                #_serialized
                buffers))
    (comment
      (println (count (first serialized))))))
(comment
  (hello-round-trip)
  )
