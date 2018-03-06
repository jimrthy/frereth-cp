(ns frereth-cp.serialization-test
  (:require [clojure.data :as data]
            [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer (are deftest is testing)]
            [clojure.test.check :refer (quick-check)]
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as lo-gen]
            [clojure.test.check.properties :as props]
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

(defn check-round-trip
  [spec template src]
  ;; And then check all the parts
  (is (s/valid? spec src))
  (let [serialized (serial/compose template src)
        rhs (serial/decompose template serialized)]
    (doseq [k (keys rhs)]
      ;; This was a point of confusion for me, because the associated value
      ;; coming out of data/diff is a vector.
      ;; It's OK: decompose is producing byte arrays as expected.
      (is ((complement vector?) (k rhs)) (str "Decomposed a vector under " k)))
    (if (= src rhs)
      ;; Round-tripped correctly. We're good.
      ;; Sadly, this doesn't happen.
      true
      ;; This is messy enough that it's worth taking some
      ;; effort to see what really went wrong.
      (let [delta (data/diff src rhs)
            only-in-src (first delta)]
        ;; I'm getting nils in the vouch wrapper here.
        ;; Q: How?
        ;; A: data/diff is recursive. Elements that match
        ;; in the byte arrays being compared show up as nil.
        (is (not only-in-src) "Things only in source")

        (is (not (second delta)) "Things only in deserialized")

        ;; Things that are in both
        (let [real-delta (nth delta 2)
              matched (= src real-delta)]
          (or matched  ; Happy path. If this were true, the first (= src rhs) check would have passed
              (let [src-keys (set (keys src))
                    dst-keys (set (keys real-delta))]
                (is (= src-keys dst-keys))
                (let [comparison
                      (map (fn [k]
                             (let [expected (k src)
                                   actual (k real-delta)
                                   eql-len (= (count expected) (count actual))
                                   eql-contents (= (vec expected) (vec actual))]
                               (is eql-len
                                   (str "array lengths under " k))
                               (is eql-contents
                                   (str "values under " k))
                               (and eql-len eql-contents)))
                           src-keys)]
                  ;; Needs to return boolean-y
                  (every? identity comparison)))))))))

(defn validate-keys
  [src]
  (dorun (map (fn [[spec o]]
                (when-not (s/valid? spec o)
                  (println o "is not a valid" spec)
                  ;; This just failed. Want to get an explanation for that failure
                  (is (not (s/explain-data spec o))
                      (str "Expected: " spec
                           "\nActual:\n"
                           (if (bytes? o)
                             {::payload (vec o)
                              ::length (count o)}
                             o)))))
              src)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Generators

(def gen-key #_(fixed-length-byte-array-generator K/key-length)
  (lo-gen/->Generator (fn [_ _]
                        (rose/make-rose (utils/random-secure-bytes K/key-length) []))))

(def gen-xtn (fixed-length-byte-array-generator K/extension-length))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Properties

(def can-round-trip-initiate-packet
  (props/for-all [prefix (gen/return K/cookie-header)
                  srvr-xtn gen-xtn
                  clnt-xtn gen-xtn
                  clnt-short-pk gen-key
                  cookie (fixed-length-byte-array-generator K/server-cookie-length)
                  outer-i-nonce (fixed-length-byte-array-generator K/client-nonce-suffix-length)
                  vouch-wrapper (gen/fmap byte-array
                                          (gen/fmap (fn [x]
                                                      (assert (every? (complement nil?) x))
                                                      ;; Make sure length is an even multiple of 16
                                                      (let [n (count x)
                                                            extra (mod n 16)]
                                                        (println "Coping with" extra "extra bytes out of" n)
                                                        (if (= 0 extra)
                                                          x
                                                          (if (> n 16)
                                                            (drop extra x)
                                                            (take 16 (cycle x))))))
                                                    (gen/vector (gen/choose -128 127)
                                                                (+ K/minimum-vouch-length
                                                                   K/min-vouch-message-length)
                                                                (+ K/minimum-vouch-length
                                                                   K/max-vouch-message-length))))]
                 (is (not-any? nil? vouch-wrapper))

                 (let [vouch-wrapper-length (count vouch-wrapper)
                       template (assoc-in K/initiate-packet-dscr
                                          [::K/vouch-wrapper ::K/length]
                                          vouch-wrapper-length)
                       src {::K/prefix prefix
                            ::K/srvr-xtn srvr-xtn
                            ::K/clnt-xtn clnt-xtn
                            ::K/clnt-short-pk clnt-short-pk
                            ::K/cookie cookie
                            ::K/outer-i-nonce outer-i-nonce
                            ::K/vouch-wrapper vouch-wrapper}]
                   (validate-keys src)
                   (check-round-trip ::K/initiate-packet-spec template src ))))

(def can-round-trip-hello-packet
  (props/for-all
   [hello-prefix (gen/return K/hello-header)
    srvr-xtn gen-xtn
    clnt-xtn gen-xtn
    clnt-short-pk gen-key
    zeros (gen/return (byte-array (take K/zero-box-length (repeat 0))))
    client-nonce-suffix (fixed-length-byte-array-generator K/client-nonce-suffix-length)
    crypto-box (fixed-length-byte-array-generator K/hello-crypto-box-length)]
   (let [hello {::K/hello-prefix hello-prefix
                ::K/srvr-xtn srvr-xtn
                ::K/clnt-xtn clnt-xtn
                ::K/clnt-short-pk clnt-short-pk
                ::K/zeros zeros
                ::K/client-nonce-suffix client-nonce-suffix
                ::K/crypto-box crypto-box}]
     (validate-keys hello))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(defspec initiate-round-trip 10
  can-round-trip-initiate-packet)

(defspec hello-round-trip 10
  can-round-trip-initiate-packet)

(comment
  (hello-round-trip))

;; FIXME: Add tests for the rest
