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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Properties

(def can-round-trip-initiate-packet
  (props/for-all [prefix (gen/return K/cookie-header)
                  srvr-xtn (fixed-length-byte-array-generator K/extension-length)
                  clnt-xtn (fixed-length-byte-array-generator K/extension-length)
                  clnt-short-pk (fixed-length-byte-array-generator K/client-key-length)
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
                            ::K/vouch-wrapper vouch-wrapper}
                       key-validation (map (fn [[spec o]]
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
                                           src)]
                   ;; Verify each individual field by realizing that lazy seq
                   (dorun key-validation)

                   ;; And then check all the parts
                   (is (s/valid? ::K/initiate-packet-spec src))
                   (let [serialized (serial/compose template src)]
                     (let [rhs (serial/decompose template serialized)]
                       (doseq [k (keys rhs)]
                         ;; This was a point of confusion for me, because the associated value
                         ;; coming out of data/diff is a vector.
                         ;; It's OK: decompose is producing byte arrays as expected.
                         (is ((complement vector?) (k rhs)) (str "Decomposed a vector under " k)))
                       (if (= src rhs)
                         (do
                           (println "Rainbows an unicorns")
                           true)  ; Round-tripped correctly. We're good.
                         ;; This is messy enough that it's worth taking some
                         ;; effort to see what really went wrong.
                         (let [delta (data/diff src rhs)
                               only-in-src (first delta)]
                           (println "You didn't expect it to be that easy, did you?")
                           ;; I'm getting nils in the vouch wrapper here.
                           ;; Q: How?
                           ;; A: data/diff is recursive. Elements that match
                           ;; in the byte arrays being compared show up as nil.
                           (is (not only-in-src) "Things only in source")

                           (is (not (second delta)) "Things only in deserialized")

                           ;; Things that are in both
                           (let [real-delta (nth delta 2)
                                 matched (= src real-delta)]
                             (or matched  ; Happy path
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
                                   (every? identity comparison))))))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests

(defspec initiate-round-trip 10  ;; The "run test this many times" parameter doesn't seem to work as advertised.
  can-round-trip-initiate-packet)

(comment
  (time (initiate-round-trip 10))

  (let [outcome
        (quick-check 1 can-round-trip-initiate-packet
                     #_[:reporter-fn (fn [m]
                                       (println "Outcome:" m))])]
    #_(:result :result-data :seed :failing-size :num-tests :fail :shrunk)
    (keys outcome)
    ;; The big thing here seems to be that :result is false
    (select-keys outcome [:result :failing-size]))

  ;; test.check is claiming that this all zeros sample is a failure. But it isn't giving me any hints about
  ;; the actual problem.
  (let [prefix K/cookie-header
        srvr-xtn (byte-array K/extension-length)
        clnt-xtn (byte-array K/extension-length)
        clnt-short-pk (byte-array K/client-key-length)
        cookie (byte-array K/server-cookie-length)
        outer-i-nonce (byte-array K/client-nonce-suffix-length)
        ;; 384 bytes
        vouch-wrapper (byte-array  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        vouch-wrapper-length (count vouch-wrapper)
        template (assoc-in K/initiate-packet-dscr
                           [::K/vouch-wrapper ::K/length]
                           vouch-wrapper-length)
        src {::K/prefix prefix
             ::K/srvr-xtn srvr-xtn
             ::K/clnt-xtn clnt-xtn
             ::K/clnt-short-pk clnt-short-pk
             ::K/cookie cookie
             ::K/outer-i-nonce outer-i-nonce
             ::K/vouch-wrapper vouch-wrapper}
        src' (reduce-kv (fn [acc k v]
                          (assoc acc k (vec v)))
                        {}
                        src)
        serialized (serial/compose template src)
        deserialized (serial/decompose template serialized)
        dsrlzd (reduce-kv (fn [acc k v]
                            (assoc acc k (vec v)))
                          {}
                          deserialized)]
    (when (not= src' dsrlzd)
      (let [changes (reduce (fn [acc k]
                              (let [expected (k src')
                                    actual (k dsrlzd)]
                                (if (= expected actual)
                                  acc
                                  (assoc-in (assoc-in acc [::expected k] expected)
                                            [::actual k] actual))))
                            {}
                            (keys src))]
        (throw (ex-info "Round trip failure" changes)))))

  (let [lhs {:a [1 2 3 4]
             :b [5 6 7 8]}
        rhs {:a [1 2 4 5]
             :b [5 6 9 8]}]
    (data/diff lhs rhs))
  (let [gend
        (gen/sample
         (gen/fmap byte-array
                   (gen/fmap (fn [x]
                               (let [n (count x)
                                     extra (mod n 16)]
                                 (if (= 0 extra)
                                   x
                                   (if (> n 16)
                                     (drop extra x)
                                     (take 16 (cycle x))))))
                             (gen/vector (gen/such-that (complement nil?) (gen/choose -128 127))
                                         (+ K/minimum-vouch-length
                                            K/min-vouch-message-length)
                                         (+ K/max-vouch-message-length
                                            K/minimum-vouch-length))))
         50)]
    (doseq [bs gend]
      (println ".")
      (doseq [b bs]
        (when (nil? b)
          (throw (ex-info "nil snuck in" bs))))))

  (let [gend (gen/sample (gen/vector (gen/bytes) 16 640))]
    (map count gend))

  (let [gend (gen/sample (gen/fmap (fn [xs]
                                     (println (vec xs))
                                     (byte-array xs))
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
                                                         (+ K/max-vouch-message-length
                                                            K/minimum-vouch-length)))) 20)]
    #_(map vec gend)
    (map count gend))

  (map count (gen/sample (gen/bytes 16 640)))
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
