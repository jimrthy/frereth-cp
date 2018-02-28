(ns frereth-cp.shared-test
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer (are deftest is testing)]
            [clojure.test.check.generators :as lo-gen]
            [clojure.test.check.rose-tree :as rose]
            [frereth-cp.shared :as shared]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.marshal :as marshal]
            [frereth-cp.shared.specs :as specs]
            [frereth-cp.util :as utils]))

(deftest serialization-round-trip
  ;; initiate-packet-spec probably isn't a good choice for starting,
  ;; since it has the variable-length message field
  (let [vouch-descriptions (gen/sample (s/gen ::K/initiate-packet-spec))
        encoded (map (fn [fields]
                       (marshal/compose ::K/initiate-packet-dscr fields)))]
    (dorun (map #(= %1
                    (marshal/decompose ::K/initiate-packet-dscr %2))
                vouch-descriptions
                encoded))))

(comment
  (s/exercise ::K/initiate-packet-spec)
  (gen/generate (s/gen ::K/hello-spec
                       {::K/hello-prefix (fn []
                                           (s/gen (constantly K/hello-header)))}))
  ;; The s/gen part is really just a thin wrapper around
  (#'s/gensub ::K/hello-spec
              {::K/hello-prefix (fn []
                                (s/gen (constantly K/hello-header)))}
              []
              {::recursion-limit 4}
              ::K/hello-spec)
  ;; The part of that which is blowing up expands to
  (let [overrides {::K/hello-prefix (fn []
                                      (s/gen (constantly K/hello-header)))}
        path []
        rmap {::recursion-limit 4}
        spec (#'s/specize ::K/hello-spec)
        g (or (when-let [gfn (or (get overrides (or (#'s/spec-name spec) spec))
                                 (get overrides path))]
                (gfn))
              (s/gen* spec overrides path rmap))]
    g)
  ;; That fails with the same stack trace
  (let [overrides {::K/hello-prefix (fn []
                                      (s/gen (constantly K/hello-header)))}
        spec (#'s/specize ::K/hello-spec)
        path []
        rmap {::recursion-limit 4}
        gfn (get overrides (or (#'s/spec-name spec) spec))]
    (comment (#'s/spec-name spec))
    ;; nil at this level
    gfn
    (try
      (s/gen* spec overrides path rmap)
      (catch clojure.lang.ExceptionInfo ex
        (print ex)
        (.getData ex))))

  (try
    (gen/generate (s/gen ::K/hello-spec
                         {::K/hello-prefix #(gen/return K/hello-header)
                          ::K/srvr-xtn #(gen/vector lo-gen/byte K/extension-length)
                          ::K/clnt-xtn #(gen/vector lo-gen/byte K/extension-length)
                          ::K/clnt-short-pk #(lo-gen/->Generator (fn [rnd size]
                                                                   (let [pair (crypto/random-keys :client)]
                                                                     (rose/make-rose
                                                                      {::specs/secret-long (::specs/my-client-public pair)
                                                                       ::specs/secret-short (::specs/my-client-secret pair)}
                                                                      []))))
                          ::K/zeros #(gen/return (byte-array (take K/zero-box-length (repeat 0))))
                          }))
    (catch clojure.lang.ExceptionInfo ex
      (println ex)
      (.getData ex))
    (catch ClassCastException ex
      (println ex)))
  (gen/sample (gen/return K/hello-header))
  (gen/sample (gen/vector lo-gen/byte K/extension-length))
  (gen/sample (lo-gen/->Generator (fn [rnd size]
                                    (let [pair (crypto/random-keys :client)]
                                      (rose/make-rose
                                       {::specs/secret-long (::specs/my-client-public pair)
                                        ::specs/secret-short (::specs/my-client-secret pair)}
                                       [])))))

  (gen/generate (s/gen (s/keys :req [::K/hello-prefix
                                     ::K/srvr-xtn
                                     ::K/clnt-short-pk])
                       {::K/hello-prefix #(gen/return K/hello-header)
                        ::K/srvr-xtn #(gen/vector lo-gen/byte K/extension-length)
                        ::K/clnt-xtn #(gen/vector lo-gen/byte K/extension-length)
                        ;; This generates a random encrypted keypair.
                        ;; Which isn't what I want, but this is the secret magical
                        ;; sauce to make a dead-simple custom generator work.
                        ;; (The real trick stems from shrinking it)
                        #_[::K/clnt-short-pk #(lo-gen/->Generator (fn [rnd size]
                                                                  (let [pair (crypto/random-keys :client)]
                                                                    (rose/make-rose
                                                                     {::specs/secret-long (::specs/my-client-public pair)
                                                                      ::specs/secret-short (::specs/my-client-secret pair)}
                                                                     []))))]
                        ::K/zeros #(gen/return (byte-array (take K/zero-box-length (repeat 0))))
                        }))
  (gen/sample (s/gen (s/keys :req [#_::K/hello-prefix
                                     ::K/srvr-xtn
                                     ::K/clnt-xtn
                                     #_::K/clnt-short-pk
                                     #_::K/zeros
                                     #_::K/client-nonce-suffix
                                     #_::K/crypto-box])
                       #_::K/hello-spec
                       {::K/hello-prefix #(gen/return K/hello-header)
                        ::K/srvr-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) K/extension-length))
                        ::K/clnt-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) K/extension-length))
                        ;; This generates a random encrypted keypair.
                        ;; Which isn't what I want, but this is the secret magical
                        ;; sauce to make a dead-simple custom generator work.
                        ;; (The real trick stems from shrinking it)
                        #_[::K/clnt-short-pk #(lo-gen/->Generator (fn [rnd size]
                                                                  (let [pair (crypto/random-keys :client)]
                                                                    (rose/make-rose
                                                                     {::specs/secret-long (::specs/my-client-public pair)
                                                                      ::specs/secret-short (::specs/my-client-secret pair)}
                                                                     []))))]
                        ::K/zeros #(gen/return (byte-array (take K/zero-box-length (repeat 0))))
                        ::K/client-nonce-suffix #(gen/fmap byte-array (gen/vector lo-gen/byte K/client-nonce-suffix-length))
                        ::K/crypto-box #(gen/fmap byte-array (gen/vector lo-gen/byte K/hello-crypto-box-length))
                        }))
  (count (gen/generate (gen/fmap byte-array (gen/vector lo-gen/byte K/hello-crypto-box-length))))
  (gen/generate (s/gen (s/keys :req [::K/clnt-xtn
                                     ::K/srvr-xtn])
                       {::K/clnt-xtn #(gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))
                        ::K/srvr-xtn #(gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))}))
  (count (gen/sample (gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length)) 200))
  (let [sample (gen/sample (gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length)) 200)]
    (doseq [x sample]
      (when-not (s/valid? ::K/clnt-xtn x)
        (throw (ex-info "Something went wrong"
                        (s/explain-data ::K/clnt-xtn x))))))

  (gen/generate (s/gen ::K/clnt-xtn
                       {::specs/extension #(gen/fmap byte-array (gen/vector (gen/choose -128 127) K/extension-length))}))

  (type (gen/generate (gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))))
  (count (gen/generate (gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))))
  ;; This is a way to avoid dipping down into lo-gen
  (gen/generate (gen/fmap byte-array (gen/vector (gen/choose -128 127) K/extension-length)))

  ;; Note that this definitely does not do what I want
  (comment (count (gen/generate (gen/bytes 16))))
  ;; Neither does this
  (count (gen/generate (gen/bytes nil 16)))

  (gen/generate (s/gen ::K/clnt-short-pk))
  (gen/generate (lo-gen/->Generator (fn [_ _]
                                      (rose/make-rose (utils/random-secure-bytes K/key-length) []))))

  (gen/sample (gen/return K/hello-header))
  (gen/generate (gen/return K/hello-header))

  (s/gen ::K/hello-spec)

  (gen/generate (gen/vector lo-gen/byte K/extension-length))

  (gen/sample (s/gen ::K/prefix))
  (gen/sample (s/gen (s/with-gen ::K/hello-prefix
                       (fn []
                         (s/gen (constantly K/hello-header))))))
  (gen/sample (gen/bytes))
  (gen/sample (gen/such-that (s/and #(= K/extension-length (count %))
                                    identity)
                             (gen/bytes)))
  (gen/generate (s/with-gen ::K/prefix
                  (gen/such-that (s/and #(= K/extension-length (count %))
                                        identity)
                                 #_(gen/vector gen/byte K/extension-length)
                                 (gen/bytes K/extension-length))))
  (map count (gen/sample (gen/bytes 16)))

  (gen/generate (s/gen
                 ::K/hello-spec
                 {::K/hello-prefix #(gen/return K/hello-header)
                  ::K/srvr-xtn #(gen/vector lo-gen/byte K/extension-length)
                  ::K/clnt-xtn #(gen/vector lo-gen/byte K/extension-length)
                  ::K/clnt-short-pk #(lo-gen/->Generator (fn [_ _]
                                                           (rose/make-rose (utils/random-secure-bytes K/key-length) [])))
                  ::K/zeros #(gen/return (byte-array (take K/zero-box-length (repeat 0))))
                  ::K/client-nonce-suffix #(gen/fmap byte-array (gen/vector lo-gen/byte K/client-nonce-suffix-length))
                  ::K/crypto-box #(gen/fmap byte-array (gen/vector lo-gen/byte K/hello-crypto-box-length))}))
  )

(defn fixed-length-byte-array-generator
  [n]
  (gen/fmap byte-array (gen/vector (gen/choose -128 127) n)))

(deftest hello-round-trip
  ;; FIXME: The code for generating a specific byte array needs to
  ;; be moved somewhere generally useful
  (let [hellos (gen/sample (s/gen
                            ::K/hello-spec
                            {::K/hello-prefix #(gen/return K/hello-header)
                             ;; FIXME: Go back to spec'ing out both
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
        buffers (map (partial marshal/compose K/hello-packet-dscr) hellos)
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
          b (marshal/decompose K/hello-packet-dscr (first buffers))]
      (println "First raw: " a
               "\nFirst decomposed: " b))
    (dorun (map #(is (= %1 (marshal/decompose K/hello-packet-dscr %2)))
                hellos
                ;; decompose does expect a ByteBuf
                #_serialized
                buffers))
    (comment
      (println (count (first serialized))))))
(comment
  (hello-round-trip)
  )
