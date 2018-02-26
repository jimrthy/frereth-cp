(ns frereth-cp.shared-test
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer (are is deftest testing)]
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
  (gen/generate (s/gen (s/keys :req [::K/hello-prefix
                                     #_::K/srvr-xtn
                                     #_::K/clnt-xtn
                                     ::K/clnt-short-pk
                                     ::K/zeros
                                     ::K/client-nonce-suffix
                                     ::K/crypto-box])
                       #_::K/hello-spec
                       {::K/hello-prefix #(gen/return K/hello-header)
                        ::K/srvr-xtn #(gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))
                        ::K/clnt-xtn #(gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))
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
  (gen/generate (s/gen ::K/clnt-xtn
                       {::K/clnt-xtn #(gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))}))

  (gen/generate (s/gen ::K/clnt-xtn
                       {::specs/extension #(gen/fmap byte-array (gen/vector (gen/choose -128 127) K/extension-length))}))

  (type (gen/generate (gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))))
  (count (gen/generate (gen/fmap byte-array (gen/vector lo-gen/byte K/extension-length))))
  ;; This is a way to avoid dipping down into lo-gen
  (gen/generate (gen/fmap byte-array (gen/vector (gen/choose -128 127) K/extension-length)))

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

(deftest hello-round-trip
  ;; FIXME: The code for generating a specific byte array needs to
  ;; be moved somewhere generally useful
  ;; FIXME: Convert to gen/sample instead of gen/generate
  (let [hellos (gen/generate (s/gen
                              ::K/hello-spec
                              {::K/hello-prefix #(gen/return K/hello-header)
                               ::K/srvr-xtn #(gen/vector lo-gen/byte K/extension-length)
                               ::K/clnt-xtn #(gen/vector lo-gen/byte K/extension-length)
                               ::K/clnt-short-pk #(lo-gen/->Generator (fn [_ _]
                                                                        (rose/make-rose (utils/random-secure-bytes K/key-length) [])))
                               ::K/zeros #(gen/return (byte-array (take K/zero-box-length (repeat 0))))
                               ::K/client-nonce-suffix #(gen/fmap byte-array (gen/vector lo-gen/byte K/client-nonce-suffix-length))
                               ::K/crypto-box #(gen/fmap byte-array (gen/vector lo-gen/byte K/hello-crypto-box-length))}))
        serialized (map (partial marshal/compose K/hello-packet-dscr) hellos)]
    (dorun (map #(is (= %1 (marshal/decompose K/hello-packet-dscr %2)))
                hellos
                serialized))))
(comment
  (hello-round-trip))
