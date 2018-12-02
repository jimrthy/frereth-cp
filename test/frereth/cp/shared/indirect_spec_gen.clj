(ns frereth.cp.shared.indirect-spec-gen
  "This was really just a proof of concept trying to narrow down spec.gen oddities"
  ;; FIXME: Make this ns go away completely
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer (deftest is)]))

(def extension-length 16)
(comment
  (s/def ::extension (s/with-gen (s/and bytes?
                                        #(= (count %) extension-length))
                       #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length)))))
(s/def ::extension (s/and bytes?
                          #(= (count %) extension-length)))
(s/def ::srvr-xtn ::extension)
(s/def ::clnt-xtn ::extension)

;; Haven't seen this fail yet
(deftest transitive
  (let [test-runs 40
        success-count
        (reduce (fn [n m]
                  (try
                    (let [samples (gen/sample (s/gen (s/keys :req [::srvr-xtn
                                                                   ::clnt-xtn])
                                                     {::srvr-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))
                                                      ::clnt-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))}))]
                      (is samples)
                      (inc n))
                    (catch Exception ex
                      (println ex "on sample" m)
                      n)))
                0
                (range test-runs))]
    (println success-count "successes out of" test-runs)))

(defn manual-check
  []
  (gen/sample (s/gen (s/keys :req [::srvr-xtn
                                   ::clnt-xtn])
                     #_{::srvr-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))
                        ::clnt-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))
                        ::extension #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))}
                     {::extension #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))})))
;; Calling this fails pretty much every time, unless I specify the generator for ::extension.
(comment (manual-check))

(comment
  (gen/sample (s/gen (s/keys :req [::srvr-xtn
                                   ::clnt-xtn])
                     {::srvr-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))
                      ::clnt-xtn #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))}))
  )

(s/def ::test (s/with-gen (s/and bytes?
                                 #(= (count %) extension-length))
                #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))))
(comment
  (gen/sample (s/gen ::test))
  (map count (gen/sample (s/gen ::test)))
  )

;; Calling manual-check from inside a test passes
(deftest transitive-indirect
  (let [test-runs 40
        success-count
        (reduce (fn [n m]
                  (try
                    (let [samples (manual-check)]
                      (is samples)
                      (inc n))
                    (catch Exception ex
                      (println ex "on sample" m)
                      n)))
                0
                (range test-runs))]
    (println success-count "successes out of" test-runs)))

;; This approach seems to always work
(deftest direct
  (let [samples (gen/sample (s/gen ::extension
                                   {::extension #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))}))]
    (is samples)))

(defn check-direct
  []
  (gen/sample (s/gen ::extension
                     {::extension #(gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))})))
(check-direct)

(defn generate-directly
  []
  (gen/sample (gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))))

(comment
  (let [xs (generate-directly)]
    (doseq [x xs]
      (println ".")
      (when-let [problem (s/explain-data ::srvr-xtn x)]
        (throw (ex-info "oops" problem)))))
  )

(deftest manual-spec
  (let [xs (generate-directly)]
    (doseq [x xs]
      (is (not (s/explain-data ::srvr-xtn x))))))


(comment
  (map count (gen/sample (gen/vector (gen/choose -128 127))))
  (map count (gen/sample (gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))))
  (map vec (gen/sample (gen/fmap byte-array (gen/vector (gen/choose -128 127) extension-length))))
  )
