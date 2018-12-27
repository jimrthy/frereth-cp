(ns frereth.cp.shared.util
  "Pieces refactored from frereth.common.util

  Because I haven't really decided what to do with them yet"
  ;; TODO: Move into frereth.cp.shared.util
  (:require [clojure.pprint :as pprint]
            [clojure.spec.alpha :as s]
            [clojure.stacktrace :as s-t]
            [clojure.string :as string]
            [frereth.weald
             [logging :as log]])
  (:import clojure.lang.ExceptionInfo
           java.security.SecureRandom
           java.util.UUID))

(set! *warn-on-reflection* true)

(defn jvm-version
  []
  (System/getProperty "java.runtime.version"))

(defn get-class-path
  []
  ;; There are actually multiple CLASSPATHS available.
  ;; For my current purposes, this returns empty.
  ;; java.lang.ClassLoader/getSystemClassLoader includes
  ;; 1. my boot script
  ;; 2. the boot.jar
  ;; 3. the openjdk tools.jar
  ;; Gotta <3 java's ease of use.
  (let [^java.net.URLClassLoader loader (-> (Thread/currentThread)
                                            .getContextClassLoader)]
    (-> loader
        .getURLs
        seq)))
(comment
  (get-class-path))

(s/fdef get-cpu-count
        :ret nat-int?)
(defn get-cpu-count
  []
  (let [^Runtime rt (Runtime/getRuntime)]
    (.availableProcessors rt)))

(s/fdef get-current-thread
        :args (s/cat)
        :ret string?)
(defn get-current-thread
  []
  (.getName (Thread/currentThread)))

(defn pre-log
  "This is really just a leftover from trying to make 'normal' logging frameworks work"
  [human-name]
  (pprint/cl-format nil
                    "~a (~a):\n"
                    human-name
                    (get-current-thread)))

;; TODO: Rename this to seconds-in-millis
(defn seconds [] 1000)  ; avoid collision w/ built-in second
(defn minute [] (* 60 (seconds)))
(defn nanos->millis
  [ns]
  (/ ns 1000000))
(defn millis->nanos
  [ms]
  (* ms 1000000))
(defn seconds->nanos
  [ss]
  (* ss 1000000000))

;;; This seems to work
;;; TODO: Verify that it's actually getting used.
(def pprint-proxy
  (try (require '[fipp.edn :refer (pprint) :rename {pprint fipp}])
       (resolve 'fipp.edn/pprint)
       (catch java.io.FileNotFoundException _
         pprint/pprint)))
(defn pretty
  "Return a pretty-printed representation of xs"
  [& xs]
  (try
    (with-out-str (apply pprint-proxy xs))
    (catch RuntimeException ex
      (let [log-state (log/init ::pretty)
            log-state (log/exception log-state
                                     ex
                                     ::failed
                                     "Pretty Printing Failed"
                                     {::problem xs})]
        (print-str (-> log-state
                       ::log/entries
                       first))))
    (catch AbstractMethodError ex
      ;; Q: Why isn't this a RuntimeException?
      (let [log-state (log/init ::pretty)
            log-state (log/exception log-state
                                     ex
                                     ::failed
                                     "Something seriously wrong w/ pretty printing? Falling back to standard"
                                     {::problem xs})]
        (print-str (-> log-state
                       ::log/entries
                       first))))))

(s/fdef random-uuid
        :args nil
        :ret uuid?)
(defn random-uuid
  "Generate a random UUID"
  []
  ;; Yes, this is cheeseball. I just get tired of looking
  ;; it up every time I need to use it.
  (UUID/randomUUID))

(s/fdef get-stack-trace
        :args (s/cat :ex #(instance? Throwable %))
        :ret (s/coll-of str))
(defn get-stack-trace
  "Returns stack trace frame descriptions in a vector"
  [^Throwable ex]
  (reduce
   (fn [acc ^StackTraceElement frame]
     (conj acc
           (str "\n" (.getClassName frame)
                "::" (.getMethodName frame)
                " at " (.getFileName frame)
                " line " (.getLineNumber frame))))
   [] (.getStackTrace ex)))

(s/fdef random-secure-bytes
        :args (s/cat :count nat-int?)
        :fn (fn [{:keys [:args :ret]}]
              (= (count ret) (:count args)))
        :ret bytes?)
(let [generator (SecureRandom.)]
  (defn random-secure-bytes
    "Returns an array of n bytes, generated in a cryptographically secure manner"
    [n]
    (let [result (byte-array n)]
      (.nextBytes generator result)
      result)))

(s/fdef show-stack-trace
        :args (s/cat :ex #(instance? Throwable %))
        :ret string?)
(defn show-stack-trace
  "Convert stack trace to a readable string
  Slow and inefficient, but you have bigger issues than
  performance if you're calling this"
  ;; This is more-or-less a built-in. TODO: Switch to using that
  [^Throwable ex]
  ;; TODO: Compare timing against my implementation
  ;; It seems like the core lib approach really should be the
  ;; clear winner
  #_(with-out-str (s-t/print-stack-trace ex))
  (let [base (if (instance? ExceptionInfo ex)
               (str ex "\n" (pretty (.getData ^ExceptionInfo ex)))
               (str ex))]
    (reduce str
            base
            (get-stack-trace ex))))

(defn slurp-bytes
  "Slurp the bytes from a slurpable thing

Copy/pasted from stackoverflow. Credit: Matt W-D.

alt approach: Add dependency to org.apache.commons.io

Or there's probably something similar in guava"
  [bs]
  (with-open [out (java.io.ByteArrayOutputStream.)]
    (clojure.java.io/copy (clojure.java.io/input-stream bs) out)
    (.toByteArray out)))

(defn spit-bytes
  "Spit bytes to a spittable thing"
  [f bs]
  (with-open [out (clojure.java.io/output-stream f)]
    (with-open [in (clojure.java.io/input-stream bs)]
      (clojure.java.io/copy in out))))

(defn update-values
  "Apply f (& args) to each value in a map

  Credit: http://blog.jayfields.com/2011/08/clojure-apply-function-to-each-value-of.html"
  [m f & args]
  ;; TODO: Compare speed against the suggested alternatives
  ;; Assuming we ever have any indication that this is used in
  ;; a speed-critical inner loop
  (comment
    (zipmap (keys m) (map #(apply f % args) (vals m))))
  (comment
    (into {}
          (for [[k v] m]
            [k (apply f v args)])))
  (reduce (fn [r [k v]]
            (assoc r k (apply f v args)))
          {}
          m))
