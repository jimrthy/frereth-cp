(ns frereth-cp.util
  "Pieces refactored from frereth.common.util

  Because I haven't really decided what to do with them yet"
  ;; TODO: Try to require fipp and use it instead of
  ;; pprint
  (:require [clojure.pprint :as pprint]
            [clojure.spec.alpha :as s]
            [clojure.stacktrace :as s-t]
            [clojure.string :as string]
            [clojure.tools.logging :as log])
  (:import clojure.lang.ExceptionInfo
           java.util.UUID))

(set! *warn-on-reflection* true)

(defn jvm-version
  []
  (System/getProperty "java.runtime.version"))

(s/fdef get-cpu-count
        :ret nat-int?)
(defn get-cpu-count
  []
  (let [^Runtime rt (Runtime/getRuntime)]
    (.availableProcessors rt)))

(defn get-current-thread
  []
  (.getName (Thread/currentThread)))

(defn pre-log
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
(defn seconds->nanos
  [ss]
  (* ss 1000000000))

;;; TODO: Verify that this works
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
      (log/error ex "Pretty printing failed (there should be a stack trace about this failure).
Falling back to standard")
      (str xs))
    (catch AbstractMethodError ex
      ;; Q: Why isn't this a RuntimeException?
      (log/error ex "Something seriously wrong w/ pretty printing? Falling back to standard:\n")
      (str xs))))

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
    (reduce #(str %1 %2)
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
