(ns frereth-cp.util
  "Pieces refactored from frereth.common.util

  Because I haven't really decided what to do with them yet"
  ;; TODO: Try to require fipp and use it instead of
  ;; pprint
  (:require [clojure.pprint :as pprint]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log])
  (:import clojure.lang.ExceptionInfo))

(set! *warn-on-reflection* true)

;; TODO: Rename this to seconds-in-millis
(defn seconds [] 1000)  ; avoid collision w/ built-in second
(defn minute [] (* 60 (seconds)))
(defn nanos->millis
  [ns]
  (/ ns 1000000))
(defn seconds->nanos
  [ss]
  (* ss 1000000000))

(defn pretty
  "Return a pretty-printed representation of xs"
  [& xs]
  (try
    (with-out-str (apply pprint/pprint xs))
    (catch RuntimeException ex
      (log/error ex "Pretty printing failed (there should be a stack trace about this failure).
Falling back to standard")
      (str xs))
    (catch AbstractMethodError ex
      ;; Q: Why isn't this a RuntimeException?
      (log/error ex "Something seriously wrong w/ pretty printing? Falling back to standard:\n")
      (str xs))))

(s/fdef get-stack-trace
        :args (s/cat :ex #(instance? Throwable %))
        :ret (s/coll-of str))
(defn get-stack-trace
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
  [^Throwable ex]
  (let [base (if (instance? ExceptionInfo ex)
               (str ex "\n" (pretty (.getData ^ExceptionInfo ex)))
               (str ex))]
    (reduce #(str %1 %2)
            base
            (get-stack-trace ex))))
