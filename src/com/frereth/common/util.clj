(ns com.frereth.common.util
  "Utilities to try to make my life easier"
  (:require [clojure.core.async :as async]
            [clojure.edn :as edn]
            [clojure.pprint :as pprint]
            [clojure.spec :as s]
            [clojure.string :as string]
            [com.frereth.common.schema :as fr-sch]
            [hara.event :refer (raise)]
            [taoensso.timbre :as log])
  (:import [java.io PushbackReader Reader]
           [java.lang.reflect Modifier]
           [java.net InetAddress]
           [java.util UUID]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::reader (fr-sch/class-predicate Reader))
(s/def ::pushback-reader (fr-sch/class-predicate PushbackReader))
(s/def ::uuid (fr-sch/class-predicate UUID))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Configuration

;; Global function calls like this are bad.
;; Especially since I'm looking at a
;; white terminal background, as opposed to what
;; most seem to expect
;; TODO: Put this inside a component's start
;; instead
;; Bigger TODO: Figure out what replaced it
(comment
  (puget/set-color-scheme! :keyword [:bold :green]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn describe-annotations
  "Convert reflected annotions to a seq of strings"
  [as]
  (map #(.toString %) as))

(s/fdef interpret-modifiers
        :args (s/cat :modifiers integer?)
        :ret (s/coll-of keyword?))
(defn interpret-modifiers
  "Convert reflected java modifiers (which is really a bit flag) to a seq of keywords"
  [ms]
  ;; TODO: this implementation sucks
  (let [dict {Modifier/ABSTRACT :abstract
              Modifier/FINAL :final
              Modifier/INTERFACE :interface
              Modifier/NATIVE :native
              Modifier/PRIVATE :private
              Modifier/PROTECTED :protected
              Modifier/PUBLIC :public
              Modifier/STATIC :static
              Modifier/STRICT :strict
              Modifier/SYNCHRONIZED :synchronized
              Modifier/TRANSIENT :transient
              Modifier/VOLATILE :volatile}]
    (reduce (fn [acc [k v]]
              (comment (println "Thinking about assoc'ing " v " with " acc))
              (if (not= 0 (bit-and ms k))
                (conj acc v)
                acc))
            [] dict)))

;; TODO: Spec this
(defn describe-field
  "Make java's reflected field description more user-friendly"
  [f]
  {:name (.getName f)
   :annotations (map describe-annotations (.getDeclaredAnnotations f))
   :modifiers (interpret-modifiers (.getModifiers f))})

;; TODO: Spec this
(defn describe-method
  "Make java's reflected method description more user-friendly"
  [m]
  {:annotations (map describe-annotations (.getDeclaredAnnotations m))
   :exceptions (.getExceptionTypes m)
   :modifiers (interpret-modifiers (.getModifiers m))
   :return-type (.getReturnType m)
   :name (.toGenericString m)})

;; TODO: Spec this
(defn fn-var?
  "Does a var represent something we can call?"
  [v]
  (let [f @v]
    (or (contains? (meta v) :arglists)
        (fn? f)
        (instance? clojure.lang.MultiFn f))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

;; TODO: Spec this
(defn cheat-sheet
  "Shamelessly borrowed from https://groups.google.com/forum/#!topic/clojure/j5PmMuhG3d8"
  [ns]
  (let [nsname (str ns)
        vars (vals (ns-publics ns))
        {funs true
         defs false} (group-by fn-var? vars)
        fmeta (map meta funs)
        dmeta (map meta defs)
        flen (apply max 0 (map (comp count str :name) fmeta))
        dnames (map #(str nsname \/ (:name %)) dmeta)
        fnames (map #(format (str "%s/%-" flen "s %s") nsname (:name %)
                             (string/join \space (:arglists %)))
                    fmeta)
        lines (concat (sort dnames) (sort fnames))]
    (str ";;; " nsname " {{{1\n\n"
         (string/join \newline lines))))

(s/fdef core-count
        :ret integer?)
(defn core-count
  []
  (.availableProcessors (Runtime/getRuntime)))

;; TODO: Spec this
(defn dir
  [something]
  (let [k (class something)
        bases (.getClasses k)
        fields (.getDeclaredFields k)
        useful-fields (map describe-field fields)
        methods (.getDeclaredMethods k)
        useful-methods (map describe-method methods)]
    ;; There are a bunch of associated predicates, but they don't seem all that useful
    ;; yet.
    ;; Things like isInterface
    {:bases bases
     :declared-bases (.getDeclaredClasses k)   ; I have serious doubts about this' usefulness
     :canonical-name (.getCanonicalName k)
     :class-loader (.getClassLoader k)
     :fields useful-fields
     :methods useful-methods
     :owner (.getDeclaringClass k)
     :encloser (.getEnclosingClass k)
     :enums (.getEnumConstants k)  ; seems dubiously useless...except when it's needed
     :package (.getPackage k)
     :protection-domain (.getProtectionDomain k)
     :signers (.getSigners k)
     :simple-name (.getSimpleName k)
     ;; Definitely deserves more detail...except that this is mostly useless
     ;; in the clojure world
     :type-params (.getTypeParameters k)}))

;; TODO: Spec this
(defn five-minute-timeout-chan
  "Returns an async channel that will time out in 5 minutes

Because I keep using them for heartbeat monitors"
  []
  (async/timeout (* 1000 60 5)))

(s/fdef load-resource
        :args (s/cat :url string?)
        :ret any?)
;; TODO: ^:always-validate
(defn load-resource
  [url]
  (-> url
      clojure.java.io/resource
      slurp
      edn/read-string))

;; TODO: Spec this
(defmacro make-runner
  "Ran across this on the clojure mailing list

Idiom for converting expression(s) to a callable"
  [expr]
  (eval `(fn []
           ~expr)))

;; TODO: Spec this
(defn my-ip
  "What is my IP address?

Totally fails on multi-home systems. But it's worthwhile as a starting point"
  []
  (.getHostAddress (InetAddress/getLocalHost)))

;; TODO: Spec this
(defn pick-home
  "Returns the current user's home directory"
  []
  (System/getProperty "user.home"))

;; TODO: Spec this
(defn pretty
  [& os]
  (try
    (with-out-str (apply pprint/pprint os))
    (catch RuntimeException ex
      (log/error ex "Pretty printing failed (there should be a stack trace about this failure).
Falling back to standard")
      (str os))
    (catch AbstractMethodError ex
      ;; Q: Why isn't this a RuntimeException?
      (log/error ex "Something seriously wrong w/ pretty printing? Falling back to standard:\n")
      (str os))))

(s/fdef pushback-reader
        :args (s/cat :reader ::reader)
        :ret ::pushback-reader)
(defn pushback-reader
  "Probably belongs under something like utils.
Yes, it does seem pretty stupid"
  [reader]
  (PushbackReader. reader))

(s/fdef random-uuid
        :ret ::uuid)
(defn random-uuid
  "Because remembering the java namespace is annoying

medley.core has a cross-platform implementation. As long as it's being
included anyway, might as well use it instead.

TODO: Make that so.

Or maybe revisit the idea of including io.aviso/config in the first place.
Why did I include it in the first place? (And would it make more sense in
component-dsl?)"
  []
  (UUID/randomUUID))

(s/fdef deserialize
        :args (s/cat :bs :com.frereth.common/byte-array-seq)
        :ret any?)
(defn deserialize
  "Out of alphaetical order because it uses pretty"
  [bs]
  (let [s (String. bs)]
    (try
      (edn/read-string s)
      (catch RuntimeException ex
        (log/error ex "Failed reading incoming string:\n"
                   (pretty s))))))

(s/fdef serialize
        :args any?
        :ret :com.frereth.common.schema/byte-array-seq)
(defn serialize
  [o]
  (if (= (class o) fr-sch/java-byte-array)
    o
    (-> o pr-str .getBytes)))

(s/fdef thread-count
        :ret integer?)
(defn thread-count
  "Rough estimate of how many threads are currently being used
Probably doesn't mean much, considering thread pools. But it can't hurt
to know and have available

Note that this should *not* be used for monitoring. It's pretty heavy-
weight.

c.f. stackoverflow.com/questions/1323408/get-a-list-of-all-threads-currently-running-in-java
for a more complex-looking example which would be much more appropriate for that
sort of scenario"
  []
  (count (Thread/getAllStackTraces)))

;;; Named constants for timeouts
;;; TODO: These really don't belong in here
;;; Aside from being grossly inaccurate
(defn seconds [] 1000)  ; avoid collision w/ built-in second
(defn minute [] (* 60 (seconds)))
(defn hour [] (* 60 (minute)))
(defn day [] (* 24 (hour)))
(defn week [] (* 7 (day)))
(defn year [] (* 365 day))
