(ns frereth-cp.shared.serialization
  "I didn't do enough research before choosing this name.

Marshalling is really tied in with things like RMI and CORBA
and DCOM. It's really about OOP, which just does not belong
in this picture.

FIXME: Rename for better semantics before this progresses any further."
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.shared.constants :as K]
            [frereth-cp.util :as util])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn composition-reduction
  "Reduction function associated for run!ing from compose.

TODO: Think about a way to do this using specs instead.

Needing to declare these things twice is annoying."
  [tmplt fields ^ByteBuf dst k]
  (let [dscr (k tmplt)
        cnvrtr (::K/type dscr)
        ^bytes v (k fields)]
    ;; An assertion error here is better than killing the JVM
    ;; through a SIGSEGV, which is what happens without it
    (assert (or (= ::K/zeroes cnvrtr)
                (and (= ::K/const cnvrtr)
                     (::K/contents dscr))
                v) (try (str "Composing from '"
                             (pr-str v)
                             "' (a "
                             (pr-str (class v))
                             ")\nbased on "
                             k
                             " among\n"
                             (keys fields)
                             "\nto "
                             dst
                             "\nbased on "
                             cnvrtr
                             "\nfor\n"
                             dscr)
                        (catch ClassCastException ex
                          (str ex "\nTrying to build error message about '" v
                               "' under " k " in\n" fields))))
    (try
      (case cnvrtr
        ::K/bytes (let [^Long n (::K/length dscr)
                        beg (.readableBytes dst)]
                    (try
                      (log/debug (str "Getting ready to write "
                                      n
                                      " bytes to\n"
                                      dst
                                      " a "
                                      (class dst)
                                      "\nfor field "
                                      k))
                      (.writeBytes dst v 0 n)
                      (let [end (.readableBytes dst)]
                        (assert (= (- end beg) n)))
                      (catch ClassCastException ex
                        (log/error ex (str "Trying to write " n " bytes from\n"
                                           v "\nto\n" dst))
                        (throw (ex-info "Setting bytes failed"
                                        {::field k
                                         ::length n
                                         ::dst dst
                                         ::dst-length (.capacity dst)
                                         ::src v
                                         ::source-class (class v)
                                         ::description dscr
                                         ::error ex})))
                      (catch IllegalArgumentException ex
                        (log/error ex (str "Trying to write " n " bytes from\n"
                                           v "\nto\n" dst))
                        (throw (ex-info "Setting bytes failed"
                                        {::field k
                                         ::length n
                                         ::dst dst
                                         ::dst-length (.capacity dst)
                                         ::src v
                                         ::source-class (class v)
                                         ::description dscr
                                         ::error ex})))))
        ::K/const (.writeBytes dst (::K/contents dscr))
        ::K/int-64 (.writeLong dst v)
        ::K/zeroes (let [n (::K/length dscr)]
                     (log/debug "Getting ready to write " n " zeros to " dst " based on "
                                (util/pretty dscr))
                     (.writeZero dst n))
        (throw (ex-info "No matching clause" dscr)))
      (catch IllegalArgumentException ex
        (throw (ex-info "Missing clause"
                        {::problem ex
                         ::cause cnvrtr
                         ::field k
                         ::description dscr
                         ::source-value v})))
      (catch NullPointerException ex
        (throw (ex-info "NULL"
                        {::problem ex
                         ::cause cnvrtr
                         ::field k
                         ::description dscr
                         ::source-value v}))))))

(defn calculate-length
  [{cnvrtr ::K/type
    :as dscr}]
  (case cnvrtr
    ::K/bytes (::K/length dscr)
    ::K/const (count (::K/contents dscr))
    ::K/int-64 8
    ::K/zeroes (::K/length dscr)))

(defn read-byte-array
  [dscr src]
  (let [^Long len (calculate-length dscr)
        dst (byte-array len)]
    (.readBytes src dst)
    dst))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn compose!
  "compose destructively. If you need that optimization"
  ^ByteBuf [tmplt fields ^ByteBuf dst]
  ;; Q: How much do I gain by supplying dst?
  ;; A: It does let callers reuse the buffer, which
  ;; will definitely help with GC pressure.
  ;; Yes, it's premature optimization. And how
  ;; often will this get used?
  ;; Rename this to compose!
  ;; Add a purely functional version of compose that
  ;; creates the ByteBuf, calls compose! and
  ;; returns dst.
  (run!
   (partial composition-reduction tmplt fields dst)
   (keys tmplt))
  dst)

(defn compose
  "serialize a map into a ByteBuf"
  ^ByteBuf [tmplt fields]
  ;; Q: Is it worth precalculating the size?
  (let [size (reduce + (map calculate-length (vals tmplt)))
        dst (Unpooled/buffer size)]
    (run!
     (partial composition-reduction tmplt fields dst)
     (keys tmplt))
    dst))

(s/fdef decompose
        ;; TODO: tmplt needs a spec for the values
        :args (s/cat :template map?
                     :src #(instance? ByteBuf %))
        ;; TODO: Really should match each value in tmplt
        ;; with the corresponding value in ret and clarify
        ;; a type that way.
        :fn #(= (-> % :ret keys)
                (-> % :tmplt keys))
        :ret map?)
(defn decompose
  ;; Q: Is ztellman's vertigo applicable here?
  "Read a C-style ByteBuf struct into a map, based on a template"
  [tmplt ^ByteBuf src]
  (reduce
   (fn
     [acc k]
     (let [dscr (k tmplt)
           cnvrtr (::K/type dscr)]
       ;; The correct approach would be to move this (and compose)
       ;; into its own tiny ns that everything else can use.
       ;; helpers seems like a good choice.
       ;; That's more work than I have time for at the moment.
       (assoc acc k (case cnvrtr
                      ;; .readBytes does not produce a derived buffer.
                      ;; The buffer that gets created here will need to be
                      ;; released separately
                      ;; Q: Would .readSlice make more sense?
                      ::K/bytes (read-byte-array dscr src)
                      ::K/const (let [contents (::K/contents dscr)
                                      extracted (read-byte-array dscr src)]
                                  (when-not (b-t/bytes= extracted contents)
                                    (throw (ex-info "Deserialization constant mismatched"
                                                    {::expected (vec contents)
                                                     ::actual (vec extracted)})))
                                  extracted)
                      ::K/int-64 (.readLong src)
                      ::K/int-32 (.readInt src)
                      ::K/int-16 (.readShort src)
                      ::K/uint-64 (b-t/possibly-2s-uncomplement-64 (.readLong src))
                      ::K/uint-32 (b-t/possibly-2s-uncomplement-32 (.readInt src))
                      ::K/uint-16 (b-t/possibly-2s-uncomplement-16 (.readShort src))
                      ::K/zeroes (let [dst (read-byte-array dscr src)]
                                   (when-not (every? zero? dst)
                                     (throw (ex-info "Corrupted zeros field"
                                                     {::field dscr
                                                      ::src src
                                                      ::tmplt tmplt})))
                                   dst)
                      (throw (ex-info "Missing case clause"
                                      {::failure cnvrtr
                                       ::acc acc
                                       ::key k
                                       ::template tmplt
                                       ::source src}))))))
   {}
   (keys tmplt)))
