(ns frereth.cp.shared.serialization
  ;; Something like protocol buffers or avro seems very tempting.
  ;; Those are actually higher-level constructs that these wrap up.
  ;; This is more about building things like raw TCP packets.
  "Convert native data structures to/from raw bytes for network travel"
  (:require [clojure.spec.alpha :as s]
            ;; FIXME: Make this go away.
            [clojure.tools.logging :as log]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [specs :as specs]]
            [frereth.cp.util :as util])
  (:import [io.netty.buffer ByteBuf Unpooled]
           java.util.Arrays))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;; FIXME: I can do better than this
(s/def ::decomposed (s/map-of keyword? (s/or :bytes bytes?
                                             :number integer?)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

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
        ::K/bytes (let [n (long (::K/length dscr))
                        beg (.readableBytes dst)]
                    (try
                      (log/debug (str "Getting ready to write "
                                      n
                                      " bytes to\n"
                                      dst
                                      " a "
                                      (class dst)
                                      "\nfor field "
                                      k
                                      "\nfrom " (count v)
                                      " bytes in " v))
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
        ::K/const (let [contents (::K/contents dscr)]
                    (log/debug (str "Writing "
                                    (::K/length dscr)
                                    " constant bytes "
                                    contents
                                    " to "
                                    dst
                                    " based on "
                                    (util/pretty dscr)))
                    (.writeBytes dst contents))
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
  (try
    (case cnvrtr
      ::K/bytes (::K/length dscr)
      ::K/const (count (::K/contents dscr))
      ::K/int-64 8
      ::K/zeroes (::K/length dscr))
    (catch IllegalArgumentException ex
      (log/error ex (str "Trying to calculate length for "
                         dscr)))))

(s/fdef extract-byte-array-subset
        :args (s/and (s/cat :offset nat-int?
                            ;; Q: Is there a way to spec the relationship
                            ;; between offset, length, and src?
                            :src bytes?
                            :length nat-int?)
                     #((> (count (:src %)) (+ (:offset %) (:length %)))))
        :fn #(= (count (:ret %)) (-> % :args :length))
        :ret bytes?)
(defn extract-byte-array-subset
  [offset src length]
  (let [dst (byte-array length)]
    (b-t/byte-copy! dst 0 length src offset)
    dst))

(s/fdef decompose-array-field
        :args (s/cat :src ::bytes?
                     ;; FIXME: find or write a spec for this
                     :tmplt map?
                     ;; FIXME: find or write a spec for this
                     :acc map?
                     ;; Really, it's a function for pulling the
                     ;; appropriate field out of tmplt.
                     ;; In practice, it's a keyword
                     :k keyword?)
        ;; Q: Can I write anything meaningful in the functional
        ;; part of the spec?
        ;; A: Well, :k should be in :ret, but not [:args :acc],
        ;; and those maps really should otherwise be the same.
        ;; Don't really have a way to check the before/after
        ;; (.tell src)
        ;; Q: Are there any other possibilities?
        :ret ::decomposed)
(defn decompose-array-field
  "Refactored from inside a reduce"
  [^bytes src
   tmplt
   {:keys [::index]
    :as acc}
   k]
  (let [dscr (k tmplt)
        field-length (calculate-length dscr)
        cnvrtr (::K/type dscr)]
    (assoc acc k (case cnvrtr
                   ::K/bytes (extract-byte-array-subset index src field-length)
                   ::K/const (let [contents (::K/contents dscr)
                                   extracted (extract-byte-array-subset index src field-length)]
                               (when-not (b-t/bytes= extracted contents)
                                 (throw (ex-info "Deserialization constant mismatched"
                                                 {::expected (vec contents)
                                                  ::actual (vec extracted)})))
                               extracted)
                   ;; FIXME: Write these next 3
                   ::K/int-64 (.readLong src)
                   ::K/int-32 (.readInt src)
                   ::K/int-16 (.readShort src)
                   ::K/uint-64 (let [buf (Arrays/copyOfRange src index (+ 8 index))]
                                 (b-t/uint64-unpack buf))
                   ::K/uint-32 (let [buf (Arrays/copyOfRange src index (+ 4 index))]
                                 (b-t/uint32-unpack buf))
                   ::K/uint-16 (let [buf (Arrays/copyOfRange src index (+ 2 index))]
                                 (b-t/uint16-unpack buf))
                   ::K/zeroes (let [dst (extract-byte-array-subset index src field-length)]
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
                                    ::source src})))
           ::index (+ index (calculate-length dscr)))))

(s/fdef read-byte-array
  :args (s/cat :dscr map?  ; still needs a real spec
               :src ::specs/byte-buf)
  :ret bytes?)
(defn read-byte-array!
  "From a ByteBuf

  Destructive in the sense that it updates the readIndex in src"
  [dscr src]
  (let [len (long (calculate-length dscr))
        dst (byte-array len)]
    (.readBytes src dst)
    dst))

(s/fdef decompose-field!
        :args (s/cat :src ::specs/byte-buf
                     ;; FIXME: find or write a spec for this
                     :tmplt map?
                     ;; FIXME: find or write a spec for this
                     :acc map?
                     ;; Really, it's a function for pulling the
                     ;; appropriate field out of tmplt.
                     ;; In practice, it's a keyword
                     :k keyword?)
        ;; Q: Can I write anything meaningful in the functional
        ;; part of the spec?
        ;; A: Well, :k should be in :ret, but not [:args :acc],
        ;; and those maps really should otherwise be the same.
        ;; Don't really have a way to check the before/after
        ;; (.tell src)
        ;; Q: Are there any other possibilities?
        :ret ::decomposed)
(defn decompose-field!
  "Refactored from inside a reduce"
  [src tmplt acc k]
  (let [dscr (k tmplt)
        cnvrtr (::K/type dscr)]
    (assoc acc k (case cnvrtr
                   ;; .readBytes does not produce a derived buffer.
                   ;; The buffer that gets created here will need to be
                   ;; released separately
                   ;; Q: Would .readSlice make more sense?
                   ::K/bytes (read-byte-array! dscr src)
                   ::K/const (let [contents (::K/contents dscr)
                                   extracted (read-byte-array! dscr src)]
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
                   ::K/zeroes (let [dst (read-byte-array! dscr src)]
                                ;; Note that, aside from wasting time, this is
                                ;; pointless:
                                ;; the Hello packet is the only one that
                                ;; deliberately includes 0 padding,
                                ;; and it specifically forbids this test.
                                ;; Those fields are available for possible future
                                ;; expansion.
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
  ;; TODO: This should really just return a [B
  ;; Or, at least, have an optional arity override that does
  ;; so. The value in making this change really depends on
  ;; how many callers need to do that vs. the ones that
  ;; actually take advantage of the ByteBuf.
  ;; TODO: Look into this.
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
  ;; TODO: Refactor rename to decompose!
  "Read a C-style struct from a ByteBuf into a map, based on template"
  [tmplt ^ByteBuf src]
  ;; It seems as though this should call .release on src
  ;; when done
  (reduce
   (partial decompose-field! src tmplt)
   {}
   (keys tmplt)))

(s/fdef decompose-array
  ;; FIXME: Still need a spec for the template array-map
  :args (s/cat :tmplt map?
               :src bytes?)
  :ret ::decomposed)
(defn decompose-array
  "Read a C-style struct from a byte array into a map, based on template"
  [tmplt src]
  (let [src (bytes src)]
    (dissoc
     (reduce
      (partial decompose-array-field src tmplt)
      {::index 0}
      (keys tmplt))
     ::index)))
