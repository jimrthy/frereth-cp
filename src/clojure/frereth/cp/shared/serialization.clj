(ns frereth.cp.shared.serialization
  ;; Something like protocol buffers or avro seems very tempting.
  ;; Those are actually higher-level constructs that these wrap up.
  ;; This is more about building things like raw TCP packets.
  "Convert native data structures to/from raw bytes for network travel"
  (:require [clojure.spec.alpha :as s]
            [frereth.cp.shared
             [bit-twiddling :as b-t]
             [constants :as K]
             [specs :as specs]
             [templates :as templates]
             [util :as util]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]
            [byte-streams :as b-s])
  (:import [io.netty.buffer ByteBuf Unpooled]
           java.util.Arrays))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Specs

;; FIXME: I can do better than this
(s/def ::decomposed (s/map-of keyword? (s/or :bytes bytes?
                                             :number integer?)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Internal

(s/fdef do-composition-reduction
  :args (s/cat :tmplt ::templates/pattern
               :dst ::specs/byte-buf
               :log-state ::weald/state
               :k keyword?)
  :ret ::weald/state)
(defn do-composition-reduction
  "Reduction function associated for run!ing from compose.

TODO: Think about a way to do this using specs instead.

Needing to declare these things twice is annoying."
  [tmplt fields ^ByteBuf dst log-state k]
  (let [dscr (k tmplt)
        cnvrtr (::K/type dscr)
        v (bytes (k fields))
        ;; Q: Worth making this a transient instead?
        ;; (would that even work?)
        log-state-atom (atom log-state)]
    ;; An assertion error here is better than killing the JVM
    ;; through a SIGSEGV, which is what happens without it
    (assert (or (= ::K/zeroes cnvrtr)
                (and (= ::K/const cnvrtr)
                     (::K/contents dscr))
                v)
            (try (str "Composing from '"
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
                    (swap! log-state-atom
                           (fn [current]
                             (println "Trying to add a log entry to" current)
                             (log/debug current
                                        ::do-composition-reduction
                                        "Writing bytes to a field"
                                        {::byte-count n
                                         ::destination dst
                                         ::destination-class (class dst)
                                         ::field-name k
                                         ::source-bytes v
                                         ::source-byte-count (count v)})))
                    (try
                      (.writeBytes dst v 0 n)
                      (let [end (.readableBytes dst)]
                        (assert (= (- end beg) n))
                        @log-state-atom)
                      (catch RuntimeException ex
                        (swap! log-state-atom
                               #(log/exception %
                                               ex
                                               ::writing
                                               ""
                                               {::byte-count n
                                                ::destination dst
                                                ::raw-source v
                                                ::source (vec v)}))
                        (throw (ex-info "Setting bytes failed"
                                        {::field k
                                         ::K/length n
                                         ::dst dst
                                         ::dst-length (.capacity dst)
                                         ::source v
                                         ::source-class (class v)
                                         ::description (util/pretty dscr)
                                         ::error ex
                                         ::weald/log @log-state-atom})))))
        ::K/const (let [contents (::K/contents dscr)
                        log-state (log/debug log-state
                                             ::do-composition-reduction
                                             "Writing const field"
                                             {::field k
                                              ::K/length (::K/length dscr)
                                              ::raw-source contents
                                              ::source (vec contents)
                                              ::destination dst
                                              ::description (util/pretty dscr)})]
                    (.writeBytes dst contents)
                    log-state)
        ::K/int-64 (do
                     (.writeLong dst v)
                     log-state)
        ::K/zeroes (let [n (::K/length dscr)
                         log-state (log/debug log-state
                                              ::do-composition-reduction
                                              "Zeroing"
                                              {::field k
                                               ::K/length n
                                               ::destination dst
                                               ::description (util/pretty dscr)})]
                     (.writeZero dst n)
                     log-state)
        (throw (ex-info "No matching clause" dscr)))
      (catch RuntimeException ex
        (throw (ex-info ""
                        {::problem ex
                         ::cause cnvrtr
                         ::field k
                         ::description dscr
                         ::source-value v}))))))

(s/fdef calculate-length
  :args (s/cat :log-state ::weald/state
               :description ::templates/field)
  :ret (s/keys :req [::weald/state]
               :opt [::K/length]))
(defn calculate-length
  [log-state
   {cnvrtr ::K/type
    :as dscr}]
  (try
    (let [result
          (case cnvrtr
            ::K/bytes (::K/length dscr)
            ::K/const (count (::K/contents dscr))
            ::K/int-64 8
            ::K/zeroes (::K/length dscr))]
      {::weald/state log-state
       ::K/length result})
    (catch IllegalArgumentException ex
      {::weald/state
       (log/exception log-state
                      ex
                      ::calculate-length
                      ""
                      {::problem dscr})})))

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
               :tmplt ::templates/pattern
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
    log-state ::weald/state
    :as acc}
   k]
  (let [dscr (k tmplt)
        {field-length ::K/length
         log-state ::weald/state} (calculate-length log-state dscr)
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
           ::index (+ index (calculate-length dscr))
           ::weald/state log-state)))

(s/fdef read-byte-array
  :args (s/cat :dscr ::templates/pattern
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
                     :tmplt ::templates/pattern
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

(s/fdef do-compose
  :args (s/cat :log-state ::weald/state
               :tmplt ::templates/pattern
               :fields ::templates/field-names
               :dst ::specs/byte-buf))
(defn do-compose
  ;; Nothing outside unit tests calls this.
  ;; It's possible that's a mistake and huge
  ;; performance hit.
  ;; Keep this around until I get a chance to
  ;; FIXME: profile this.
  "compose destructively. If you need that optimization"
  ^ByteBuf [log-state tmplt fields ^ByteBuf dst]
  ;; Q: How much do I gain by supplying dst?
  ;; A: It does let callers reuse the buffer, which
  ;; will definitely help with GC pressure.
  ;; Yes, it's premature optimization. And how
  ;; often will this get used?
  (reduce (fn [log-state k]
            (do-composition-reduction tmplt fields dst log-state k))
          log-state
          (keys tmplt)))

(s/fdef compose
  :args (s/cat :log-state ::weald/state
               :tmplt ::templates/pattern
               :fields ::templates/field-names)
  :ret (s/keys :req [::specs/byte-array ::weald/state]))
(defn compose
  "serialize a map into a ByteBuf"
  ;; TODO: This should really just return a [B
  ;; Or, at least, have an optional arity override that does
  ;; so. The value in making this change really depends on
  ;; how many callers need to do that vs. the ones that
  ;; actually take advantage of the ByteBuf.
  ;; TODO: Look into this.
  ^ByteBuf [log-state tmplt fields]
  ;; Q: Is it worth precalculating the size?
  (let [size (reduce + (map calculate-length (vals tmplt)))
        ;; Callers need to .release this buffer.
        ;; TODO: Switch to returning a byte-array (vector?)
        ;; instead.
        dst (Unpooled/buffer size)
        log-state (reduce
                   (fn [log-state k]
                     (do-composition-reduction tmplt fields dst log-state k))
                   log-state
                   (keys tmplt))]
    {::specs/byte-array (b-s/convert dst specs/byte-array-type)
     ::weald/state log-state}))

(s/fdef decompose
        :args (s/cat :template ::templates/pattern
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
  :args (s/cat :tmplt ::templates/pattern
               :src bytes?)
  :ret (s/keys :req [::decomposed
                     ::weald/state]))
(defn decompose-array
  "Read a C-style struct from a byte array into a map, based on template"
  [log-state tmplt src]
  (let [src (bytes src)
        result (reduce
                (fn [acc k]
                  (decompose-array-field src tmplt acc k))
                {::index 0
                 ::weald/state log-state}
                (keys tmplt))]
    {::decomposed (dissoc result ::index ::weald/state)
     ::weald/state (::weald/state result)}))
