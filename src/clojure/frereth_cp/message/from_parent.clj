(ns frereth-cp.message.from-parent
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.marshall :as marshall]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared])
  (:import [io.netty.buffer ByteBuf Unpooled]
           java.nio.ByteOrder))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::delta-k nat-int?)
(s/def ::max-k nat-int?)
(s/def ::min-k nat-int?)
;; Q: What is this, really?
(s/def ::max-rcvd nat-int?)
(s/def ::start-stop-details (s/keys :req [::min-k
                                          ::max-k
                                          ::delta-k
                                          ::max-rcvd]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Implementation

(s/fdef deserialize
        :args (s/cat :buf bytes?)
        :ret ::specs/packet)
(defn deserialize
  "Convert a raw message block into a message structure"
  ;; Important: there may still be overlap with previously read bytes!
  ;; (but that's a problem for downstream)
  [^bytes buf]
  {:pre [buf]}
  (let [;; Q: How much of a performance hit do I take by
        ;; wrapping this?
        ;; Using decompose is nice and convenient here, but
        ;; I can definitely see it cause problems.
        ;; TODO: Benchmark!
        buf' (.order (Unpooled/wrappedBuffer buf)
                     ByteOrder/LITTLE_ENDIAN)
        header (shared/decompose marshall/message-header-dscr buf')
        D (::specs/size-and-flags header)
        D' D
        SF (bit-and D (bit-or K/normal-eof K/error-eof))
        D (- D SF)
        zero-padding-count (- (.readableBytes buf')
                              D')]
    (when (nat-int? zero-padding-count)
      (when (pos? zero-padding-count)
        (.skipBytes buf' zero-padding-count))
      ;; 3 approaches seem to make sense here:
      ;; 1. Create a copy of buf and release the original,
      ;; trying to be memory efficient.
      (comment
        (let [result (assoc header ::specs/buf (.copy buf'))]
          (.release buf')
          result))
      ;; 2. Avoid the time overhead of making the copy.
      ;; If we don't release this very quickly, something
      ;; bigger/more important is drastically wrong.
      ;; TODO: Try out this potential compromise:
      ;; (preliminary testing suggests that it should work)
      (comment
        (.discardReadBytes buf')
        (.capacity buf' D'))
      ;; 3. Just do these manipulations on the incoming
      ;; byte-array (vector?) and avoid the overhead (?)
      ;; of adding a ByteBuf to the mix

      ;; Going with option 2 for now
      (assoc header ::specs/buf buf'))))

(s/fdef calculate-start-stop-bytes
        :args (s/cat :state ::specs/state
                     :packet ::specs/packet)
        :ret ::start-stop-details)
(defn calculate-start-stop-bytes
  "calculate start/stop bytes (lines 562-574)"
  [{{:keys [::specs/receive-bytes
            ::specs/receive-written]
     :as incoming} ::specs/incoming
    :as state}
   ;; Q: Isn't this a byte array now?
   {^ByteBuf incoming-buf ::specs/buf
    D ::specs/size-and-flags
    start-byte ::specs/start-byte
    :as packet}]
  (assert D (str "Missing ::specs/size-and-flags among\n" (keys packet)))
  (log/debug "D ==" D "\nIncoming State:\n" incoming)
  ;; If we're re-receiving bytes...well, the reference
  ;; implementation just discards them.
  ;; It would be safer to verify that the overlapping bits
  ;; match, since that sort of thing is an important attack
  ;; vector.
  ;; Then again, we've already authenticated the message and
  ;; verified its signature. If an attacker can break that,
  ;; doing extra work here isn't going to protect anything.
  ;; We're back to the "DJB thought it was safe" appeal to
  ;; authority.
  ;; So stick with the current approach for now.
  (comment (throw (RuntimeException. "What's up with starting-point?")))
  (let [starting-point (.readerIndex incoming-buf)
        ;; For from-parent-test/check-start-stop-calculation:
        ;; This is starting at position 112.
        ;; Then 113.
        ;; Then 112 again.
        ;; Q: What gives?
        D' D
        SF (bit-and D (bit-or K/normal-eof K/error-eof))
        D (- D SF)
        message-length (.readableBytes incoming-buf)]
    (log/debug (str "Setting up initial read from position " starting-point)
               ": " D' " bytes")
    (if (and (<= D K/k-1)
             ;; In the reference implementation,
             ;; len = 16 * (unsigned long long) messagelen[pos]
             ;; (assigned at line 443)
             ;; This next check looks like it really
             ;; amounts to "have we read all the bytes
             ;; in this block from the parent pipe?"
             ;; It doesn't make a lot of sense in this
             ;; approach
             ;; Except that it's a sanity check on the
             ;; extraction code.
             (= D message-length))
      ;; start-byte and stop-byte are really addresses in the
      ;; message stream
      (let [stop-byte (+ D start-byte)]
        (log/debug "Starting with ACK from" start-byte "to" stop-byte)
        ;; Q: Why are we writing to receive-buf?
        ;; A: receive-buf is a circular buffer of bytes past the
        ;; receive-bytes counter which holds bytes that have not yet
        ;; been forwarded along to the child.
        ;; At least, that's the case in the reference implementation.
        ;; In this scenario where I've ditched that circular buffer,
        ;; it simply does not apply.
        ;; That does not make the decision to do that ditching correct.
        ;; However, I can probably move forward successfully with this
        ;; approach using a sorted-map (or possibly sorted-map-by)
        ;; acting as a priority queue.
        ;; Or the buddy queue that DJB recommended initially.
        ;; The key to this approach would be
        ;; 1) receive message from parent
        ;; 2) reduce of the buffer of received messages
        ;; 3) forwarding the completed stream blocks to the child
        ;; 4) finding a balance between
        ;;    a) calling that over and over
        ;;    b) memory copy churn
        ;; 5) Consolidating new incoming blocks
        ;; There's actually plenty of ripe fruit to pluck here.
        (comment (throw (RuntimeException. "And there's my bug")))
        (log/debug "receive-written:" receive-written
                   "\nstop-byte:" stop-byte
                   ;; We aren't using this.
                   ;; Big Q: Should we?
                   ;; A: Maybe. It would save some GC.
                   ;; "\nreceive-buf writable length:" (.writableBytes receive-buf)
                   )

        ;; of course, flow control would avoid this case -- DJB
        ;; Q: What does that mean? --JRG
        ;; Whatever it means:
        ;; Note that both stop-byte and receive-written are absolute
        ;; stream addresses. So we're just tossing messages for addresses
        ;; that are too far past the last portion of that stream that
        ;; we've passed along to the child.
        (when (<= stop-byte (+ receive-written K/recv-byte-buf-size))
          ;; 576-579: SF (StopFlag? deals w/ EOF)
          (let [receive-eof (case SF
                              0 false
                              normal-eof ::specs/normal
                              error-eof ::specs/error)
                ;; Note that this needs to update the "global state" because
                ;; we've reached the end of the stream.
                receive-total-bytes (when receive-eof stop-byte)]
            ;; 581-588: copy incoming into receivebuf

            (let [min-k (max 0 (- receive-written start-byte))  ; drop bytes we've already written
                  ;; Address at the limit of our buffer size
                  max-rcvd (+ receive-written K/recv-byte-buf-size)
                  ^Long max-k (min D (- max-rcvd start-byte))
                  delta-k (- max-k min-k)]
              (assert (<= 0 max-k))
              (when (neg? delta-k)
                (throw (ex-info "stop-byte before start-byte"
                                {::max-k max-k
                                 ::min-k min-k
                                 ::D D
                                 ::max-rcvd max-rcvd
                                 ::start-byte start-byte
                                 ::receive-written receive-written})))

              {::min-k min-k
               ::max-k max-k
               ::delta-k delta-k
               ::max-rcvd max-rcvd
               ;; Yes, this might well be nil if there's no reason to "change"
               ;; the "global state".
               ;; This feels pretty hackish.
               ::receive-total-bytes receive-total-bytes}))))
      (do
        (log/warn (str "Too long message packet from parent. D == " D
                       "\nRemaining readable bytes: " message-length))
        ;; This needs to short-circuit.
        ;; Q: is there a better way to accomplish that?
        nil))))

(s/fdef extract-message!
        :args (s/cat :state ::specs/state
                     :receive-buf ::specs/buf)
        :ret ::specs/state)
(defn extract-message!
  "Lines 562-593"
  [{{:keys [::specs/receive-bytes]} ::specs/incoming
    :as state}
   {^ByteBuf incoming-buf ::specs/buf
    D ::specs/size-and-flags
    start-byte ::specs/start-byte
    :as packet}]
  {:pre [start-byte]}
  (when-let [calculated (calculate-start-stop-bytes state packet)]
    (let [{:keys [::delta-k
                  ::max-rcvd
                  ::min-k
                  ::receive-total-bytes]
           ^Long max-k ::max-k} calculated]
      (let [;; It's tempting to use a Pooled buffer here instead.
            ;; That temptation is wrong.
            ;; There's no good reason for this to be direct memory,
            ;; and "the JVM garbage collector...works OK for heap buffers,
            ;; but not direct buffers" (according to netty.io's wiki entry
            ;; about using it as a generic performance library).
            ;; It *is* tempting to retain the original direct
            ;; memory in which it arrived as long as possible. That approach
            ;; might make sense if I were using a JNI layer for encryption.
            ;; As it stands, we've already stomped all over the source
            ;; memory long before it got here.

            ;; Except that there's still Norman Mauer's advice
            ;; about the best practice to just always use a
            ;; Direct Pooled buffer.

            ;; Stack overflow answer directly from the man himself:
            ;; "using heap-buffers may make sense if you need to act
            ;; directly on the backing array. This is for example true
            ;; when you use deflater/inflater as it only acts on byte[].
            ;; For all other cases a direct buffer is prefered."

            ;; So, it's back to the "get it working correctly, then
            ;; profile" approach.

            ;; Be that as it may, this almost definitely needs to come
            ;; from a Pooled implementation.
            ;; OTOH, this is what we hand over to the child (at least
            ;; in theory).
            ;; For the sake of API ease, it should probably be a vector
            ;; of bytes.
            ;; Or, at worst, a Byte Array.
            ;; Unfortunately for that plan, gap buffer consolidation
            ;; is quite a bit easier if I just stick with the ByteBuf
            #_[output-buf (byte-array D)] ]
        ;; There are at least a couple of curve balls in the air right here:
        ;; 1. Only write bytes at stream addresses(?)
        ;;    (< receive-written where (+ receive-written receive-buf-size))

        ;; Q: Why haven't I converted incoming-buf to a vector of bytes?
        ;; Or even a byte-array?
        ;; Using a ByteBuf here doesn't make any sense.
        (when (pos? min-k)
          (.skipBytes incoming-buf min-k))
        (comment (.readBytes incoming-buf output-buf 0 max-k))
        ;; Q: Do I just want to release it, since I'm done with it?
        ;; Except that I may not be. If this read would have overflowed
        ;; the buffer, max-k would have kept us from reading.
        ;; Next Q: Is trying to limit that buffer here worth the
        ;; added complexity?
        ;; We're talking about 1-k max.
        ;; (assuming previous code did a sanity check for our buffer max)
        ;; Bigger Q: Shouldn't I just discard it completely?
        ;; A: Well, it depends.
        ;; Honestly, we should should just be making a slice
        ;; to avoid copying.
        (.discardSomeReadBytes incoming-buf)
        ;;          set the receivevalid flags
        ;; 2. Update the receive-valid flag associated with each byte as we go
        ;;    The receivevalid array is declared with this comment:
        ;;    1 for byte successfully received; XXX: use buddy structure to speed this up --DJB

        ;; 3. The array of receivevalid flags is used in the loop between lines
        ;;    589-593 to decide how much to increment receive-bytes.
        ;;    It's cleared on line 630, after we've written the bytes to the
        ;;    child pipe.
        ;; I'm fairly certain this is what that for loop amounts to
        (-> state
            (update-in [::specs/incoming ::specs/receive-bytes] + (min (- max-rcvd receive-bytes)
                                                                       (+ receive-bytes delta-k)))
            (update-in [::specs/incoming ::specs/receive-total-bytes]
                       (fn [cur]
                         ;; calculate-start-stop-bytes might have an override for this
                         (or receive-total-bytes
                             cur)))
            (update-in [::specs/incoming ::specs/gap-buffer]
                       assoc
                       ;; This needs to be the absolute stream position of the values that are left
                       [(+ start-byte min-k) (+ start-byte max-k)]
                       incoming-buf))))))

(s/fdef flag-acked-others!
        :args (s/cat :state ::specs/state
                     :packet ::specs/packet)
        :ret ::specs/state)
(defn flag-acked-others!
  "Lines 544-560"
  [state
   packet]
  (log/info "Top of flag-acked-others!" packet)
  (let [gaps (map (fn [[startfn stopfn]]
                    [(startfn packet) (stopfn packet)])
                  [[(constantly 0) ::specs/ack-length-1] ;  0-8
                   [::specs/ack-gap-1->2 ::specs/ack-length-2] ; 16-20
                   [::specs/ack-gap-2->3 ::specs/ack-length-3] ; 22-24
                   [::specs/ack-gap-3->4 ::specs/ack-length-4] ; 26-28
                   [::specs/ack-gap-4->5 ::specs/ack-length-5] ; 30-32
                   [::specs/ack-gap-5->6 ::specs/ack-length-6]])] ; 34-36
    (log/info "Gaps:" gaps "\nState:" state)
    (->
     (reduce (fn [{:keys [::stop-byte]
                   :as state}
                  [start stop]]
               ;; Note that this is based on absolute stream addresses
               (let [start-byte (+ stop-byte start)
                     stop-byte (+ start-byte stop)]
                 ;; This seems like an awkward way to get state modified to
                 ;; adjust the return value.
                 ;; It actually fits perfectly, but it isn't as obvious as
                 ;; I'd like.
                 (assoc (help/mark-acknowledged! state start-byte stop-byte)
                              ::stop-byte
                              stop-byte)))
             (assoc state ::stop-byte 0)
             gaps)
     ;; Ditch the temp key we used to track the stop point
     (dissoc ::stop-byte))))

(s/fdef prep-send-ack
        :args (s/cat :state ::state
                     :msg-id (s/and int?
                                    pos?))
        :ret (s/nilable ::specs/buf))
(defn prep-send-ack
  "Build a ByteBuf to ACK the message we just received

  Lines 595-606"
  [{{:keys [::specs/receive-bytes
            ::specs/receive-eof
            ::specs/receive-total-bytes]} ::specs/incoming
    :as state}
   message-id]
  {:pre [receive-bytes
         (some? receive-eof)
         receive-total-bytes
         message-id]}
  ;; XXX: incorporate selective acknowledgments --DJB
  ;; never acknowledge a pure acknowledgment --DJB
  ;; I've seen at least one email pointing out that the
  ;; author (Matthew Dempsky...he's the only person I've
  ;; run across who's published any notes about
  ;; the messaging protocol) has a scenario where the
  ;; child just hangs, waiting for an ACK to the ACKs
  ;; it sends 4 times a second.
  (when (not= message-id 0)
    (log/debug "Building an ACK for message" message-id)
    ;; I'm concerned that I'm sending back gibberish.
    ;; DJB reuses the incoming message that we're preparing
    ;; to ACK, locked to 192 bytes.
    ;; It seems like it probably doesn't matter, since this
    ;; is purely an ACK, but I strongly suspect that I should
    ;; at least 0 it all out.
    ;; TODO: Get this from a pool.
    ;; TODO: Switch to using a byte array
    (let [send-buf (Unpooled/buffer (+ K/header-length
                                       192))]
      ;; XXX: delay acknowledgments  --DJB
      ;; 0 ID for pure ACK
      ;; Q: Would doing
      #_(.writeInt send-buf 0)
      ;; be slower?
      ;; It seems like making it explicit would be
      ;; more clear
      (.writerIndex send-buf 4)
      (.writeInt send-buf message-id)
      (.writeLong send-buf (if (and receive-eof
                                    (= receive-bytes receive-total-bytes))
                             (inc receive-bytes)
                             receive-bytes))
      send-buf)))

(defn send-ack!
  "Write ACK buffer back to parent

Line 608"
  [{{:keys [::specs/->parent]} ::specs/outgoing
    :as state}
   ^ByteBuf send-buf]
  (if send-buf
    (do
      (when-not ->parent
        (throw (ex-info "Missing ->parent callback"
                        {::callbacks (::specs/callbacks state)
                         ::available-keys (keys state)})))
      (->parent send-buf))
    (log/debug "No bytes to send...presumably we just processed a pure ACK")))

(s/fdef handle-comprehensible-message!
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
(defn handle-comprehensible-message!
  "handle this message if it's comprehensible: (DJB)

  This seems like the interesting part.
  lines 444-609"
  [{{^bytes parent->buffer ::specs/parent->buffer} ::specs/incoming
    ;; It seems really strange to have anything that involves
    ;; the outgoing blocks in here.
    ;; But there's an excellent chance that the incoming message
    ;; is going to ACK some or all of what we have pending in here.
    {:keys [::specs/blocks]} ::specs/outgoing
    :as state}]
  ;; Q: Do I want the first message here or the last?
  ;; Top A: There should be only one entry.
  ;; That isn't a realistic expectation, though.
  (let [len (count parent->buffer)]
    (if (and (>= len K/min-msg-len)
             (<= len K/max-msg-len))
      ;; TODO: Time this. See whether it's worth combining these calls
      ;;  using either some version of comp or as-> (or possibly
      ;; transducers?)
      (let [packet (deserialize parent->buffer)
            ack-id (::specs/acked-message packet)
            ;; Note that there's something terribly wrong if we
            ;; have multiple blocks with the same message ID.
            ;; Q: Isn't there?
            acked-blocks (filter #(= ack-id (::specs/message-id %))
                                 blocks)
            flagged (-> (reduce flow-control/update-statistics
                                ;; Remove parent->buffer.
                                ;; It's been parsed into packet
                                (update state ::specs/incoming
                                        dissoc
                                       ::specs/parent->buffer)
                                acked-blocks)
                        ;; That takes us down to line 544
                        (flag-acked-others! packet))
            extracted (extract-message! flagged packet)]
        (log/debug "extracted:" extracted)
        (if extracted
          (or
           (let [msg-id (::specs/message-id packet)]
             (when-not msg-id
               ;; Note that 0 is legal: that's a pure ACK.
               ;; We just have to have something.
               ;; (This comment is because I have to keep remembering
               ;; how truthiness works in C)
               (throw (ex-info "Missing the incoming message-id"
                               extracted)))
             (when-let [ack-msg (prep-send-ack extracted msg-id)]
               (log/debug "Have an ACK to send back")
               ;; since this is called for side-effects, ignore the
               ;; return value.
               (send-ack! extracted ack-msg)
               (update extracted
                       ::specs/incoming
                       dissoc
                       ::specs/packet)))
           extracted)
          flagged))
      (do
        (log/warn "Illegal incoming message length:" len)
        nil))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef try-processing-message!
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
(defn try-processing-message!
  "436-613: try processing a message: --DJB"
  ;; Q: Why is this in the public section?
  [{{:keys [::specs/->child-buffer
            ::specs/parent->buffer
            ::specs/receive-bytes
            ::specs/receive-written]} ::specs/incoming
    :as state}]
  (let [child-buffer-count (count ->child-buffer)]
    (log/debug "from-parent/try-processing-message"
               "\nchild-buffer-count:" child-buffer-count
               "\nparent->buffer count:" (count parent->buffer)
               "\nreceive-written:" receive-written
               "\nreceive-bytes:" receive-bytes)
    (if (or parent->buffer  ; new incoming message?
            ;; any previously buffered incoming messages to finish
            ;; processing?
            (not= 0 child-buffer-count)
            ;; This next check includes an &&
            ;; to verify that tochild is > 0 (I'm
            ;; pretty sure that's just verifying that
            ;; the pipe is open)
            ;; I think the point of this next check
            ;; is back-pressure:
            ;; If we have pending bytes from the parent that have not
            ;; been written to the child, don't add more.
            ;; Note that there's really an && close connected
            ;; to this check: it quits mattering once the tochild
            ;; pipe has been closed.
            (>= receive-written receive-bytes))
      ;; 440: sets maxblocklen=1024
      ;; Q: Why was it ever 512?
      ;; Guess: for initial Message part of Initiate packet
      (let [state' (assoc-in state [::specs/incoming ::specs/max-byte-length] K/k-1)]
        (log/debug "Handling incoming message, if it's comprehensible")
        (handle-comprehensible-message! state'))
      (do
        ;; Nothing to do.
        (log/debug "False alarm. Nothing to be done")
        state))))
