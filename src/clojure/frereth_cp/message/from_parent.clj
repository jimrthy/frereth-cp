(ns frereth-cp.message.from-parent
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared :as shared])
  (:import [io.netty.buffer ByteBuf Unpooled]
           java.nio.ByteOrder))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Implementation

(s/fdef deserialize
        :args (s/cat :buf ::specs/buf)
        :ret ::specs/packet)
(defn deserialize
  "Convert a raw message block into a message structure"
  ;; Important: there may still be overlap with previously read bytes!
  ;; (but that's a problem for downstream)
  [^ByteBuf buf]
  {:pre [buf]}
  (let [buf (.order buf ByteOrder/LITTLE_ENDIAN)
        header (shared/decompose K/message-header-dscr buf)
        D (::specs/size-and-flags header)
        D' D
        SF (bit-and D (bit-or K/normal-eof K/error-eof))
        D (- D SF)
        zero-padding-count (- (.readableBytes buf)
                              D')]
    (when (nat-int? zero-padding-count)
      (when (pos? zero-padding-count)
        (.skipBytes buf zero-padding-count))
      ;; 2 approaches seem to make sense here:
      ;; 1. Create a copy of buf and release the original,
      ;; trying to be memory efficient.
      (comment
        (let [result (assoc header ::specs/buf (.copy buf))]
          (.release buf)
          result))
      ;; 2. Avoid the time overhead of making the copy.
      ;; If we don't release this very quickly, something
      ;; bigger/more important is drastically wrong.
      ;; Going with option 2 for now
      ;; TODO: Try out this potential compromise:
      ;; (preliminary testing suggests that it should work)
      (comment
        (.discardReadBytes buf)
        (.capacity buf D'))
      (assoc header ::specs/buf buf))))

(defn calculate-start-stop-bytes
  "calculate start/stop bytes (lines 562-574)"
  [{:keys [::specs/receive-bytes
           ::specs/receive-written]
    :as state}
   {^ByteBuf receive-buf ::specs/buf
    D ::specs/size-and-flags
    start-byte ::start-byte
    :as packet}]
  ;; If we've already received bytes...well, the reference
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
  (let [starting-point (.readerIndex receive-buf)
        D' D
        SF (bit-and D (bit-or K/normal-eof K/error-eof))
        D (- D SF)
        message-length (.readableBytes receive-buf)]
    (log/debug (str "Initial read from position " starting-point)
               ":\n" D')
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
        ;; of course, flow control would avoid this case -- DJB
        ;; Q: What does that mean? --JRG
        ;; Q: Why are we writing to receive-buf?
        ;; A: receive-buf is a circular buffer of bytes past the
        ;; receive-bytes counter which holds bytes that have not yet
        ;; been forwarded along to the child.
        (when (<= stop-byte (+ receive-written (.writableBytes receive-buf)))
          ;; 576-579: SF (StopFlag? deals w/ EOF)
          (let [receive-eof (case SF
                              0 false
                              normal-eof ::specs/normal
                              error-eof ::specs/error)
                receive-total-bytes (if (not= SF 0)
                                      stop-byte)]
            ;; 581-588: copy incoming into receivebuf
            (let [min-k (max 0 (- receive-written start-byte))  ; drop bytes we've already written
                  ;; Address at the limit of our buffer size
                  max-rcvd (+ receive-written K/recv-byte-buf-size)
                  ^Long max-k (min D (- max-rcvd start-byte))
                  delta-k (- max-k min-k)]
              (assert (<= 0 max-k))
              (assert (<= 0 delta-k))

              {::min-k min-k
               ::max-k max-k
               ::delta-k delta-k
               ::max-rcvd max-rcvd}))))
      (do
        (log/warn (str "Gibberish Message packet from parent. D == " D
                       "\nRemaining readable bytes: " message-length))
        ;; This needs to short-circuit.
        ;; Q: is there a better way to accomplish that?
        nil))))

(s/fdef extract-message
        :args (s/cat :state ::specs/state
                     :receive-buf ::specs/buf)
        :ret ::specs/state)
(defn extract-message
  "Lines 562-593"
  [{:keys [::specs/receive-bytes]
    :as state}
   {^ByteBuf receive-buf ::specs/buf
    D ::specs/size-and-flags
    start-byte ::start-byte
    :as packet}]
  (when-let [{:keys [::delta-k
                     ::max-rcvd
                     ::min-k]
              ^Long max-k ::max-k} (calculate-start-stop-bytes state packet)]
    (let [;; It's tempting to use a Pooled buffer here instead.
          ;; That temptation is wrong.
          ;; There's no good reason for this to be direct memory,
          ;; and "the JVM garbage collector...works OK for heap buffers,
          ;; but not direct buffers" (according to netty.io's wiki entry
          ;; about using it as a generic performance library).
          ;; It *is* tempting to retain the original direct
          ;; memory in which it arrived as long as possible. That approach
          ;; would probably make a lot more sense if I were using a JNI
          ;; layer for encryption.
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
          output-buf (Unpooled/buffer D)]
      ;;; There are at least a couple of curve balls in the air right here:
      ;; 1. Only write bytes at stream addresses(?)
      ;;    (< receive-written where (+ receive-written receive-buf-size))

      (when (pos? min-k)
        (.skipBytes receive-buf min-k))
      (.readBytes receive-buf output-buf max-k)
      ;; Q: Do I just want to release it, since I'm done with it?
      ;; Except that I may not be. If this read would have overflowed
      ;; the buffer, max-k would have kept us from reading.
      ;; Next Q: Is trying to limit that buffer here worth the
      ;; added complexity?
      ;; We're talking about 1-k max.
      ;; (assuming previous code did a sanity check for our buffer max)
      ;; Bigger Q: Shouldn't I just discard it completely?
      ;; A: Well, it depends.
      ;; Honestly, we should should just be making a slice or
      ;; duplicate to avoid copying.
      (.discardSomeReadBytes receive-buf)
      ;; TODO: Something with output-buf

      ;;          set the receivevalid flags
      ;; 2. Update the receive-valid flag associated with each byte as we go
      ;;    The receivevalid array is declared with this comment:
      ;;    1 for byte successfully received; XXX: use buddy structure to speed this up --DJB

      ;; 3. The array of receivevalid flags is used in the loop between lines
      ;;    589-593 to decide how much to increment receive-bytes.
      ;;    It's cleared on line 630, after we've written the bytes to the
      ;;    child pipe.
      ;; I'm fairly certain this is what that for loop amounts to

      (throw (RuntimeException. "Q: What is to-child expecting in terms of output-buffer?"))
      (update state ::receive-bytes + (min (- max-rcvd receive-bytes)
                                           (+ receive-bytes delta-k))))))

(s/fdef flag-acked-others!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn flag-acked-others!
  "Lines 544-560"
  [{:keys [::specs/->child-buffer]
    :as state}
   packet]
  (let [indexes (map (fn [[startfn stopfn]]
                       [(startfn packet) (stopfn packet)])
                     [[(constantly 0) ::specs/ack-length-1]            ;  0-8
                      [::specs/ack-gap-1->2 ::specs/ack-length-2]      ; 16-20
                      [::specs/ack-gap-2->3 ::specs/ack-length-3]      ; 22-24
                      [::specs/ack-gap-3->4 ::specs/ack-length-4]      ; 26-28
                      [::specs/ack-gap-4->5 ::specs/ack-length-5]      ; 30-32
                      [::specs/ack-gap-5->6 ::specs/ack-length-6]])]   ; 34-36
    (dissoc
     (reduce (fn [{:keys [::stop-byte]
                   :as state}
                  [start stop]]
               ;; This can't be right. Needs to be based on absolute
               ;; stream addresses.
               ;; Q: Doesn't it?
               ;; A: Yes, definitely
               (let [start-byte (+ stop-byte start)
                     stop-byte (+ start-byte stop)]
                 (assoc
                  (help/mark-acknowledged! state start-byte stop-byte)
                  ::stop-byte stop-byte)))
             (assoc state ::stop-byte 0)
             indexes)
     ::start-byte)))

(defn prep-send-ack
  ;; Q: What should be calling this?
  ;; A: Right after extract-message, assuming there's
  ;; a message to ACK
  "Build a ByteBuf to ACK the message we just received

  Lines 595-606"
  [{:keys [::specs/current-block-cursor
           ::specs/receive-bytes
           ::specs/receive-eof
           ::specs/receive-total-bytes]
    ^ByteBuf buf ::specs/send-buf
    :as state}
   message-id]
  (when-not receive-bytes
    (throw (ex-info "Missing receive-bytes"
                    {::among (keys state)})))
  ;; never acknowledge a pure acknowledgment --DJB
  ;; I've seen at least one email pointing out that the
  ;; author (Matthew Dempsky...he's the only person I've
  ;; run across who's published any notes about
  ;; the messaging protocol) has a scenario where the
  ;; child just hangs, waiting for an ACK to the ACKs
  ;; it sends 4 times a second.
  (if (not= message-id 0)
    (let [send-buf (Unpooled/buffer K/send-byte-buf-size)
          u 192]
      ;; XXX: delay acknowledgments  --DJB
      (.writeLong send-buf (quot u 16))
      (.writeInt send-buf message-id)
      (.writeLong send-buf (if (and receive-eof
                                    (= receive-bytes receive-total-bytes))
                             (inc receive-bytes)
                             receive-bytes))
      (assoc state ::specs/send-buf send-buf))
    ;; XXX: incorporate selective acknowledgments --DJB
    state))

(defn send-ack!
  "Write ACK buffer back to parent

Line 608"
  [{{:keys [::specs/->parent]} ::specs/callbacks
    ^ByteBuf send-buf ::specs/send-buf
    :as state}]
  (if send-buf
    (do
      (when-not ->parent
        (throw (ex-info "Missing ->parent callback"
                        {::callbacks (::specs/callbacks state)
                         ::available-keys (keys state)})))
      (->parent send-buf))
    (log/debug "No bytes to send...presumably we just processed a pure ACK")))

(s/fdef handle-comprehensible-message
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
(defn handle-comprehensible-message
  "handle this message if it's comprehensible: (DJB)

  This seems like the interesting part.
  lines 444-609"
  [{:keys [::specs/blocks
           ::specs/->child-buffer]
    :as state}]
  ;; Q: Do I want the first message here or the last?
  ;; Top A: There should be only one entry in child-buffer
  (let [^ByteBuf msg (first ->child-buffer)
        len (.readableBytes msg)]
    (when (< 1 (count ->child-buffer))
      ;; TODO: Keep this from happening.
      (log/warn "Multiple entries in child-buffer. This seems wrong."))
    (when (and (>= len K/min-msg-len)
               (<= len K/max-msg-len))
      (let [packet (deserialize msg)
            ack-id (::specs/acked-message packet)
            ;; Note that there's something terribly wrong if we
            ;; have multiple blocks with the same message ID.
            ;; Q: Isn't there?
            acked-blocks (filter #(= ack-id (::specs/message-id %))
                                 blocks)
            flagged (-> (reduce flow-control/update-statistics state acked-blocks)
                        ;; That takes us down to line 544
                        (partial flag-acked-others! packet))
            ;; TODO: Combine these calls using either some version of comp
            ;; or ->>
            extracted (extract-message flagged packet)]
        (if extracted
          (let [msg-id (get-in extracted [::packet ::message-id])]
            ;; Important detail that I haven't seen documented
            ;; anywhere: message ID 0 is not legal.
            (if (not= 0 msg-id)
              (if-let [ack-prepped (prep-send-ack extracted)]
                (do
                  (send-ack! ack-prepped)
                  (dissoc ack-prepped ::specs/send-buf))
                extracted)
              extracted))
          flagged)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef try-processing-message
        :args (s/cat :state ::specs/state)
        :ret (s/nilable ::specs/state))
(defn try-processing-message
  "436-614: try processing a message: --DJB"
  [{:keys [::specs/->child-buffer
           ::specs/receive-bytes
           ::specs/receive-written]
    :as state}]
  (let [child-buffer-count (count ->child-buffer)]
    (log/debug "from-parent/try-processing-message"
               "\nchild-buffer-count:" child-buffer-count
               "\nreceive-written:" receive-written
               "\nreceive-bytes:" receive-bytes)
    (if-not (or (= 0 child-buffer-count)  ; any incoming messages to process?
                ;; This next check includes an &&
                ;; to verify that tochild is > 0 (I'm
                ;; pretty sure that's just verifying that
                ;; it's open)
                ;; I think the point of this next check
                ;; is back-pressure:
                ;; If we have pending bytes from the parent that have not
                ;; been written to the child, don't add more.
                (< receive-written receive-bytes))
      ;; 440: sets maxblocklen=1024
      ;; Q: Why was it ever 512?
      ;; Guess: for initial Message part of Initiate packet
      (let [state' (assoc state ::max-byte-length K/k-1)]
        (log/debug "Handling incoming message, if it's comprehensible")
        (handle-comprehensible-message state))
      state)))
