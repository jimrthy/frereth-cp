(ns frereth-cp.message.from-parent
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.flow-control :as flow-control]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs])
  (:import [io.netty.buffer ByteBuf Unpooled]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef extract-message
        :args (:state ::specs/state)
        :ret ::specs/state)
(defn extract-message
  "Lines 562-593"
  [{:keys [::specs/receive-bytes
           ::specs/receive-written
           ::specs/->child-buffer]
    :as state}]
  ;; 562-574: calculate start/stop bytes
  (let [^ByteBuf receive-buf (last ->child-buffer)
        starting-point (.readerIndex receive-buf)
        D (help/read-ushort receive-buf)
        D' D
        SF (bit-and D (bit-or K/normal-eof K/error-eof))
        D (- D SF)]
    (println (str "Initial read from position " starting-point)
             ":\n" D')
    (if (and (<= D 1024)
               ;; In the reference implementation,
               ;; len = 16 * (unsigned long long) messagelen[pos]
               ;; (assigned at line 443)
               ;; This next check looks like it really
               ;; amounts to "have we read all the bytes
               ;; in this block from the parent pipe?"
               ;; It doesn't make a lot of sense in this
               ;; approach
               #_(> (+ 48 D) len))
      (let [start-byte (help/read-ulong receive-buf)
            stop-byte (+ D start-byte)]
        ;; of course, flow control would avoid this case -- DJB
        ;; Q: What does that mean? --JRG
        (when (<= stop-byte (+ receive-written (.writableBytes receive-buf)))
          ;; 576-579: SF (StopFlag? deals w/ EOF)
          (let [receive-eof (case SF
                              0 false
                              normal-eof ::specs/normal
                              error-eof ::specs/error)
                receive-total-bytes (if (not= SF 0)
                                      stop-byte)
                ;; It's tempting to use a Pooled buffer here instead.
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
                output-buf (Unpooled/buffer D)]
            ;; 581-588: copy incoming into receivebuf
            (let [min-k (min 0 (- receive-written start-byte))  ; drop bytes we've already written
                  ;; Address at the limit of our buffer size
                  max-rcvd (+ receive-written K/recv-byte-buf-size)
                  ^Long max-k (min D (- max-rcvd start-byte))
                  delta-k (- max-k min-k)]
              (assert (<= 0 max-k))
              (assert (<= 0 delta-k))
              ;; There are at least a couple of curve balls in the air right here:
              ;; 1. Only write bytes at stream addresses(?)
              ;;    (< receive-written where (+ receive-written receive-buf-size))
              (.skipBytes receive-buf min-k)
              (.readBytes receive-buf output-buf max-k)
              ;; Q: Do I just want to release it, since I'm done with it?
              ;; Bigger Q: Shouldn't I just discard it completely?
              ;; And I've totally dropped the ball with output-buf.
              ;; The longer I look at this function, the fishier it smells.
              (.discardSomeReadBytes receive-buf)
              ;;          set the receivevalid flags
              ;; 2. Update the receive-valid flag associated with each byte as we go
              ;;    The receivevalid array is declared with this comment:
              ;;    1 for byte successfully received; XXX: use buddy structure to speed this up --DJB

              ;; 3. The array of receivevalid flags is used in the loop between lines
              ;;    589-593 to decide how much to increment receive-bytes.
              ;;    It's cleared on line 630, after we've written the bytes to the
              ;;    child pipe.
              ;; I'm fairly certain this is what that for loop amounts to
              (update state ::receive-bytes + (min (- max-rcvd receive-bytes)
                                                   (+ receive-bytes delta-k)))))))
      (do
        (log/warn (str "Gibberish Message packet from parent. D == " D))
        ;; This needs to short-circuit.
        ;; Q: is there a better way to accomplish that than just returning nil?
        state))))

(s/fdef flag-acked-others!
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn flag-acked-others!
  "Lines 544-560"
  [{:keys [::specs/->child-buffer]
    :as state}]
  (let [receive-buf (last ->child-buffer)]
    (assert receive-buf (str "Missing receive-buf among\n" (keys state)))
    (let [indexes (map (fn [[startfn stopfn]]
                         [(startfn receive-buf) (stopfn receive-buf)])
                       [[(constantly 0) help/read-ulong]   ;  0-8
                        [help/read-uint help/read-ushort]       ; 16-20
                        [help/read-ushort help/read-ushort]     ; 22-24
                        [help/read-ushort help/read-ushort]     ; 26-28
                        [help/read-ushort help/read-ushort]     ; 30-32
                        [help/read-ushort help/read-ushort]])]   ; 34-36
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
       ::start-byte))))

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
  (let [^ByteBuf msg (first ->child-buffer)
        len (.readableBytes msg)]
    (when (and (>= len K/min-msg-len)
               (<= len K/max-msg-len))
      (let [])
      ;; The problem with this idea is that it makes flag-acked-others
      ;; noticeably messier.
      ;; And there's no way to know the length of the message block vs. the padding
      ;; until we've read the length field.
      ;; So, it's doable. But I'd really need to add something like function handling
      ;; to fields to update the template after a field's been processed.
      ;; That's actually very tempting, but it isn't going to happen tonight.
      ;; TODO: Think about this some more.
      (comment (throw (RuntimeException. "Just decompose the message here and now")))
      (let [msg-id (help/read-uint msg) ;; won't need this (until later?), but need to update read-index anyway
            ack-id (help/read-uint msg)
            ;; Note that there's something terribly wrong if we
            ;; have multiple blocks with the same message ID.
            ;; Q: Isn't there?
            acked-blocks (filter #(= ack-id (::message-id %))
                                 blocks)
            flagged (-> (reduce flow-control/update-statistics state acked-blocks)
                          ;; That takes us down to line 544
                          flag-acked-others!)
            extracted (extract-message flagged)]
        (if extracted
          (do
            (send-ack! state)
            (dissoc extracted ::specs/send-buf))
          flagged)))))

(defn prep-send-ack
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
  (if-not (or (= 0 (count ->child-buffer))  ; any incoming messages to process?
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
      (handle-comprehensible-message state))
    state))
