(ns frereth-cp.message.flow-control
  "Cope with flow-control algorithms"
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.crypto :as crypto]
            [frereth-cp.shared.logging :as log2]
            [frereth-cp.util :as utils]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef recalc-rtt-average
        :args (s/cat :state ::specs/state
                     :rtt ::specs/rtt)
        :ret ::specs/state)
(defn calculate-base-rtt-averages
  "Lines 460-466"
  [{{:keys [::specs/rtt-average]} ::specs/flow-control
    :keys [::specs/recent]
    :as state}
   ackd-time]
  (let [rtt (- recent ackd-time)]
    (when (< 0 rtt)
      ;; I'm getting into scenarios with negative RTT, which
      ;; seems to have something to do with math overflow
      ;; warnings. That seems to be breaking things.
      ;; We should have set the block time when we first
      ;; spotted it. By contrast, recent should have
      ;; been set later, when the block was handed over
      ;; to the ioloop.
      ;; Note that assertions here just get swallowed
      ;; silently.
      (throw (ex-info "ACK arrived before recent"
                      {::specs/recent recent
                       ::ackd-time ackd-time
                       ::delta rtt})))
    (if (= 0 rtt-average)
      (update state
              ::specs/flow-control
              (fn [s]
                (assoc s
                       ::specs/n-sec-per-block rtt
                       ::specs/rtt rtt
                       ::specs/rtt-average rtt
                       ::specs/rtt-deviation (quot rtt 2)
                       ::specs/rtt-highwater rtt
                       ::specs/rtt-lowwater rtt)))
      state)))
(comment
  (let [times {::specs/recent 1515989075638
               ::ackd-time 2024584666631859}]
    (- (::specs/recent times) (::ackd-time times)))
  1515989075638)

(s/fdef jacobson-adjust-block-time
        :args (s/cat :n-sec-per-block ::specs/n-sec-per-block)
        :ret ::specs/n-sec-per-block)
(defn jacobson-adjust-block-time
  "Lines 496-509"
  [n-sec-per-block]
  (let [result
        (if (> n-sec-per-block K/k-128)
          ;; DJB had this to say.
          ;; As 4 separate comments.
          ;; additive increase: adjust 1/N by a constant c
          ;; rtt-fair additive increase: adjust 1/N by a constant c every nanosecond
          ;; approximation: adjust 1/N by cN every N nanoseconds
          ;; i.e., N <- 1/(1/N + cN) = N/(1 + cN^2) every N nanoseconds
          (if (< n-sec-per-block K/m-16)
            (let [u (quot n-sec-per-block K/k-128)]
              (- n-sec-per-block (* u u u)))
            (let [d (double n-sec-per-block)]
              ;; TODO: figure out the meaning behind this magic
              ;; formulation
              (long (/ d (inc (/ (* d d) 2251799813685248.0))))))
          n-sec-per-block)]
    (when-not (pos? result)
      ;; There's an important detail here for my current debugging
      ;; woes:
      ;; If I throw this exception erroneously (I had the logic
      ;; backwards, throwing when result was positive), then my
      ;; handshake test passes.
      (throw (ex-info "n-sec-per-block went negative"
                      {::specs/n-sec-per-block n-sec-per-block
                       ::adjusted-to result
                       ::u (quot n-sec-per-block K/k-128)})))
    (throw (RuntimeException. "Start back here"))
    result))

(s/fdef adjust-rtt-phase
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn adjust-rtt-phase
  "Lines 511-521"
  [{:keys [::specs/recent]
    {:keys [::specs/n-sec-per-block
            ::specs/rtt-phase
            ::specs/rtt-seen-older-high
            ::specs/rtt-seen-older-low]} ::specs/flow-control
    :as state}]
  (if rtt-phase
    (if rtt-seen-older-high
      (update state (fn [s]
                      (assoc s
                             ::specs/rtt-phase true
                             ::specs/last-edge recent
                             ::specs/n-sec-per-block (+ n-sec-per-block
                                                        (crypto/random-mod (quot n-sec-per-block 4))))))
      state)
    (if rtt-seen-older-low
      (assoc-in state [::specs/flow-control ::specs/rtt-phase] false)
      state)))
(comment
  (crypto/random-mod (quot 1000000000 4))
  (crypto/random-mod 4))

(defn possibly-adjust-speed
  [{:keys [::specs/recent]
    {:keys [::specs/last-edge
            ::specs/last-speed-adjustment
            ::specs/n-sec-per-block
            ::specs/rtt-seen-recent-high
            ::specs/rtt-seen-recent-low]} ::specs/flow-control
    :as state}]
  ;; Lines 488-527
  (if (>= recent (+ last-speed-adjustment (* 16 n-sec-per-block)))
    (let [n-sec-per-block (if (> (- recent last-speed-adjustment) K/secs-10)
                            (+ K/secs-1 (crypto/random-mod (quot K/sec->n-sec 8)))
                            n-sec-per-block)
          n-sec-per-block (jacobson-adjust-block-time n-sec-per-block)
          ;; adjust-rtt-phase depends on this
          state (assoc-in state [::specs/flow-control ::specs/n-sec-per-block] n-sec-per-block)
          ;; adjust-rtt-phase does not modify rtt-seen-recent-high/low.
          ;; Q: Should it?
          {{:keys [::specs/rtt-seen-recent-high ::specs/rtt-seen-recent-low]} ::specs/flow-control
           :as state} (adjust-rtt-phase state)]
      (update state
              ::specs/flow-control
              (fn [cur]
                (assoc cur
                       ::specs/last-speed-adjustment recent
                       ::specs/seen-older-high rtt-seen-recent-high
                       ::specs/seen-older-low rtt-seen-recent-low
                       ;; We're throwing away the values we just calculated.
                       ;; Well, except that they got moved into seen-older-*
                       ;; Saving these booleans seems pointless.
                       ::specs/seen-recent-high false
                       ::specs/seen-recent-low false))))
    state))

(s/fdef jacobson's-retransmission-timeout
        :args (s/cat :state ::specs/state
                     :block ::specs/block)
        :ret ::specs/state)
(defn jacobson's-retransmission-timeout
  "Jacobson's retransmission timeout calculation: --DJB

  I'm lumping lines 467-527 into here, even though I haven't
  seen the actual paper describing the algorithm. This is the
  basic algorithm that TCP uses pretty much everywhere. -- JRG"
  [{:keys [::specs/recent]
    {:keys [::specs/last-doubling
            ::specs/last-edge
            ::specs/last-speed-adjustment
            ::specs/n-sec-per-block
            ::specs/rtt
            ::specs/rtt-average
            ::specs/rtt-deviation
            ::specs/rtt-highwater
            ::specs/rtt-lowwater
            ::specs/rtt-seen-recent-high
            ::specs/rtt-seen-recent-low
            ::specs/rtt-timeout]} ::specs/flow-control
    :as state}
   {block-send-time ::specs/time
    :as block}]
  (let [rtt-delta (- rtt rtt-average)
        ;; I'm seeing this drop below 0.
        ;; The math that leads to that *is* plausible.
        ;; But...does it ever make any sense?
        rtt-average (+ rtt-average (/ rtt-delta 8.0))
        rtt-delta (if (> 0 rtt-delta)
                    (- rtt-delta)
                    rtt-delta)
        rtt-delta (- rtt-delta rtt-deviation)
        rtt-deviation (+ rtt-deviation (/ rtt-delta 4.0))
        rtt-timeout (+ rtt-average (* 4 rtt-deviation))
        ;; adjust for delayed acks with anti-spiking: --DJB
        rtt-timeout (+ rtt-timeout (* 8 n-sec-per-block))

        ;; recognizing top and bottom of congestion cycle:  --DJB
        rtt-delta (- rtt rtt-highwater)
        rtt-highwater (+ rtt-highwater (/ rtt-delta K/k-1f))
        rtt-delta (- rtt rtt-lowwater)
        rtt-lowwater (+ rtt-lowwater
                        (if (> rtt-delta 0)
                          (/ rtt-delta K/k-8f)
                          (/ rtt-delta K/k-div4f)))
        ;; Q: Are these actually used anywhere else?
        recently-seen-rtt-high? (> rtt-average (+ rtt-highwater K/ms-5))
        rtt-seen-recent-high recently-seen-rtt-high?
        rtt-seen-recent-low (and (not recently-seen-rtt-high?)
                                 (< rtt-average rtt-lowwater))
        state (update state
                      ::specs/flow-control
                      (fn [cur]
                        (assoc cur
                               ::specs/n-sec-per-block n-sec-per-block
                               ::specs/rtt-average rtt-average
                               ::specs/rtt-deviation rtt-deviation
                               ::specs/rtt-highwater rtt-highwater
                               ::specs/rtt-lowwater rtt-lowwater
                               ::specs/rtt-seen-recent-high rtt-seen-recent-high
                               ::specs/rtt-seen-recent-low rtt-seen-recent-low
                               ::specs/rtt-timeout rtt-timeout)))
        state (possibly-adjust-speed state)
        been-a-minute? (- recent last-edge K/minute-1)]
    (cond
      ;; Note that we generally don't need to make any changes
      (and (> 0 been-a-minute?)
           (< recent (+ last-doubling
                        (* 4 n-sec-per-block)
                        (* 64 rtt-timeout)
                        K/ms-5))) state
      (and (<= 0 been-a-minute?)
           (< recent (+ last-doubling
                        (* 4 n-sec-per-block)
                        (* 2 rtt-timeout)))) state
      ;; Q: Really? A: Yep. This is line 535
      (<= (dec K/k-64) n-sec-per-block) state
      :else (-> state
                (assoc ::specs/last-edge
                       (if (not= 0 last-edge) recent last-edge))
                (assoc-in [::specs/flow-control ::specs/last-doubling]
                          recent)
                (assoc-in [::specs/flow-control ::specs/n-sec-per-block]
                          (quot n-sec-per-block 2))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef update-statistics
        :args (s/cat :state ::specs/state
                     :acked-block ::specs/block)
        :ret ::specs/state)
(defn update-statistics
  "It looks like this is coping with the first sent/ACK'd message from the child

  TODO: Better name
  Lines 458-541"
  [{:keys [::specs/message-loop-name
           ::specs/recent]
    :as state}
   {acked-time ::specs/time
    :as acked-block}]
  (log/debug (utils/pre-log message-loop-name)
             "Updating flow-control stats due to "
             acked-block)
  ;; The base-rtt-average calculation really only needs to
  ;; happen the first time around, when the rtt-average
  ;; is 0.
  ;; Q: Would it be worth moving the if check for that out
  ;; of there and into here to avoid the associated function
  ;; call overhead?
  ;; (It seems like premature optimization, but it's a cheap one)
  ;; A: Maybe, maybe not. This gets called again at the top
  ;; of jacobson's-retransmission-timeout.
  ;; Which is just wasteful duplication.
  (try
    (let [state (calculate-base-rtt-averages state acked-time)
          state (update state
                        ::log2/state
                        #(log2/debug %
                                     ::update-statistics
                                     "Recalculating retransmission timeout"
                                     {::specs/message-loop-name message-loop-name}))]
      (jacobson's-retransmission-timeout state acked-block))
    (catch RuntimeException ex
      (update state
              ::log2/state
              #(log2/exception %
                               ex
                               ::update-statistics
                               "Updating statistics failed"
                               (dissoc state ::log2/state))))))
