(ns frereth-cp.message.flow-control
  "Cope with flow-control algorithms"
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.crypto :as crypto]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal Helpers

(s/fdef recalc-rtt-average
        :args (s/cat :state ::specs/state
                     :rtt ::specs/rtt)
        :ret ::specs/state)
(defn recalc-rtt-average
  "Lines 460-466"
  [{:keys [::specs/rtt-average]
    :as state}
   rtt]
  (if (not= 0 rtt-average)
    (assoc state
           ::specs/n-sec-per-block rtt
           ::specs/rtt-average rtt
           ::specs/rtt-deviation (quot rtt 2)
           ::specs/rtt-highwater rtt
           ::specs/rtt-lowwater rtt)
    state))

(s/fdef jacobson-adjust-block-time
        :args (s/cat :n-sec-per-block ::specs/n-sec-per-block)
        :ret ::specs/n-sec-per-block)
(defn jacobson-adjust-block-time
  "Lines 496-509"
  [n-sec-per-block]
  ;; This next magic number matches K/send-byte-buf-size, but that's
  ;; almost definitely just a coincidence
  (if (< n-sec-per-block K/k-128)
    n-sec-per-block
    ;; DJB had this to say.
    ;; As 4 separate comments.
    ;; additive increase: adjust 1/N by a constant c
    ;; rtt-fair additive increase: adjust 1/N by a constant c every nanosecond
    ;; approximation: adjust 1/N by cN every N nanoseconds
    ;; i.e., N <- 1/(1/N + cN) = N/(1 + cN^2) every N nanoseconds
    (if (< n-sec-per-block 16777216)
      (let [u (quot n-sec-per-block K/k-128)]
        (- n-sec-per-block (* u u u)))
      (let [d (double n-sec-per-block)]
        (long (/ d (inc (/ (* d d) 2251799813685248.0))))))))

(s/fdef adjust-rtt-phase
        :args (s/cat :state ::specs/state)
        :ret ::specs/state)
(defn adjust-rtt-phase
  "Lines 511-521"
  [{:keys [::specs/n-sec-per-block
           ::specs/recent
           ::specs/rtt-phase
           ::specs/rtt-seen-older-high
           ::specs/rtt-seen-older-low]
    :as state}]
  (if (not rtt-phase)
    (if rtt-seen-older-high
      (assoc state
             ::specs/rtt-phase true
             ::specs/last-edge recent
             ::specs/n-sec-per-block (+ n-sec-per-block
                                        (crypto/random-mod (quot n-sec-per-block 4))))
      state)
    (if rtt-seen-older-low
      (assoc state ::specs/rtt-phase false)
      state)))

(defn jacobson's-retransmission-timeout
  "Jacobson's retransmission timeout calculation: --DJB

  I'm lumping lines 467-527 into here, even though I haven't
  seen the actual paper describing the algorithm. This is the
  basic algorithm that TCP uses pretty much everywhere. -- JRG"
  [{:keys [::specs/last-doubling
           ::specs/last-edge
           ::specs/last-speed-adjustment
           ::specs/n-sec-per-block
           ::specs/recent
           ::specs/rtt
           ::specs/rtt-average
           ::specs/rtt-deviation
           ::specs/rtt-highwater
           ::specs/rtt-lowwater
           ::specs/rtt-seen-recent-high
           ::specs/rtt-seen-recent-low
           ::specs/rtt-timeout]
    :as state}]
  (let [rtt-delta (- rtt-average rtt)
        rtt-average (+ rtt-average (/ rtt-delta 8))
        rtt-delta (if (> 0 rtt-delta)
                    (- rtt-delta)
                    rtt-delta)
        rtt-delta (- rtt-delta rtt-deviation)
        rtt-deviation (+ rtt-deviation (/ rtt-delta 4))
        rtt-timeout (+ rtt-average (* 4 rtt-deviation))
        ;; adjust for delayed acks with anti-spiking: --DJB
        rtt-timeout (+ rtt-timeout (* 8 n-sec-per-block))

        ;; recognizing top and bottom of congestion cycle:  --DJB
        rtt-delta (- rtt rtt-highwater)
        rtt-highwater (+ rtt-highwater (/ rtt-delta K/k-1))
        rtt-delta (- rtt rtt-lowwater)
        rtt-lowwater (+ rtt-lowwater
                        (if (> rtt-delta 0)
                          (/ rtt-delta K/k-8)
                          (/ rtt-delta K/k-div4)))
        rtt-seen-recent-high (> rtt-average (+ rtt-highwater K/ms-5))
        rtt-seen-recent-low (and (not rtt-seen-recent-high)
                                 (< rtt-average rtt-lowwater))]
    (when (>= recent (+ last-speed-adjustment (* 16 n-sec-per-block)))
      (let [n-sec-per-block (if (> (- recent last-speed-adjustment) K/secs-10)
                              (+ K/secs-1 (crypto/random-mod (quot n-sec-per-block 8)))
                              n-sec-per-block)
            n-sec-per-block (jacobson-adjust-block-time n-sec-per-block)
            state (assoc state ::specs/n-sec-per-block n-sec-per-block)
            {:keys [::specs/rtt-seen-recent-high ::specs/rtt-seen-recent-low]
             :as state} (adjust-rtt-phase state)
            state (assoc state
                         ::specs/last-speed-adjustment recent
                         ::specs/n-sec-per-block n-sec-per-block

                         ::specs/rtt-average rtt-average
                         ::specs/rtt-deviation rtt-deviation
                         ::specs/rtt-highwater rtt-highwater
                         ::specs/rtt-lowwater rtt-lowwater
                         ::specs/rtt-timeout rtt-timeout

                         ::specs/seen-older-high rtt-seen-recent-high
                         ::specs/seen-older-low rtt-seen-recent-low
                         ::specs/seen-recent-high false
                         ::specs/seen-recent-low false)
            been-a-minute? (- recent last-edge K/minute-1)]
        (cond
          (and been-a-minute?
               (< recent (+ last-doubling
                            (* 4 n-sec-per-block)
                            (* 64 rtt-timeout)
                            K/ms-5))) state
          (and (not been-a-minute?)
               (< recent (+ last-doubling
                            (* 4 n-sec-per-block)
                            (* 2 rtt-timeout)))) state
          (<= (dec K/k-64) n-sec-per-block) state
          :else (assoc state {::specs/n-sec-per-block (quot n-sec-per-block 2)
                              ::specs/last-doubling recent
                              ::specs/last-edge (if (not= 0 last-edge) recent last-edge)}))))))

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
  [{:keys [::specs/recent]
    :as state}
   {:keys [::specs/time]
    :as acked-block}]
  (let [rtt (- recent time)
        state (recalc-rtt-average state rtt)]
    (jacobson's-retransmission-timeout state)))
