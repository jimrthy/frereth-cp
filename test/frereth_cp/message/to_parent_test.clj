(ns frereth-cp.message.to-parent-test
  (:require [clojure.test :refer (are deftest is testing)]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.from-parent :as from-parent]
            [frereth-cp.message.to-parent :as to-parent])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(deftest check-padding-size
  (are [n v] (let [u (to-parent/calculate-padded-size n)]
               (println "Expected" v "got" u)
               (= u v))
    {::specs/length 16}  192
    {::specs/length (- 192 64 1)} 192
    {::specs/length (- 192 64)} 192
    {::specs/length (- 193 64)} 320
    {::specs/length (- 320 64 1)} 320
    {::specs/length (- 320 64)} 320
    {::specs/length (- 321 64)} 576
    {::specs/length (- 576 64)} 576
    {::specs/length (- 577 64)} 1088
    {::specs/length (- 1087 64)} 1088
    {::specs/length (- 1088 64)} 1088)
  (try
    (to-parent/calculate-padded-size {::specs/length 1089})
    (is false "That should have failed")
    (catch AssertionError ex
      (is ex))))

(deftest check-message-builder
  ;; FIXME: This is screaming for generative testing
  (testing "16 bytes"
    (let [length 16
          buf (Unpooled/buffer length)]
      (try
        (.writeBytes buf (byte-array (range length)))
        (let [arbitrary-id #_167535 16
              ;; Current implementation skips this, since we send
              ;; off every ACK immediately
              acked-id #_2194584589721 32
              magical-start-byte #_(long (Math/pow 2 33)) 45
              block (to-parent/build-message-block arbitrary-id
                                                   {::specs/buf buf
                                                    ;; Q: What happens if this
                                                    ;; doesn't match the actual?
                                                    ;; (That's a good reason to avoid
                                                    ;; the duplication)
                                                    ::specs/length length
                                                    ::specs/send-eof false
                                                    ::specs/start-pos magical-start-byte})]
          (is (= 240 (.readableBytes block)))
          (comment)
          (let [bs (.array block)
                v (vec bs)
                sh [0 0]]
            (is (= [16 0 0 0] (subvec v 0 4)) "Message ID")
            (is (= [0 0 0 0] (subvec v 4 8)) "ACK ID")
            ;; This next part's almost a direct translation of
            ;; curvecpmessage.c, lines 544-562.
            ;; Maybe it will serve as a useful reference if
            ;; I ever have to look at this table again
            (is (= (repeat 8 0) (subvec v 8 16)) "Bytes in first ACK range")
            (is (= (repeat 4 0) (subvec v 16 20)) "Gap 1-2")
            (is (= sh (subvec v 20 22)) "Bytes in 2nd ACK")
            (is (= sh (subvec v 22 24)) "Gap 2-3")
            (is (= sh (subvec v 24 26)) "Bytes in 3rd ACK")
            (is (= sh (subvec v 26 28)) "Gap 3-4")
            (is (= sh (subvec v 28 30)) "Bytes in 4th ACK")
            (is (= sh (subvec v 30 32)) "Gap 4-5")
            (is (= sh (subvec v 32 34)) "Bytes in 5th ACK")
            (is (= sh (subvec v 34 36)) "Gap 5-6")
            (is (= sh (subvec v 36 38)) "Bytes in 6th ACK")
            (is (= [16 0] (subvec v 38 40)) "D + Flags")
            (is (= [45 0 0 0 0 0 0 0] (subvec v 40 48)) "Stream index")
            (let [padding-bytes (- 192 length)]
              (is (= (repeat padding-bytes 0) (subvec v 48 (+ 48 padding-bytes))))
              (is (= (range length) (subvec v (+ 48 padding-bytes) 240)))))
          (comment)
          (let [{:keys [::specs/message-id
                        ::specs/acked-message
                        ::specs/size-and-flags
                        ::specs/start-byte
                        ::specs/buf]
                 :as packet} (from-parent/deserialize block)]
            (comment
              (is (not packet)))
            (try
              (is (= message-id arbitrary-id) "message ID")
              (is (= #_acked-id 0 acked-message) "We don't ACK")
              (is (= length size-and-flags) "length flag")
              (is (= magical-start-byte start-byte) "start index")
              ;; Q: Huh?
              (is (= 0 (::specs/ack-length-4 packet)) "length-4")
              (comment
                ;; We aren't shrinking buf yet,
                ;; so this is still the full 240
                (is (= length (.capacity buf))))
              (comment
                (is (.hasArray buf))
                (if (.hasArray buf)
                  (let [bs (.array buf)]
                    ;; This check isn't going to work without shrinkage
                    ;; (assuming that works properly)
                    (is (= (vec bs) (range length)) "shrinkage"))
                  (throw (RuntimeException. "Guess I have to cope with this"))))
              (finally
                ;; The one that we wound up with
                (.release buf)))))
        (finally
          ;; The source that we built from
          ;; Q: What are the odds that this got reused?
          (.release buf))))))
