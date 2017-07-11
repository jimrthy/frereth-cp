(ns frereth-cp.message.to-parent-test
  (:require [clojure.test :refer (are deftest is testing)]
            [frereth-cp.message.specs :as specs]
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
  (testing "16 bytes"
    (let [buf (Unpooled/buffer 16)]
      (.writeBytes buf (byte-array (range 16)))
      (let [block (to-parent/build-message-block 1 {::specs/buf buf
                                                    ::specs/length 16
                                                    ::specs/send-eof false
                                                    ::specs/start-pos 0})]
        (is (= 192 (.readableBytes block)))
        ;; TODO: This is why I need an isolated message extractor
        (is (.hasArray block))
        (let [raw (.array block)
              details (vec raw)]
          ;; Note that, thanks to java's lack of unsigned types,
          ;; the length field looks like -64
          (is (not details)))))))
