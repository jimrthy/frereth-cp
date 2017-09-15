(ns frereth-cp.message.message-test
  (:require [clojure.data]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer (deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.helpers :as help]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.message.test-utilities :as test-helpers]
            [frereth-cp.message.to-parent :as to-parent]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils])
  (:import [io.netty.buffer ByteBuf Unpooled]))

(deftest basic-echo
  (let [src (Unpooled/buffer K/k-1)  ; w/ header, this takes it to the 1088 limit
        msg-len (- K/max-msg-len K/header-length K/min-padding-length)
        ;; Note that this is what the child sender should be supplying
        message-body (byte-array (range msg-len))
        ;; Might as well start with 1, since we're at stream address 0.
        ;; Important note: message-id 0 is reserved for pure ACKs!
        ;; TODO: Play with this and come up with test states that simulate
        ;; dropping into the middle of a conversation
        message-id 1]
    (is (= msg-len K/k-1))
    (.writeBytes src message-body)
    (let [incoming (to-parent/build-message-block message-id {::specs/buf src
                                                              ::specs/length msg-len
                                                              ::specs/send-eof false
                                                              ::specs/start-pos 0})]
      (is (= K/max-msg-len (count incoming)))
      (let [response (promise)
            parent-state (atom 0)
            parent-cb (fn [dst]
                        (let [response-state @parent-state]
                          (log/debug "parent-cb:" response-state)
                          ;; Should get 2 callbacks here:
                          ;; 1. The ACK (this has stopped showing up)
                          ;; 2. The actual response
                          ;; Although, depending on timing, 3 or
                          ;; more are possible
                          ;; (If we don't end this quickly enough to
                          ;; avoid a repeated send, for example)
                          (when (= response-state 1)
                            (deliver response dst))
                          (swap! parent-state inc)))
            ;; I have a circular dependency between
            ;; child-cb and initialized.
            ;; child-cb is getting called inside an
            ;; agent send handler,
            ;; which means I have the agent state
            ;; directly available, but not the actual
            ;; agent.
            ;; That's what it needs, because child->
            ;; is going to trigger another send.
            ;; Wrapping it inside an atom is obnoxious, but
            ;; it works.
            ;; Don't do anything like this for anything real.
            state-agent-atom (atom nil)
            child-message-counter (atom 0)
            strm-address (atom 0)
            child-cb (fn [array-o-bytes]
                       ;; TODO: Add another similar test that throws an
                       ;; exception here, for the sake of hardening the
                       ;; caller
                       (is (bytes? array-o-bytes)
                           (str "Expected a byte-array. Got a "
                                (class array-o-bytes)))
                       (assert array-o-bytes)
                       (let [msg-len (count array-o-bytes)]
                         (log/debug "Echoing back an incoming message:"
                                    msg-len
                                    "bytes")
                         (when (not= K/k-1 msg-len)
                           (log/warn "Incoming message doesn't match length we sent"
                                     {::expected K/k-1
                                      ::actual msg-len
                                      ::details (vec array-o-bytes)}))
                         ;; Just echo it directly back.
                         (let [state-agent @state-agent-atom]
                           (is state-agent)
                           (swap! child-message-counter inc)
                           (swap! strm-address + msg-len)
                           (message/child-> state-agent array-o-bytes))))
            ;; It's tempting to treat this test as a server.
            ;; Since that's the way it acts: request packets come in and
            ;; trigger responses.
            ;; But the setup is wrong:
            ;; The server shouldn't start until after the first client
            ;; message arrives.
            ;; Maybe it doesn't matter, since I'm trying to send the initial
            ;; message quickly, but the behavior seems suspicious.
            initialized (message/initial-state parent-cb child-cb true)
            state (message/start! initialized)]
        (reset! state-agent-atom state)
        (try
          ;; TODO: Add tests that send a variety of gibberish messages
          (let [wrote (future (message/parent-> state incoming))
                outcome (deref response 1000 ::timeout)]
            (if-let [err (agent-error state)]
              (is (not err))
              (do
                (is (not= outcome ::timeout))
                (when-not (= outcome ::timeout)
                  (is (= @parent-state 2))
                  ;; I'm getting the response message header here, which is
                  ;; correct, even though it seems wrong.
                  ;; In the real thing, these are the bytes I'm getting ready
                  ;; to send over the wire
                  (is (= (count outcome) (+ msg-len K/header-length K/min-padding-length)))
                  (let [without-header (byte-array (drop (+ K/header-length K/min-padding-length)
                                                         (vec outcome)))]
                    (is (= (count message-body) (count without-header)))
                    (is (b-t/bytes= message-body without-header))))
                (is (realized? wrote))
                (when (realized? wrote)
                  (let [outcome-agent @wrote]
                    (is (not (agent-error outcome-agent)))
                    (when-not (agent-error outcome-agent)
                      ;; Fun detail:
                      ;; wrote is a promise.
                      ;; When I deref that, there's an agent
                      ;; that I need to deref again to get
                      ;; the actual end-state
                      (let [child-outcome @outcome-agent
                            outgoing (::specs/outgoing child-outcome)
                            incoming (::specs/incoming child-outcome)]
                        (is (= (::specs/receive-bytes incoming) (inc msg-len)))
                        (is (= (::specs/next-message-id outgoing) 2))
                        (is (= (::specs/send-processed outgoing) 0))
                        (is (not (::specs/send-eof outgoing)))
                        (is (= (::specs/send-bytes outgoing) msg-len))
                        ;; Keeping around as a reminder for when the implementation changes
                        ;; and I need to see what's really going on again
                        (comment (is (not outcome) "What should we have here?")))))))))
          (finally
            (message/halt! state)))))))
(comment (basic-echo))

(deftest bigger-echo
  ;; Flip-side of echo: I want to see what happens
  ;; when the child sends bytes that don't fit into
  ;; a single message packet.

  (let [packet-count 8  ; trying to make life interesting
        response (promise)
        parent-state (atom {:count 0
                            :buffer []})
        parent-cb (fn [dst]
                    (let [response-state @parent-state]
                      (log/debug "parent-cb:" response-state)
                      ;; The first few blocks should max out the message size.
                      ;; The way the test is set up, the last will be
                      ;; (+ 512 64).
                      ;; It doesn't seem worth the hoops it would take to validate that.
                      (swap! parent-state
                             (fn [cur]
                               (-> cur
                                   (update :count inc)
                                   ;; Seems a little silly to include the ACKs.
                                   ;; Should probably think this through more thoroughly
                                   (update :buffer conj (vec dst)))))
                      ;; I would like to get 8 callbacks here:
                      ;; 1 for each kilobyte of message the child tries to send.
                      ;; Actually, the initial message bytes are
                      ;; only getting 512 bytes, which seems like an odd issue.
                      ;; But, more importantly, I don't really have an
                      ;; i/o loop at this point. So the follow-up
                      ;; messages will never arrive.
                      (when (= 8 (:count @parent-state))
                        (deliver response (:buffer @parent-state)))))
        ;; I have a circular dependency between
        ;; child-cb and initialized.
        ;; child-cb is getting called inside an
        ;; agent send handler,
        ;; which means I have the agent state
        ;; directly available, but not the actual
        ;; agent.
        ;; That's what it needs, because child->
        ;; is going to trigger another send.
        ;; Wrapping it inside an atom is obnoxious, but
        ;; it works.
        ;; Don't do anything like this for anything real.
        state-agent-atom (atom nil)
        child-message-counter (atom 0)
        strm-address (atom 0)
        child-cb (fn [_]
                   (throw (RuntimeException. "This should never get called")))
        initialized (message/initial-state parent-cb child-cb true)
        state (message/start! initialized)]
    (reset! state-agent-atom state)
    (try
      ;; Add an extra half-K just for giggles
      (let [msg-len (+ (* packet-count K/k-1) K/k-div2)
            ;; Note that this is what the child sender should be supplying
            message-body (byte-array (range msg-len))]
        (message/child-> state message-body)
        (let [outcome (deref response 5000 ::timeout)]
          (println "Verifying that state hasn't errored out")
          (if-let [err (agent-error state)]
            (is (not err))
            (do
              (is (not= outcome ::timeout))
              (when-not (= outcome ::timeout)
                ;; TODO: What do I need to set up a full-blown i/o
                ;; loop to make this accurate?
                (is (= packet-count (count outcome)))
                (is (= K/max-msg-len (count (first outcome))))
                (doseq [packet outcome]
                  (is (= (count packet) (+ K/k-1 K/header-length K/min-padding-length))))
                (let [rcvd-strm
                      (reduce (fn [acc with-header]
                                (let [without-header (byte-array (drop (+ K/header-length K/min-padding-length)
                                                                       with-header))]
                                  (conj acc without-header)))
                              []
                              outcome)]
                  (is (b-t/bytes= (->> rcvd-strm
                                       first
                                       byte-array)
                                  (->> message-body
                                       vec
                                       (take K/standard-max-block-length)
                                       byte-array)))))
              (let [state-agent @state-agent-atom
                    outcome @state-agent
                    outgoing (::specs/outgoing outcome)
                    incoming (::specs/incoming outcome)]
                (is (= msg-len (::specs/send-bytes outgoing)))
                (is (= packet-count (::specs/next-message-id outgoing)))
                ;; I'm not sending back any ACKs
                (is (= (::specs/send-processed outgoing) 0))
                ;; TODO: Need a test that does this
                (is (not (::specs/send-eof outgoing)))
                (is (= (::specs/send-bytes outgoing) msg-len))
                ;; Keeping around as a reminder for when the implementation changes
                ;; and I need to see what's really going on again
                (comment (is (not outcome) "What should we have here?")))))))
      (finally
        (message/halt! state)))))
(comment
  (bigger-echo)
  )

(comment
  (deftest parallel-parent-test
    (testing "parent-> should be thread-safe"
      (is false "Write this")))

  (deftest parallel-child-test
    (testing "child-> should be thread-safe"
      (is false "Write this")))

  (deftest simulate-dropped-acks
    ;; When other side fails to respond "quickly enough",
    ;; should re-send message blocks
    ;; This adds an entirely new wrinkle (event scheduling)
    ;; to the mix
    (is false "Write this")))

(comment
  (deftest piping-io
    ;; This was an experiment that failed.
    ;; Keeping it around as a reminder of why it didn't work.
    (let [in-pipe (java.io.PipedInputStream. K/send-byte-buf-size)
          out-pipe (java.io.PipedOutputStream. in-pipe)]
      (testing "Overflow"
        (let [too-big (+ K/k-128 K/k-8)
              src (byte-array (range too-big))
              dst (byte-array (range too-big))]
          (is (= 0 (.available in-pipe)))
          (let [fut (future (.write out-pipe src)
                            (println "Bytes written")
                            ::written)]
            (is (= K/k-128 (.available in-pipe)))
            (is (= K/k-8 (.read in-pipe dst 0 K/k-8)))
            (is (= (- K/k-128 K/k-8) (.available in-pipe)))
            (is (= (- K/k-128 K/k-8) (.read in-pipe dst 0 K/k-128)))
            (println "Read 128K")
            ;; It looks like these extra 8K bytes just silently disappear.
            ;; That's no good.
            (Thread/sleep 0.5)
            ;; Actually, they didn't disappear.
            ;; I just don't have any good way to tell that they're
            ;; available.
            (is (not= K/k-8 (.available in-pipe)))
            ;; Q: Is this a deal-killer?
            ;; A: Yes.
            (println "Trying to read 1K more")
            (let [remaining-read (.read in-pipe dst 0 K/k-1)]
              (println "Read" remaining-read "bytes")
              (is (= K/k-1 remaining-read)))
            (is (= (* 7 K/k-1) (.available in-pipe)))
            (is (= (* 7 K/k-1) (.read in-pipe dst 0 K/k-16)))
            (is (realized? fut))
            (is (= ::written (deref fut 500 ::timed-out)))))))))
