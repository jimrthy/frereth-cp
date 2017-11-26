(ns frereth-cp.message.handshake-test
  (:require [clojure.edn :as edn]
            [clojure.spec.alpha :as s]
            [clojure.test :refer (are deftest is testing)]
            [clojure.tools.logging :as log]
            [frereth-cp.message :as message]
            [frereth-cp.message.constants :as K]
            [frereth-cp.message.message-test :as m-t]
            [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.bit-twiddling :as b-t]
            [frereth-cp.util :as utils]
            [gloss.core :as gloss]
            [gloss.io :as io]
            [manifold.deferred :as dfrd]
            [manifold.stream :as strm])
  (:import io.netty.buffer.Unpooled))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::prefix (s/nilable bytes?))
(s/def ::count nat-int?)
(s/def ::state (s/keys :req [::count
                             ::prefix]))
(s/def ::next-object any?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Magic constants

(def protocol
  (gloss/compile-frame
   (gloss/finite-frame :uint16
                       (gloss/string :utf-8))
   pr-str
   edn/read-string))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Helper functions

(defn consumer
  [io-handle prelog time-out succeeded? bs]
  ;; Note that, at this point, we're blocking the
  ;; I/O loop.
  ;; Whatever happens here must return control
  ;; quickly.
  (log/info prelog "Message over network")
  ;; Checking for the server state is wasteful here.
  ;; And very dubious...depending on implementation details,
  ;; it wouldn't take much to shift this over to triggering
  ;; a deadlock (since we're really running on the event loop
  ;; thread).
  ;; Actually, I'm a little surprised that this works at all.
  ;; And it definitely *has* had issues.
  ;; Q: But is it worth it for the test's sake?
  (let [state (message/get-state io-handle time-out ::timed-out)]
    (if (or (= ::timed-out state)
            (instance? Throwable state)
            (nil? state))
      (let [problem (if (instance? Throwable state)
                      state
                      (ex-info "Non-exception"
                               {::problem state}))]
        (log/error problem prelog "Failed!")
        (dfrd/error! succeeded? problem))
      (message/parent->! io-handle bs))))

(defn srvr->client-consumer
  "This processes bytes that are headed from the server to the client"
  [client-io time-out succeeded? bs]
  (let [prelog (utils/pre-log "server->client consumer")]
    (consumer client-io prelog time-out succeeded? bs)))

(defn client->srvr-consumer
  [server-io time-out succeeded? bs]
  (let [prelog (utils/pre-log "client->server consumer")]
    (consumer server-io prelog time-out succeeded? bs)))

(defn buffer-response!
  "Serialize and send a message from the child"
  [io-handle
   prelog
   message
   success-message
   error-message
   error-details]
  (let [frames (io/encode protocol message)]
    (log/debug prelog "Ready to send" (count frames) "message frames")
    (doseq [frame frames]
      (let [array (if (.hasArray frame)
                    (.array frame)
                    (let [result (byte-array (.readableBytes frame))]
                      (.readBytes frame result)))]
        ;; This is actually a java.nio.HeapByteBuffer.
        ;; Which is a totally different animal from a reference-counted ByteBuf
        ;; from netty.
        (comment (.release frame))
        (if-not (message/child->! io-handle array)
          (throw (ex-info "Sending failed"
                          {::failed-on frame
                           ::context prelog}))
          (log/debug prelog (str (count array) "-byte frame sent")))))))
(comment
  (io/encode protocol ::test)
  (let [chzbrgr-length 182
        frames (io/encode protocol (range chzbrgr-length))
        [length payload] frames
        chzbrgr (byte-array (.getShort length))]
    (.get payload chzbrgr)
    (String. chzbrgr))
  )

(defn decoder
  [src]
  (io/decode-stream src protocol))

(defn decode-bytes->child
  [decode-src decode-sink bs]
  (comment) (log/debug (str "Trying to decode "
                            (if-not (keyword? bs)
                              (count bs)
                              "")
                            " bytes in ") bs)
  (if-not (keyword? bs)
    (do
      (when (= 2 (count bs))
        (log/debug (str "This is probably a prefix expecting "
                        (b-t/uint16-unpack bs)
                        " bytes")))
      (let [decoded (strm/try-take! decode-sink ::drained 10 false)]
        (strm/put! decode-src bs)
        (deref decoded 10 false)))
    bs))

(defn server-mock-child
  [server-atom state-atom decode-src decode-sink chzbrgr-length bs]
  (let [prelog (utils/pre-log "Server's child callback")
        _ (log/debug prelog "Message arrived at server's child")
        incoming (decode-bytes->child decode-src decode-sink bs)]
    (if incoming
      (do
        (log/debug prelog
                   (str "Matching '" incoming
                        "', a " (class incoming)))
        (let [rsp (condp = incoming
                    ::ohai! ::orly?
                    ::yarly ::kk
                    ::icanhazchzbrgr? ::kk
                    ::kthxbai ::kk
                    ::specs/normal ::specs/normal)]
          (log/info prelog
                    "Server received"
                    incoming
                    "\nwhich triggers"
                    rsp)
          (if (not= rsp ::specs/normal)
            (buffer-response! @server-atom
                              prelog
                              rsp
                              "Message buffered to child"
                              "Giving up on forwarding to child"
                              {::response rsp
                               ::request incoming})
            (message/child-close! @server-atom))
          (when (= incoming ::icanhazchzbrgr?)
            ;; One of the main points is that this doesn't need to be a lock-step
            ;; request/response.
            (log/info prelog "Client requested chzbrgr. Send out of lock-step")
            ;; Only 3 messages are arriving at the client.
            ;; This almost definitely means that the chzbrgr is the problem.
            ;; Trying to send a raw byte-array here definitely does not work.
            ;; Sending the lazy seq that range produces seems like a bad idea.
            ;; Sending a vec like this doesn't help.
            ;; Note that, whatever I *do* send here, the client needs to
            ;; be updated to expect that type.
            (let [chzbrgr (vec (range chzbrgr-length))]
              ;; This is buffering far more bytes than expected.
              ;; That's because it's encoding an EDN string instead of
              ;; the raw byte-array with which I started.
              ;; (Can't just supply a byte-array because the other
              ;; side doesn't have a reader override to decode that.
              ;; And it wouldn't gain anything to add it, since it would
              ;; still be the string representation of the numbers.
              ;; That's annoying, but it should be good enough for
              ;; purposes of this test.
              (buffer-response! @server-atom
                                prelog
                                chzbrgr
                                "Buffered chzbrgr to child"
                                "Giving up on sending chzbrgr"
                                {})))))
      (log/debug prelog
                 "Partial message in"
                 bs))))

(defn client-child-processor
  "Process the messages queued by mock-client-child"
  [client-atom client-state-atom succeeded? chzbrgr-length incoming]
  (is incoming)
  (is (or (keyword? incoming)
          (< 0 (count incoming))))
  (let [prelog (utils/pre-log "Handshake Client: child callback")
        client-state @client-state-atom]
    (log/info prelog
              (str "Client State: "
                   client-state
                   "\nreceived: "
                   incoming ", a " (class incoming)))
    (if incoming
      (let [result (dfrd/future
                     (let [{n ::count} client-state
                           next-message
                           (condp = n
                             0 (do
                                 (is (= incoming ::orly?))
                                 ::yarly)
                             1 (do
                                 (is (= incoming ::kk))
                                 ::icanhazchzbrgr?)
                             2 (do
                                 (is (= incoming ::kk))
                                 ;; This is the protocol-level ACK
                                 ;; (which is different than the CurveCP
                                 ;; ACK message) associated
                                 ;; with the chzbrgr request
                                 ;; No response to send for this
                                 nil)
                             3 (do
                                 ;; This is based around an implementation
                                 ;; detail that the message stream really consists
                                 ;; of either
                                 ;; a) the same byte array sent by the other side
                                 ;; b) several of those byte arrays, if the block
                                 ;; is too big to send all at once.
                                 ;; TODO: don't rely on that.
                                 ;; It really would be more efficient for the other
                                 ;; side to batch up the ACK and this response
                                 (is (b-t/bytes= incoming (vec (range chzbrgr-length))))
                                 ::kthxbai)
                             4 (do
                                 (is (= incoming ::kk))
                                 (log/info "Client child callback is done")
                                 (dfrd/success! succeeded? ::kthxbai)
                                 (try
                                   (message/child-close! @client-atom)
                                   (catch RuntimeException ex
                                     ;; CIDER doesn't realize that this is a failure.
                                     ;; I blame something screwy in the testing
                                     ;; harness. I *do* see this error message
                                     ;; and the stack trace.
                                     (log/error ex "This really shouldn't pass")
                                     (is (not ex))))
                                 nil))]
                       (log/info prelog
                                 incoming
                                 "triggered a response:"
                                 next-message)
                       (swap! client-state update ::count inc)
                       ;; Hmm...I've wound up with a circular dependency
                       ;; on the io-handle again.
                       ;; Q: Is this a problem with my architecture, or just
                       ;; a testing artifact?
                       (when next-message
                         (buffer-response! @client-atom
                                           prelog
                                           next-message
                                           "Buffered bytes from child"
                                           "Giving up on sending message from child"
                                           {}))
                       (<= 5 n)))])
      (log/error prelog "No bytes decoded. Shouldn't have gotten here"))))

(defn mock-client-child
  "This is the callback for messages arriving from server"
  [decode-src bs]
  (let [prelog (utils/pre-log "Handshake Client: child callback")]
    (log/debug prelog "Message arrived at client's child")
    (strm/put! decode-src bs)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest check-decoder
  ;; Tests for checking my testing code seems like a really bad sign.
  ;; Then again, this really is an integration test. It's covering
  ;; a *lot* of functionality.
  ;; And I've made it extra-complicated by refusing to consider
  ;; adding serialization by default.
  (try "Fundamental idea"
    (let [s (strm/stream)
          xfrm-node (decoder s)
          msg ::message
          msg-frames (io/encode protocol msg)]
      (try
        (is (= 2 (count msg-frames)))
        (doseq [frame msg-frames]
          (strm/put! s frame))
        (let [outcome (strm/try-take! xfrm-node ::drained 40 ::timed-out)]
          (is (= msg (deref outcome 10 ::time-out-2))))
        (finally
          (strm/close! s)))))
  (testing "Wrappers"
    (let [decode-src (strm/stream)
          decode-sink (decoder decode-src)
          msg {::a 1
               ::b 2
               ::c #{3 4 5}}
          frames (io/encode protocol msg)
          binary-frames (reduce (fn [acc frame]
                                  (let [n (- (.limit frame)
                                             (.position frame))
                                        result (byte-array n)]
                                    (.get frame result)
                                    (conj acc result)))
                                []
                                frames)
          decoded (map (partial decode-bytes->child
                                decode-src
                                decode-sink)
                       binary-frames)]
      (try
        (dorun decoded)
        (is (= 2 (count frames)))
        (is (= 2 (count binary-frames)))
        (is (= 2 (count decoded)))
        (is (not (first decoded)))
        ;; Current test implementation hinges on this.
        ;; It doesn't work.
        ;; Just glancing at the gloss source code,
        ;; based on what I know about it, really
        ;; seems as though this should work.
        ;; TODO: Try just using the ByteBuffer.
        ;; Or maybe a ByteBuf?
        (is (= msg (second decoded)))
        (finally
          (strm/close! decode-src))))))

(deftest handshake
  (let [prelog (utils/pre-log "Handshake test")]
    (log/info prelog
              "Top")
    (let [client->server (strm/stream)
          server->client (strm/stream)
          succeeded? (dfrd/deferred)
          ;; Simulate a very stupid FSM
          client-state (atom {::count 0
                              ::prefix nil})
          client-atom (atom nil)
          time-out 500
          client-parent-cb (fn [^bytes bs]
                             (log/info (utils/pre-log "Client parent callback")
                                       "Sending a" (count bs)
                                       "byte array to client's parent")
                             (let [sent (strm/try-put! client->server bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          ;; Something that spans multiple packets would be better, but
          ;; that seems like a variation on this test.
          ;; Although this *does* take me back to the beginning, where
          ;; I was trying to figure out ways to gen the tests based upon
          ;; a protocol defined by something like spec.
          ;; Note that doubling this would expand to at least 2 packets,
          ;; since sending a raw byte-buffer really isn't an option.
          ;; And it's silly to pretend that this is a unit test.
          chzbrgr-length 182
          ;; For this implementation, it would make more sense to use
          ;; strm/onto to put this onto an executor. I'm not doing so
          ;; because tracking all the different threads that are involved
          ;; is already annoying, and this test isn't about trying to
          ;; maximize throughput/bandwidth/responsiveness.
          ;; (My first run after switching to this approach stretches
          ;; the callback out to around 23 ms, which is completely unacceptable)
          clnt-decode-src (strm/stream)
          clnt-decode-sink (decoder clnt-decode-src)
          client-child-cb (partial mock-client-child clnt-decode-src)
          client-child-processing (strm/consume-async (partial client-child-processor
                                                               client-atom
                                                               client-state
                                                               succeeded?
                                                               chzbrgr-length)
                                                      clnt-decode-sink)
          server-atom (atom nil)
          server-state-atom (atom {::prefix nil
                                   ::count 0})
          ;; Note that any realistic server would actually need 1
          ;; decoder per connected client.
          ;; Then again, the server really should wind up with 1 messaging
          ;; ioloop per client, so this is more realistic than it might
          ;; seem at first.
          ;; At least, that's really the reference implementation's design.
          srvr-decode-src (strm/stream)
          srvr-decode-sink (decoder srvr-decode-src)
          server-parent-cb (fn [bs]
                             (log/info (utils/pre-log "Server's parent callback")
                                       "Sending a" (class bs) "to server's parent")
                             (let [sent (strm/try-put! server->client bs time-out ::timed-out)]
                               (is (not= @sent ::timed-out))))
          server-child-cb (partial server-mock-child
                                   server-atom
                                   server-state-atom
                                   srvr-decode-src
                                   srvr-decode-sink
                                   chzbrgr-length)]
      (dfrd/on-realized succeeded?
                        (fn [good]
                          (log/info "----------> Test should have passed <-----------"))
                        (fn [bad]
                          (log/error bad "High-level test failure")
                          (is (not bad))))

      (let [client-init (message/initial-state "Client" {} false)
            client-io (message/start! client-init client-parent-cb client-child-cb)
            server-init (message/initial-state "Server" {} true)
            ;; It seems like this next part really shouldn't happen until the initial message arrives
            ;; from the client.
            ;; Actually, it starts when the Initiate(?) packet arrives as part of the handshake. So
            ;; that isn't quite true
            server-io (message/start! server-init server-parent-cb server-child-cb)]
        (reset! client-atom client-io)
        (reset! server-atom server-io)

        (try
          (strm/consume (partial client->srvr-consumer server-io time-out succeeded?)
                        client->server)
          (strm/consume (partial srvr->client-consumer client-io time-out succeeded?)
                        server->client)

          (let [initial-message (Unpooled/buffer K/k-1)]
            ;; Kick off the exchange
            (buffer-response! client-io
                              prelog
                              ::ohai!
                              "Sequence Initiated"
                              "Handshake initiation failed"
                              {})
            ;; TODO: Find a reasonable value for this timeout
            (let [really-succeeded? (deref succeeded? 10000 ::timed-out)
                  child-finished? (deref client-child-processing 500 ::timed-out)]
              (log/info prelog "handshake-test run through. Need to see what happened")
              (is (and child-finished?
                       (not= ::timed-out child-finished?)))
              (let [client-message-state (message/get-state client-io time-out ::timed-out)]
                (when (or (= client-message-state ::timed-out)
                          (instance? Throwable client-state)
                          (nil? client-message-state))
                  (is not client-message-state))
                (when (= really-succeeded? ::timed-out)
                  (let [{:keys [::specs/flow-control]} client-state]
                    ;; I'm mostly interested in the next-action inside flow-control
                    ;; Down-side to switching to manifold for scheduling:
                    ;; I don't really have any insight into what's going on
                    ;; here.
                    ;; Q: Is that true? Or have I just not studied its
                    ;; docs thoroughly enough?
                    (is (not flow-control) "Client flow-control behind a timeout"))))
              (let [{:keys [::specs/flow-control]
                     :as srvr-state} (message/get-state server-io time-out ::timed-out)]
                (when (or (= srvr-state ::timed-out)
                          (instance? Throwable srvr-state)
                          (nil? srvr-state))
                  (is (not srvr-state)))
                (comment (is (not flow-control) "Server flow-control")))
              (is (= ::kthxbai really-succeeded?))
              (is (= 5 (-> client-state
                           deref
                           ::count)))))
          (finally
            (log/info "Cleaning up")
            (strm/close! clnt-decode-src)
            (strm/close! srvr-decode-src)
            (try
              (message/halt! client-io)
              (catch Exception ex
                (log/error ex "Trying to halt client")))
            (try
              (message/halt! server-io)
              (catch Exception ex
                (log/error ex "Trying to halt server")))))))))
(comment
  (handshake)
  (count (str ::kk))
  (String. (byte-array [0 1 2]))
  )
