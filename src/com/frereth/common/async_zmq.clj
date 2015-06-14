(ns com.frereth.common.async-zmq
  "Communicate among 0mq sockets and async channels.

Strongly inspired by lynaghk's zmq-async"
  (require [cljeromq.core :as mq]
           [clojure.core.async :as async :refer (>! >!!)]
           [clojure.edn :as edn]
           #_[com.frereth.common.communication :as comm]
           [com.frereth.common.schema :as fr-sch]
           [com.frereth.common.util :as util]
           [com.stuartsierra.component :as component]
           [full.async :refer (<? <?? alts? go-try)]
           [ribol.core :refer (raise)]
           [schema.core :as s]
           [taoensso.timbre :as log]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

(declare run-async-loop! run-zmq-loop!)
(s/defrecord EventPair
  [mq-ctx :- mq/Context             ; required for building internal inproc sockets
   ex-sock :- mq/Socket     ; faces outside world. Caller provides
   in<->ex-sock :- mq/InternalPair     ; messages from in-chan to ex-sock flow across these
   ex-chan :- fr-sch/async-channel  ; messages from 0mq side travel over this to reach in-chan
   in-chan :- fr-sch/async-channel  ; faces interior. Caller provides
   async-loop :- fr-sch/async-channel  ; thread where the async event loop is running
   zmq-loop :- fr-sch/async-channel  ; thread where the 0mq event loop is running
   ;; external-reader and -writer should be simple for
   ;; everything except router/dealer (which is what
   ;; I'll be using, of course).
   ;; dealer really just needs to cope with an empty address
   ;; separator frame
   ;; reader has to handle things like socket registration,
   ;; reconnecting dropped sessions, etc.
   ;; Luckily (?) these are the server writer's problems.
   external-reader :- (s/=> fr-sch/java-byte-array mq/Socket)
   ;; I *think* this returns bool, but, honestly,
   ;; it should return nil
   external-writer :- (s/=> s/Any mq/Socket fr-sch/java-byte-array)]
  component/Lifecycle
  (start [this]
    "Set up two entertwined event loops running in background threads.

Their entire purpose in life, really, is to shuffle messages between
0mq and core.async"
         (assert mq-ctx "Missing messaging context")
         (assert ex-sock "Missing exterior socket")

         ;; I'm torn about in-chan. It seems like it would
         ;; make perfect sense to create it here.
         ;; I shouldn't be, because it wouldn't.
         ;; The thing that writes to it is responsible for
         ;; closing it.
         ;; Something on the inside writes to this channel
         ;; when it wants us to forward the message along to
         ;; the outside world.
         ;; It can close this channel to signal that it's time
         ;; to quit.
         ;; It only makes sense that that's where it gets created
         (assert in-chan "Missing internal async channel")

         ;; TODO: Still need the functions to call to read/write
         ;; from/to ex-sock
         ;; TODO: Need channel(s) to write to for handling incoming
         ;; messages.
         ;; These can't be in-chan: the entire point to this
         ;; architecture is to do the heavy lifting of both reading
         ;; and writing.
         (let [in<->ex-sock (mq/build-internal-pair! mq-ctx)
               ex-chan (async/chan)
               ;; The choice between lhs and rhs for who gets
               ;; which of the internal pairs is completely
               ;; and deliberately arbitrary.
               ;; Well, I'm thinking in terms of writing left
               ;; to right and messages originating from the
               ;; interior more often, but that isn't even
               ;; vaguely realistic.
               zmq-loop (run-zmq-loop! ex-sock
                                       (:rhs in<->ex-sock)
                                       ex-chan
                                       external-reader
                                       external-writer)
               async-loop (run-async-loop! in-chan
                                           (:lhs in<->ex-sock)
                                           ex-chan)]
           (assoc this
                  :in<->ex-sock in<->ex-sock
                  :ex-chan ex-chan
                  :async-loop async-loop
                  :zmq-loop zmq-loop)))
  (stop [this]
        ;; signal the async half of the event loop to exit
        (async/close! ex-chan)
        (log/trace "Waiting for Asynchronous Event Loop to exit")
        (let [async-result (<?? async-loop)]
          (log/trace "Asynchronous event loop exited with a status:\n"
                     (util/pretty async-result)))
        (log/trace "Waiting for 0mq Event Loop to exit")
        (let [zmq-result (<?? zmq-loop)]
          (log/trace "0mq Event Loop exited with a status:\n"
                     (util/pretty zmq-result)))
        (log/trace "Final cleanup")
        (mq/close-internal-pair! in<->ex-sock)
        (assoc this
               :in<->ex-sock nil
               :ex-chan nil
               :async-loop nil
               :zmq-loop nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(def internal-close-signal
  "Tell the 0mq event loop to exit
Need to be a string because it's travelling over
a 0mq socket

Actually, it probably needs to be a byte-array,
since that's really what I'm using at this level.

TODO: Verify that one way or another"
  (name (gensym)))

(s/defn serialize :- fr-sch/java-byte-array
  "TODO: This absolutely does not belong in here"
  [o :- s/Any]
  (-> o pr-str .getBytes))

(s/defn deserialize :- s/Any
  "Neither does this"
  [bs :- fr-sch/java-byte-array]
  (let [s (String. bs)]
    (try
      (edn/read-string s)
      (catch RuntimeException ex
        (log/error ex "Failed reading incoming string:\n"
                   (util/pretty s))))))

(s/defn run-async-loop! :- fr-sch/async-channel
  [in-chan :- fr-sch/async-channel
   ;; twin to the Pair half w/ same name in run-zmq-loop!
   internal-> :- mq/Socket
   ex-chan :- fr-sch/async-channel]
  (go-try
   ;; TODO: Catch exceptions?
   (loop [[val port] (alts? [] in-chan ex-chan)]
     (when val
       (if (= in-chan port)
         ;; Have to serialize it here: can't
         ;; send arbitrary data across 0mq sockets
         (mq/send! internal-> (serialize val))
         (do
           (assert (= ex-chan port))
           ;; This means that in-chan must be read/write
           (>! in-chan val)))
       (recur (alts! in-chan ex-chan))))
   (log/trace "One of the internal async event loops closed")
   (mq/send! internal-> internal-close-signal)))

(s/defn run-zmq-loop! :- fr-sch/async-channel
  [ex-sock :- mq/Socket
   internal-> :- mq/Socket
   ex-chan :- fr-sch/async-channel
   reader :- (s/=> fr-sch/java-byte-array mq/Socket)
   writer :- (s/=> s/Any mq/Socket fr-sch/java-byte-array)]
  (let [poller (mq/poller 2)]
    (mq/register-socket-in-poller! ex-sock poller)
    (mq/register-socket-in-poller! internal-> poller)
    (go-try
      (try
        (loop [available-sockets (mq/poll poller -1)]
          (let [received-internal?
                ;; Message over internal notifier socket?
                (if (mq/in-available? poller 1)
                  (let [msg (mq/recv! internal->)]
                    ;; Forward it
                    ;; TODO: Probably shouldn't forward the
                    ;; exit signal, but consider this a test
                    ;; of the robustness on the other side,
                    ;; for now.
                    ;; After all, both sides really have to be
                    ;; able to cope with gibberish
                    (writer ex-sock (serialize msg))
                    ;; Do we continue?
                    msg))]
            (when-not (= received-internal? internal-close-signal)
              ;; Message coming in from outside?
              (when (mq/in-available? poller 0)
                ;; TODO: Would arguably be more
                ;; efficient to loop over all available
                ;; messages in case several arrive at once.
                ;; The most obvious downside to that approach
                ;; is a DDoS that locks us into that forever
                (let [raw (reader ex-sock)
                      msg (deserialize raw)]
                  ;; Forward it along
                  (>! ex-chan msg)))
              (recur (mq/poll poller -1)))))
        (finally
          ;; This is probably pointless, but might
          ;; as well do whatever cleanup I can
          (mq/unregister-socket-in-poller! ex-sock)
          (mq/unregister-socket-in-poller! ))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public
