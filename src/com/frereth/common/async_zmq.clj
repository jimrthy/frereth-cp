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
   async->sock :- mq/Socket  ; async half of in<->ex-sock
   ->zmq-sock :- mq/Socket ; 0mq half of in<->ex-sock
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
               almost-started (assoc this
                                     :in<->ex-sock in<->ex-sock
                                     :->zmq-sock (:rhs in<->ex-sock)
                                     :async->sock (:lhs in<->ex-sock)
                                     :ex-chan ex-chan)
               ;; The choice between lhs and rhs for who gets
               ;; which of the internal pairs is completely
               ;; and deliberately arbitrary.
               ;; Well, I'm thinking in terms of writing left
               ;; to right and messages originating from the
               ;; interior more often, but that isn't even
               ;; vaguely realistic.
               zmq-loop (run-zmq-loop! almost-started)
               async-loop (run-async-loop! almost-started)]
           (assoc almost-started
                  :async-loop async-loop
                  :zmq-loop zmq-loop)))
  (stop [this]
        ;; signal the async half of the event loop to exit
        (if ex-chan
          (async/close! ex-chan)
          (log/warn "No ex-chan. This can't be legal"))
        ;; N.B. These status updates are really pretty vital
        ;; and should be logged at the warning level, at the very least
        (comment (log/debug "Waiting for Asynchronous Event Loop to exit"))
        (let [async-result (<?? async-loop)]
          (comment (log/debug "Asynchronous event loop exited with a status:\n"
                              (util/pretty async-result))))
        (comment (log/debug "Waiting for 0mq Event Loop to exit"))
        (let [zmq-result (<?? zmq-loop)]
          (comment (log/debug "0mq Event Loop exited with status:\n"
                              (util/pretty zmq-result))))
        (comment (log/debug "Final cleanup"))
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

TODO: Make this part of the top-level Component instead
of effectively a global.

This approach is probably safe enough, but it's still wrong."
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
  [{:keys [in-chan in<->ex-sock ex-chan]} :- EventPair]
  (let [internal-> (:lhs in<->ex-sock)]
    (go-try
     (comment (log/debug "Entering Async event thread"))
     ;; TODO: Catch exceptions?
     (loop [[val port] (alts? [in-chan ex-chan])]
       (when val
         (log/debug "Incoming async message:\n"
                    (util/pretty val))
         (if (= in-chan port)
           (do
             (log/debug "From internal. Forwarding to 0mq")
             ;; Have to serialize it here: can't
             ;; send arbitrary data across 0mq sockets
             (mq/send! internal-> (serialize val))
             (log/debug "Message forwarded"))
           (do
             (assert (= ex-chan port))
             (log/debug "Message received from 0mq side")
             ;; This means that in-chan must be read/write
             (>! in-chan val)
             (log/debug "Forwarded to receiver")))
         (recur (alts? [in-chan ex-chan]))))
     (comment (log/trace "One of the internal async event loops closed"))
     (mq/send! internal-> internal-close-signal)
     :exited-successfully)))

(s/defn possibly-recv-internal!
  "Really just refactored to make data flow more clear"
  [{:keys [->zmq-sock external-writer ex-sock]
    :as component} :- EventPair
   poller :- mq/Poller]
  ;; Message over internal notifier socket?
  (if (mq/in-available? poller 1)
    (let [msg (mq/recv! ->zmq-sock)]
      (comment) (log/debug "Forwarding internal message\n"
                           (util/pretty msg)
                           "\nfrom 0mq through\n"
                           (util/pretty external-writer))
      ;; Forward it
      ;; TODO: Probably shouldn't forward the
      ;; exit signal, but consider this a test
      ;; of the robustness on the other side,
      ;; for now.
      ;; After all, both sides really have to be
      ;; able to cope with gibberish
      ;; Handling this in here breaks separation
      ;; of concerns and leaves a recv! function
      ;; doing both recv and send.
      ;; TODO: Rename this to proxy and split the
      ;; two halves.
      (try
        ;; TODO: Shouldn't need the flags arg.
        ;; This is really a bug in the current version of cljeromq
        (external-writer ex-sock (serialize msg))
        (catch RuntimeException ex
          (log/error ex)
          (throw)))
      (comment) (log/debug "Message forwarded")
      ;; Do we continue?
      msg)))

(s/defn possibly-forward-msg-from-outside!
  [{:keys [external-reader ex-sock ex-chan]} :- EventPair
   poller :- mq/Poller]
  ;; Message coming in from outside?
  (when (mq/in-available? poller 0)
    ;; TODO: Would arguably be more
    ;; efficient to loop over all available
    ;; messages in case several arrive at once.
    ;; The most obvious downside to that approach
    ;; is a DDoS that locks us into that forever
    (let [raw (external-reader ex-sock)
          msg (deserialize raw)]
      ;; Forward it along
      (log/debug "Forwarding\n"
                 (util/pretty msg)
                 "from outside to async")
      ;; This is actually inside a go block,
      ;; but this is where macros < special
      ;; forms. That go block is structurally
      ;; inside the function that calls this one,
      ;; so there's no way for this one to know
      ;; that we're in it.
      (>!! ex-chan msg))))

(s/defn run-zmq-loop! :- fr-sch/async-channel
  [{:keys [ex-sock ->zmq-sock ex-chan external-reader externalwriter]
    :as component} :- EventPair]
  (let [poller (mq/poller 2)]
    (mq/register-socket-in-poller! poller ex-sock)
    (mq/register-socket-in-poller! poller ->zmq-sock)
    (go-try
     (comment (log/debug "Entering 0mq event thread"))
     (try
       (loop [available-sockets (mq/poll poller -1)]
         (let [received-internal? (possibly-recv-internal! component poller)]
           (log/debug (if received-internal?
                        (str "Received-Internal:\n" (util/pretty received-internal?))
                        "Must have been external"))
           (when-not (= received-internal? internal-close-signal)
             (log/debug "Wasn't the kill message. Continuing.")
             #_(possibly-forward-msg-from-outside! poller external-reader ex-sock ex-chan)
             (possibly-forward-msg-from-outside! component poller)
             (recur (mq/poll poller -1)))))
       (comment (log/debug "Cleaning up 0mq Event Loop"))
       :exited-successfully
       (catch NullPointerException ex
         (let [tb (->> ex .getStackTrace vec (map #(str % "\n")))
               msg (.getMessage ex)]
           (log/error ex msg "\n" tb))
         :null-pointer-exception)
       (finally
         ;; This is probably pointless, but might
         ;; as well do whatever cleanup I can
         (mq/unregister-socket-in-poller! poller ex-sock)
         (mq/unregister-socket-in-poller! poller ->zmq-sock)
         (comment (log/debug "Exiting 0mq Event Loop")))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/defn ctor :- EventPair
  [cfg]
  (map->EventPair cfg))
