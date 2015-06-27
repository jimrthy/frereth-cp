(ns com.frereth.common.async-zmq
  "Communicate among 0mq sockets and async channels.

Strongly inspired by lynaghk's zmq-async"
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async :refer (>! >!!)]
            [clojure.edn :as edn]
            #_[com.frereth.common.communication :as comm]
            [com.frereth.common.schema :as fr-sch]
            [com.frereth.common.util :as util]
            [com.frereth.common.zmq-socket :as zmq-socket]
            [com.stuartsierra.component :as component]
            [full.async :refer (<? <?? alts? go-try)]
            [ribol.core :refer (raise)]
            [schema.core :as s]
            [taoensso.timbre :as log])
  (:import [com.frereth.common.zmq_socket SocketDescription]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

(declare run-async-loop! run-zmq-loop!)
(s/defrecord EventPair
  [;; Important for public API
   ;; send messages to this to get them to 0mq. Supplied by caller
   in-chan :- fr-sch/async-channel
   ;; faces outside world.
   ;; Caller provides, because binding/connecting is really not in scope here
   ex-sock :- SocketDescription
   ;; 0mq puts messages onto here when they come in from outside
   ;; Owned by this
   ex-chan :- fr-sch/async-channel

   ;; Important to know about, since you have to supply it
   ;; required for building internal inproc sockets
   ;; TODO: Just use the context attached to ex-sock
   ;; Q: Will there ever be a scenario where that's a bad idea?
   mq-ctx :- mq/Context

   ;; Really, these are implementation details

   ;; feed this into loops to stop them. Very important  when everything hangs
   ;; Unless you just enjoy sitting around waiting for the JVM to
   ;; restart, of course
   stopper :- s/Symbol
   in<->ex-sock :- mq/InternalPair     ; messages from in-chan to ex-sock flow across these
   ;; It's tempting to make these zmq-socket/Socket instances
   ;; instead.
   ;; But mq/InternalPair was pretty much custom-written for this
   ;; scenario.
   async->sock :- mq/Socket  ; async half of in<->ex-sock
   ->zmq-sock :- mq/Socket ; 0mq half of in<->ex-sock
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
         (let [stopper (gensym)
               in<->ex-sock (mq/build-internal-pair! mq-ctx)
               ex-chan (async/chan)
               almost-started (assoc this
                                     :stopper stopper
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
        (when async-loop
          (if in-chan
            (let [[v c] (async/alts!! [[in-chan stopper] (async/timeout 750)])]
              (when-not v
                (log/error "Failed to deliver stop message to async channel. Attempting brute force")
                ;; Q: What does this even do?
                (async/close! async-loop)))
            (do
              (log/error "No channel for stopping async loop. Attempting brute force")
              (async/close! async-loop))))

        (if ex-chan
          (async/close! ex-chan)
          (log/info "No ex-chan. Assume this means we weren't actually started"))

        ;; N.B. These status updates are really pretty vital
        ;; and should be logged at the warning level, at the very least
        (comment) (log/debug "async-zmq Component: Waiting for Asynchronous Event Loop to exit")
        (comment (let [async-result (async/alts!! [async-loop (async/timeout 1500)])]
                   (comment) (log/debug "Asynchronous event loop exited with a status:\n"
                                        (util/pretty async-result))
                   (when-not async-result
                     )))
        ;; There doesn't seem to be a good way to check.
        ;; Trying to pull from its channel now fails with an IllegalArgumentException
        (log/debug "Assume that async loop didn't exit. Assume that it failed to signal 0mq loop to exit")
        (mq/send! async->sock (str stopper) :dont-wait)
        (comment) (log/debug "Waiting for 0mq Event Loop to exit")
        (let [zmq-result (async/alts!! [zmq-loop (async/timeout 150)])]
          (comment) (log/debug "0mq Event Loop exited with status:\n"
                               (util/pretty zmq-result)))
        (comment) (log/debug "Final cleanup")
        (mq/close-internal-pair! in<->ex-sock)
        (assoc this
               :stopper nil
               :in<->ex-sock nil
               :ex-chan nil
               :async-loop nil
               :zmq-loop nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

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
  [{:keys [async->sock in-chan stopper]} :- EventPair]
  (let [internal-> async->sock]
    (async/go
     (comment) (log/debug "Entering Async event thread")
     ;; TODO: Catch exceptions?
     (loop [val (async/<! in-chan)]
       (try
         (when val
           (log/debug "Incoming async message:\n"
                      (util/pretty val) "a" (class val)
                      "\nFrom internal. Forwarding to 0mq")
           ;; Have to serialize it here: can't
           ;; send arbitrary data across 0mq sockets
           (mq/send! internal-> (serialize val))
           (log/debug "Message forwarded"))
         (catch RuntimeException ex
           (log/error ex "Unexpected error in async loop"))
         (catch Exception ex
           (log/error ex "Unexpected bad error in async loop"))
         (catch Throwable ex
           (log/error ex "Things have gotten really bad in the async loop")))
       (when (and val (not= val stopper))
         (recur (<? in-chan)))))
    (comment)
    (log/debug "We either received the stop signal or the internal channel closed")
    :exited-successfully))

(s/defn possibly-recv-internal!
  "Really just refactored to make data flow more clear"
  [{:keys [->zmq-sock external-writer ex-sock]
    :as component} :- EventPair
   poller :- mq/Poller]
  ;; Message over internal notifier socket?
  (if (mq/in-available? poller 1)
    ;; Should almost definitely be using raw-recv! for
    ;; performance.
    ;; Which means the edn/read at the end needs to
    ;; deserialize instead.
    ;; Which probably kills whatever performance gain
    ;; I might hope for.
    ;; TODO: Find a profiler!
    (let [msg (mq/recv! ->zmq-sock)]
      (comment) (log/debug "Forwarding internal message\n"
                           (util/pretty msg)
                           "a" (class msg)
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
        (external-writer ex-sock msg)
        (catch RuntimeException ex
          (log/error ex)
          (throw)))
      (comment) (log/debug "Message forwarded")
      ;; Do we continue?
      (edn/read-string msg))))

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
      (log/debug "0mq Loop: Forwarding\n"
                 (util/pretty msg)
                 "a" (class msg)
                 "from outside to async")
      ;; This is actually inside a go block,
      ;; but this is where macros < special
      ;; forms. That go block is structurally
      ;; inside the function that calls this one,
      ;; so there's no way for this one to know
      ;; that we're in it.
      ;; N.B. This blocks the entire message loop
      ;; TODO: Switch to using alts!! and some sort
      ;; of timeout for scenarios where the other
      ;; end can't keep up
      (>!! ex-chan msg)
      (log/debug "0mq loop: Message forwarded"))))

(s/defn run-zmq-loop! :- fr-sch/async-channel
  [{:keys [ex-sock ->zmq-sock ex-chan external-reader externalwriter stopper]
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
                        (str "0mq: Received Internal:\n" (util/pretty received-internal?))
                        "0mq: received from external"))
           (when-not (= received-internal? stopper)
             (log/debug "Wasn't the kill message. Continuing.")
             (possibly-forward-msg-from-outside! component poller)
             (recur (mq/poll poller -1)))))
       (comment (log/debug "Cleaning up 0mq Event Loop"))
       :exited-successfully
       (catch NullPointerException ex
         (let [tb (->> ex .getStackTrace vec (map #(str % "\n")))
               msg (.getMessage ex)]
           (log/error ex msg "\n" tb))
         :null-pointer-exception)
       (catch RuntimeException ex
         (let [tb (->> ex .getStackTrace vec (map #(str % "\n")))
               msg (.getMessage ex)]
           (log/error ex "0mq Loop: Unhandled Runtime Exception\n" msg "\n" tb)))
       (catch Exception ex
         (let [tb (->> ex .getStackTrace vec (map #(str % "\n")))
               msg (.getMessage ex)]
           (log/error ex "0mq Loop: Unhandled Base Exception\n" msg "\n" tb)))
       (catch Throwable ex
         (let [tb (->> ex .getStackTrace vec (map #(str % "\n")))
               msg (.getMessage ex)]
           (log/error ex "0mq Loop: Unhandled Throwable\n" msg "\n" tb)))
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
