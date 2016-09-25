(ns com.frereth.common.async-zmq
  "Communicate among 0mq sockets and async channels.

Strongly inspired by lynaghk's zmq-async"
  (:require [cljeromq.common :as mq-cmn]
            [cljeromq.core :as mq]
            [clojure.core.async :as async :refer (>! >!!)]
            [clojure.edn :as edn]
            [clojure.spec :as s]
            [com.frereth.common.async-component]
            [com.frereth.common.schema :as fr-sch]
            [com.frereth.common.util :as util]
            [com.frereth.common.zmq-socket :as zmq-socket]
            [com.stuartsierra.component :as component]
            [component-dsl.system :as cpt-dsl]
            [full.async :refer (<? <?? alts? go-try)]
            [hara.event :refer (raise)]
            [taoensso.timbre :as log])
  (:import [com.frereth.common.async_component AsyncChannelComponent]
           [com.frereth.common.zmq_socket SocketDescription]
           [com.stuartsierra.component SystemMap]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

(s/def ::ex-chan :com.frereth.common.async-component/async-channel)
(s/def ::ex-sock :com.frereth.common.zmq-socket/socket-description)
(s/def ::external-reader (s/fspec :args (s/cat :sock :cljeromq.common/socket)
                                  :ret :cljeromq.common/byte-array-seq))
(s/def ::external-writer (s/fspec :args (s/cat :sock :cljeromq.common/socket
                                               :frames :cljeromq.common/byte-array-seq)))
(s/def ::in-chan :com.frereth.common.async-component/async-channel)

(s/def ::event-pair-interface (s/keys :unq-req [::ex-chan
                                                ::ex-sock
                                                ::external-reader
                                                ::external-writer
                                                ::in-chan]))

(s/def ::interface (s/keys :req-un [::ex-sock
                                    ::external-reader
                                    ::external-writer
                                    ::in-chan
                                    ::status-chan]))

;; This is the almost-constructed EventPair that gets passed in to the messaging loops
(s/def ::event-loopless-pair[:req-un [::->zmq-sock
                                      ::async-sock
                                      ::ex-chan
                                      ::in<->ex-sock
                                      ::interface
                                      ::_name
                                      ::stopper]])
(s/def ::event-pair (s/merge ::event-loopless-pair
                             (s/keys ::async-loop
                                     ::zmq-loop)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn do-signal-async-loop-exit
  "signal the async half of the event loop to exit"
  [async-loop interface stopper _name]
  (if-let [in-chan (->  interface :in-chan :ch)]
    (let [[v c] (async/alts!! [[in-chan stopper] (async/timeout 750)])]
      (if (= c in-chan)
        (log/debug _name ": Close signal submitted on" in-chan)
        (do
          (log/error _name ": Failed to deliver stop message to async channel. Attempting brute force")
          ;; Q: What does this even do?
          (try
            (async/close! async-loop)
            (catch IllegalArgumentException ex
              (log/error ex "Trying to force-close the Async Event Loop"
                         "\nApparently, this wasn't such a hot idea"))))))
    (do
      (log/error _name ": No channel for stopping async loop. Attempting brute force")
      (async/close! async-loop))))

(defn do-wait-for-async-loop-to-exit
  [_name async-loop stopper async->sock]
  (log/debug _name "-- async-zmq Component: Waiting for Asynchronous Event Loop" async-loop " to exit")
  (try
    (let [[async-result c] (async/alts!! [async-loop (async/timeout 1500)])]
      (if (= c async-loop)
        (log/debug _name ": Asynchronous event loop exited with a status:\n"
                   (util/pretty async-result))
        (do
          (log/warn "Asynchronous event loop failed to exit.
Assume that it failed to signal 0mq loop to exit.
Send a duplicate stopper ("
                    stopper
                    ")\nto" async->sock ", a"
                    (class async->sock))
          (if stopper
            (mq/send! async->sock (name stopper) :dont-wait)
            (log/info _name
                      ": Missing stopper. Hopefully this means we've already shut down")))))
    (catch IllegalArgumentException ex
      (log/error ex "Waiting for" async-loop "to exit."
                 "\nAs things stand, this seems to be functioning just fine."))))

(defn do-process-async-message
  "Refactored out of the loop to make it a little easier to read
  TODO: Change the parameters into a map (actually, just supply the Component)"
  [val c
   in-chan status-chan
   _name internal-> stopper in<->ex-chan]
  (let [in-chan (:ch in-chan)
        status-chan (:ch status-chan)])
  (try
    (if-not (nil? val)
      (if (= in-chan c)
        (do
          (log/debug _name "-- Incoming async message:\n"
                     (util/pretty val) "a" (class val)
                     "\nFrom internal. Forwarding to 0mq")
          ;; The try/catch is really just for debugging
          ;; TODO: Check performance timing to see whether this is acceptable to leave around.
          ;; This seems like a very likely candidate for being a performance hotspot
          (try
            (mq/send! internal-> "outgoing" 0)
            (catch Exception ex
              (log/error ex "Failed to send availability notification to internal->" internal->)
              (assert false)))
          (log/debug "0mq loop notified")
          ;; Q: Send via offer! instead?
          ;; TODO: Make this more granular to allow batch sends when
          ;; they make sense
          ;; TODO: 100 ms is far too long to wait here
          (let [[v c] (async/alts!! [[in<->ex-chan val] (async/timeout 100)])]
            (log/debug _name": Message" (if v
                                          "sent"
                                          "didn't get sent"))
            (when-not v
              (log/error _name ": Forwarding message timed out\nExpected channel:"
                         in<->ex-chan "\nTimeout channel:" c)
              ;; FIXME: Debug only
              ;; TODO: Catch this!
              (raise [:be-smarter])))

          (log/debug _name ": Message forwarded from Async side"))
        (if (= status-chan c)
          (do
            (let [msg (str _name " Async Status Request received on " c
                           "\n(which should be " status-chan
                           ")\nTODO: Something more useful"
                           "\nThe 0mq side is really much more interesting")]
              (log/debug msg))
            ;; Don't want to risk this blocking for very long
            ;; Note that we aren't technically inside a go block here, because
            ;; of macro scope
            (async/alts!! [(async/timeout 1) [val :everythings-fine]]))))
      (log/debug _name " Async Event Loop: Heartbeat\n"))
    ;; Exit when input channel closes or someone sends the 'stopper' gensym
    (catch RuntimeException ex
      (log/error ex "Unexpected error in async loop"))
    (catch Exception ex
      (log/error ex "Unexpected bad error in async loop"))
    (catch Throwable ex
      (log/error ex "Things have gotten really bad in the async loop")))
  ;; Tell the caller whether to continue
  ;; This doesn't belong in the same function as the side-effect
  ;; of handling the message. It's convenient, but
  ;; TODO: Refactor this into its own function
  (or
   (and val (not= val stopper))  ; got a message that wasn't stopper
   (and (not= c in-chan) (not= c status-chan))))

;; TODO: ^:always-validate
(s/fdef run-async-loop!
        :ret :com.frereth.common.schema/async-channel)
(defn run-async-loop!
  "Q: Would it make sense to convert this to some variant of an async/pipeline?

  It seems like a really obvious thing to do.
  But then we could have one thread trying to read while another tries to write,
  and that's a recipe for disaster."
  [{:keys [async->sock in<->ex-chan interface _name stopper] :as component}]
  (let [{:keys [in-chan status-chan]} interface
        in-chan (:ch in-chan)
        status-chan (:ch status-chan)
        internal-> async->sock
        minutes-5 (partial async/timeout (* 5 (util/minute)))]
    (async/go
      (log/debug "Top of"
                 _name
                 "Async event thread, based on:"
                 in-chan
                 "and"
                 status-chan
                 "\n")
      (try
        (loop [[val c] (async/alts! [in-chan status-chan (minutes-5)])]
          (log/debug (str _name " Async event thread received a message from "
                          (condp = c
                              in-chan "incoming channel"
                              status-chan "status channel"
                              "5 minute timeout")))
          ;; TODO: How many of these parameters should I just forward along as
          ;; part of interface or component, because they're no longer used in here?
          (when (do-process-async-message val c in-chan status-chan
                                          _name internal-> stopper
                                          in<->ex-chan)
            (recur (async/alts! [in-chan status-chan (minutes-5)]))))
        (catch Exception ex
          (log/error ex (str _name ": Async event thread exiting unexpectedly"))))
      (log/debug _name "Async Loop exited because we either received the stop signal or the internal channel closed")
      :exited-successfully)))

(s/fdef possibly-recv-internal!
        :args (s/cat :component ::event-pair
                     :poller :cljeromq.common/poller))
(defn possibly-recv-internal!
  "Really just refactored to make data flow less opaque"
  [{:keys [_name ->zmq-sock interface stopper in<->ex-chan]
    :as component}
   poller]
  (let [{:keys [ex-sock external-writer]} interface]
    ;; Message over internal notifier socket?
    (if (mq/in-available? poller 1)
      ;; Should almost definitely be using raw-recv! for
      ;; performance.
      ;; Which means the edn/read at the end needs to
      ;; deserialize instead.
      ;; Which probably kills whatever performance gain
      ;; I might hope for.
      ;; TODO: Find a profiler!
      (let [exited (atom false)
            ;; Don't really care about the payload. This was just a
            ;; notification that there is at least one message pending on
            ;; the async channel.
            ;; Or, at least, there will be very soon.
            msg (mq/recv! ->zmq-sock)
            deserialized (util/deserialize msg)]
        (log/debug _name ": from internal -- " msg "\naka\n" deserialized "\na" (class deserialized))

        ;; That's just a signal that messages
        ;; are available async channel.
        ;; TODO: Be smarter about not spending too much time here.
        ;; Remember: I'm not processing any incoming requests while this loops
        ;; TODO: update to poll! when there's a core.async release
        ;; that supports it
        ;; TODO: Split the read/write threads. Don't want a misbehaving client
        ;; to keep the server from communicating with all the rest.
        ;; Then again, since sockets aren't thread safe, that would mean
        ;; two different sockets. Which I don't think I want.
        (loop [[msg c] (async/alts!! [(async/timeout 100) in<->ex-chan])]
          (when msg
            (reset! exited msg)
            (when (not= msg stopper)
              (do
                (log/debug _name ": Not stopper. Forwarding\n" msg)
                (try
                  (external-writer (:socket ex-sock) msg)
                  (log/debug _name "Message forwarded to 0mq")
                  (catch RuntimeException ex
                    (log/error ex "Trying to forward to 0mq socket:" ex-sock)
                    ;; this shouldn't disturb the overall system
                    ;; operation...but this really does indicate a
                    ;; fatal error that should have been caught during
                    ;; development.
                    ;; This indicates a pretty thoroughly broken
                    ;; foundation.
                    (raise {:problem ex
                            :details {:socket-wrapper ex-sock
                                      :message msg
                                      :external-writer external-writer
                                      :component component}})))
                ;; TODO: Update this part when we get a core.async that supports poll!
                (recur (async/alts!! [(async/timeout 100) in<->ex-chan]))))))
        @exited))))

(s/fdef possibly-forward-msg-from-outside!
        :args (s/cat :component ::event-pair
                     :poller :cljeromq.common/poller))
(defn possibly-forward-msg-from-outside!
  [{:keys [interface ex-chan _name]
    :as component}
   poller]
  ;; Message coming in from outside?
  (when (mq/in-available? poller 0)
    (let [{:keys [external-reader ex-sock]} interface
          real-ex-chan (:ch ex-chan)]
      ;; TODO: Would arguably be more
      ;; efficient to loop over all available
      ;; messages in case several arrive at once.
      ;; The most obvious downside to that approach
      ;; is a DDoS that locks us into that forever
      (let [msg (external-reader (:socket ex-sock))]
        ;; Forward it along
        (log/debug _name " 0mq Loop: Forwarding\n"
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
        (let [[sent? c] (async/alts!! [[real-ex-chan msg] (async/timeout 250)])]
          (when-not sent?
            (raise {:q "How can I debug this?"
                    :problem "0mq loop: forwarding message from outside to async loop timed out"
                    :details {:component component
                              :dst ex-chan}})))
        (log/debug _name "0mq loop: Message forwarded")))))

(defn actual-zmq-loop
  [component poller]
  (let [stopper (:stopper component)
        five-minutes (* 1000 60 5)  ; in milliseconds
        _name (:_name component)]
    (try
      ;; When we shut down the socket/context, this poll call gets the rug
      ;; yanked out from under it and fails.
      ;; This shows up as an erroneous error at the end of shut down.
      ;; It's ugly, and it distracts from real errors.
      ;; TODO: Detect this perfectly reasonable state and handle it gracefully.
      ;; Better TODO: Add another "Stop this" socket and send a message to it so we
      ;; know that it's time to do something.
      (loop [available-sockets (mq/poll poller five-minutes)]
        (log/debug _name ": 0mq loop activated with" available-sockets "available")
        (if (< 0 available-sockets)
          (let [received-internal? (possibly-recv-internal! component poller)]
            ;; TODO: Query the poller first, to find out
            (log/debug (if received-internal?
                         (str (:_name component) " 0mq: Received Internal:\n"
                              (util/pretty received-internal?))
                         (str (:_name component)
                              " 0mq: must have been a message from external")))
            (if-not (= received-internal? stopper)
              (do
                (log/debug (:_name component) "Wasn't the kill message. Continuing.")
                (possibly-forward-msg-from-outside! component poller)
                ;; This seems to be failing. Q: What's going on?
                (log/debug "Polling on" poller "a" (class poller) "again")
                (recur (mq/poll poller five-minutes)))
              (do
                (log/info (:_name component) "Killed by" received-internal?)
                :exited-successfully)))
          (do
            (log/debug _name ": 0mq Event Loop: Heartbeat")
            (recur (mq/poll poller five-minutes)))))
      ;; TODO: Switch to mq/zmq-exception
      ;; Or maybe just rename that so I can use mq/exception
      (catch org.zeromq.ZMQException ex
        (log/error ex "Unhandled 0mq Exception. 0mq loop exiting")
        :unhandled-0mq-exception))))

;; TODO: ^:always-validate
(s/fdef run-zmq-loop!
        :ret :com.frereth.common.schema/async-channel
        :args (s/cat :component ::event-pair))
(defn run-zmq-loop!
  [{:keys [interface ->zmq-sock ex-chan _name]
    :as component}]
  (let [{:keys [ex-sock external-reader externalwriter]} interface
        poller (mq/poller 2)]
    (mq/register-socket-in-poller! (:socket ex-sock) poller)
    (mq/register-socket-in-poller! ->zmq-sock poller)
    (go-try
     (comment (log/debug "Entering 0mq event thread"))
     (try
       ;; Move the actual functionality into its own function
       ;; so that it isn't buried here in the middle of all this
       ;; error handling
       (let [result (actual-zmq-loop component poller)]
         (comment) (log/debug "Cleaning up 0mq Event Loop")
         result)
       (catch org.zeromq.ZMQException ex
         (let [tb (->> ex .getStackTrace vec (map #(str % "\n")))
               msg (.getMessage ex)]
           (log/error ex msg "\n" tb))
         :zmq-exception)
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
         (try
           (println _name " Cleaning up at end of 0mq Event Loop")
           (mq/unregister-socket-in-poller! poller (:socket ex-sock))
           (mq/unregister-socket-in-poller! poller ->zmq-sock)
           (catch RuntimeException ex
             (log/error ex _name " 0mq Event Loop cleanup failed"))
           (finally
             (log/debug "Exiting 0mq Event Loop"))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Components

(defrecord EventPairInterface
    [;; send messages to this' async-chan to get them to 0mq.
     in-chan
     ;; faces outside world.
     ;; Caller provides, because binding/connecting is really not in scope here
     ex-sock
     ;; external-reader and -writer should be simple for
     ;; everything except router/dealer (which is what
     ;; I'll be using, of course).
     ;; dealer really just needs to cope with an empty address
     ;; separator frame
     ;; reader has to handle things like socket registration,
     ;; reconnecting dropped sessions, etc.
     ;; Luckily (?) these are the server writer's problems.
     ;; TODO: Refactor-rename these to just reader/writer
     external-reader
     ;; I *think* this returns bool, but, honestly,
     ;; it should return nil
     external-writer
     ;; For requesting status messages
     ;; Put the channel where you want the response
     status-chan]
  component/Lifecycle
  (start
      [this]
    (assert in-chan "Caller must supply the input channel")
    (assert status-chan "Caller must supply the status request channel")
    (cond-> this
      ;; Set up default readers/writers
      ;; If they weren't already supplied.
      (not external-reader) (assoc
                             :external-reader
                             (fn [sock]
                               ;; It's tempting to default
                               ;; to :dont-wait
                               ;; But we shouldn't ever
                               ;; try reading this unless
                               ;; a Poller just verified
                               ;; that messages are waiting.
                               ;; Note that we probably never want this
                               ;; default behavior.
                               ;; This really needs to demarshall
                               ;; the message and analyze it before
                               ;; tagging it with whatever info
                               ;; really needs to be done.
                               ;; Still, there might be some
                               ;; apps where this is enough.
                               (mq/raw-recv! sock :wait)))
      (not external-writer) (assoc
                             :external-writer
                             (fn [sock array-of-bytes]
                               ;; Same comments re: over-simplicity
                               ;; in the default reader apply here
                               (mq/send! sock array-of-bytes)))))
  (stop
      [this]
    (assoc this
           :in-chan nil
           :status-chan nil)))

(defrecord EventPair
  [_name  ; Because trying to figure out which is what is driving me crazy

   interface

   ;; 0mq puts messages onto here when they come in from outside
   ;; Read its internal async-channel
   ex-chan

   ;; Really, these are implementation details

   ;; feed this into loops to stop them. Very important when everything hangs
   ;; Unless you just enjoy sitting around waiting for the JVM to
   ;; restart, of course
   stopper
   ;; Signals the 0mq portion of the loop that messages are ready to send
   ;; to the outside world
   in<->ex-sock
   ;; It's tempting to make these zmq-socket/Socket instances
   ;; instead.
   ;; But mq/InternalPair was pretty much custom-written for this
   ;; scenario.
   ;; Splitting them like this (instead of whatever cljeromq names them
   ;; in in<->ex-sock) is really just a convenience to help me remember
   ;; which is which
   async->sock  ; async half of in<->ex-sock
   ->zmq-sock  ; 0mq half of in<->ex-sock

   ;; After async->sock notifies ->zmq-sock that messages are ready to
   ;; go, pull them from here.
   in<->ex-chan

   async-loop  ; thread where the async event loop is running
   zmq-loop    ; thread where the 0mq event loop is running
   ]
  component/Lifecycle
  (start [this]
    "Set up two entertwined event loops running in background threads.

Their entire purpose in life, really, is to shuffle messages between
0mq and core.async"
    (assert interface "Missing the entire external interface")
    (let [{:keys [ex-sock in-chan status-chan]} interface]
      (assert ex-chan "Missing outgoing channel")
      (assert ex-sock "Missing exterior socket")

      ;; TODO: Need channel(s) to write to for handling incoming
      ;; messages.
      ;; These can't be in-chan: the entire point to this
      ;; architecture is to do the heavy lifting of both reading
      ;; and writing.
      (let [stopper (gensym)
            in<->ex-sock (or in<->ex-sock (mq/build-internal-pair!
                                           (-> ex-sock :ctx :ctx)))
            in<->ex-chan (or in<->ex-chan (async/chan))
            almost-started (assoc this
                                  :stopper stopper
                                  :in<->ex-chan in<->ex-chan
                                  :in<->ex-sock in<->ex-sock
                                  :->zmq-sock (:rhs in<->ex-sock)
                                  :async->sock (:lhs in<->ex-sock))
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
               :zmq-loop zmq-loop))))
  (stop [this]
        (when async-loop
          (do-signal-async-loop-exit async-loop
                                     interface stopper _name)
          (log/debug _name ": Waiting for Async Loop " async-loop " to exit")
          (do-wait-for-async-loop-to-exit _name async-loop stopper async->sock)
          (log/debug _name ": async loop exited"))

        (if in<->ex-chan
          (async/close! in<->ex-chan)
          (log/info _name ": No in<->ex-chan. Assume this means we weren't actually started"))

        (when zmq-loop
          ;; If the async part of the loop is gone, we didn't get the notification
          ;; to the 0mq half that it should exit
          (log/debug _name ": Waiting for 0mq Event Loop to exit")
          (let [[zmq-result c] (async/alts!! [zmq-loop (async/timeout 150)])]
            (if (= c zmq-loop)
              (log/debug _name ": 0mq Event Loop exited with status:\n"
                                 (util/pretty zmq-result))
              (do
                (log/warn _name "Timed out waiting for zmq-loop to exit; trying to force it")
                (try
                  (async/close! zmq-loop)
                  (catch Exception ex
                    (log/error ex (str "\n" _name ": Failure trying to close the go loop. Did you really expect this to work?"))))))))
        (when in<->ex-sock
          (comment) (log/debug _name ": Final cleanup")
          (mq/close-internal-pair! in<->ex-sock))
        (log/debug _name ": finished cleaning up")
        (assoc this
               :stopper nil
               :in<->ex-sock nil
               :async->sock nil
               :->zmq-sock nil
               :in<->ex-chan nil
               :ex-chan nil
               :async-loop nil
               :zmq-loop nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef status-check
        :args (s/cat :event-pair ::event-pair)
        ;; TODO: Be more explicit about what can be returned
        :ret any?)
(defn status-check
  "Really just a synchronous wrapper over the basic idea"
  [event-pair]
  (let [interface (:interface event-pair)
        status-chan (:status-chan interface)
        status-out (async/chan)]
    (async/>!! status-chan status-out)
    (async/<!! status-out)))

(s/fdef  ctor-interface
         :args (s/cat :cfg (s/keys :unq-opt [::ex-sock ::in-chan ::external-reader ::external-writer]))
         :ret ::event-pair-interface)
(defn ctor-interface
  [cfg]
  (map->EventPairInterface (select-keys cfg [:ex-sock :in-chan :external-reader :external-writer])))

(s/fdef ctor
        :args (s/cat :cfg (s/keys :unq-opt [:_name]))
        :ret ::event-pair)
(defn ctor
  [cfg]
  (map->EventPair (select-keys cfg [:_name])))

;;; I keep being surprised that I don't have a unified Component that wraps those
;;; two into a neat little bow. They're so tightly coupled that I can't imagine
;;; ever wanting one without the other.

;;; That's in the system namespace.
;;; Can't really move the definition into here because I wind up with this namespace
;;; trying to (require) itself when I try to start the System.
