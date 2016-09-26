(ns com.frereth.common.zmq-socket
  "This should be a wrapper interface that hides as many low-level queue implementation details as possible"
  (:require [cljeromq.common :as mq-cmn]
            [cljeromq.core :as mq]
            [cljeromq.curve :as curve]
            [clojure.spec :as s]
            [com.frereth.common.schema :as schema]
            [com.frereth.common.util :as util]
            [com.stuartsierra.component :as component]
            [taoensso.timbre :as log])
  (:import [clojure.lang ExceptionInfo]
           [org.zeromq ZMQException]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

(s/def ::ctx  :cljeromq.common/context)
(s/def ::thread-count int?)
(s/def ::context-wrapper (s/keys :req-un [::ctx
                                          ::thread-count]))

(s/def ::client-keys :cljeromq.curve/key-pair)
(s/def ::port int?)
(s/def ::server-key :cljeromq.common/byte-array-type)
(s/def ::sock-type :cljeromq.common/socket-type)
(s/def ::socket-description (s/keys :opt-un [::client-keys
                                             ::server-key]
                                    :req-un [::ctx
                                             :cljeromq.common/direction
                                             ::port
                                             ::sock-type
                                             :cljeromq.common/socket
                                             :cljeromq.core/url]))
(s/def socket-description-ctor-opts
  (s/keys (opt-un [:cljeromq.common/direction])
          (:req-un ::sock-type :cljeromq.core/url)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Components

(defrecord ContextWrapper
    [ctx thread-count]
  component/Lifecycle
  (start
   [this]
   (if-not ctx
     (let [thread-count (or thread-count 1)
           ctx (mq/context thread-count)]
       (assoc this
              :ctx ctx
              :thread-count thread-count))
     this))
  (stop
   [this]
   (if ctx
     (do
       (log/debug "Terminating context")
       ;; Note that this is going to hang until
       ;; all sockets are closed
       (try
         (mq/terminate! ctx)
         (assoc this :ctx nil)
         (finally
           (log/debug "Context terminated, one way or another")
           (assoc this :ctx nil))))
     (do
       (log/debug "No 0mq messaging context to terminate")
       this))))

(defrecord SocketDescription
    [ctx
     direction
     port
     client-keys
     server-key
     sock-type
     socket
     url]
  component/Lifecycle
  (start
   [this]
   (if-not socket
     (do
       (assert ctx "Can't do anything without a Messaging Context")
       (assert url "Nowhere to connect")
       (comment) (log/debug "Getting ready to try to start a"
                            sock-type
                            "socket based on context\n"
                            (util/pretty ctx)
                            "a" (class ctx)
                            "\nat" url)
       (let [sock (mq/socket! (:ctx ctx) sock-type)]
         ;; Though this would make debugging/monitoring possible on an
         ;; internal network that needs to monitor traffic for security reasons.
         ;; And, for that matter, open internal comms make things like virus
         ;; and intrusion detection a little less impossible.
         ;; In those situations, should really be using proxies that MITM
         ;; to check all the traffic anyway.
         ;; TODO: Worry about that angle later.
         ;; This breaks most of the unit tests.
         ;; TODO: Make them add encryption
         (comment (assert server-key "Not allowing decrypted communications"))
         (when server-key
           ;;; Honestly, it's more complicated than this.
           ;;; If we want it to be a server, we might want to start out
           ;;; with the set of allowed client keys.
           ;;; That's something that really needs to be checked through zauth,
           ;;; which really isn't fully baked just yet.
           ;;; So go with this approach for now.
           (if client-keys
             (curve/prepare-client-socket-for-server! sock client-keys server-key)
             (curve/make-socket-a-server! sock server-key)))
         (try
           (let [uri (mq/connection-string url)]
             (if (= direction :bind)
               (mq/bind! sock uri)
               (mq/connect! sock uri)))
           (catch ExceptionInfo ex
             (log/error ex "Problem w/ connection to\n"
                        (util/pretty url)
                        "\nAre you having internet issues?")
             ;; TODO: Don't just swallow this error
             ;; But it's really convenient at dev time
             ))
         (assoc this :socket sock)))
     this))
  (stop
   [this]
   (log/debug "Possibly closing socket" socket)
   (if socket
     (do
       (try
         (mq/set-linger! socket 0)
         (mq/close! socket)
         (assoc this :socket nil)
         (catch ZMQException ex
           (log/error ex "Failed to close socket:" socket
                      "\nAre you trying to stop this a second time?"
                      "\n(if so, you probably have a bug where you should"
                      " be using the result of the first call to stop)")
           (assoc this :socket nil))))
     this)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public
;;; TODO: Really need to add wrappers for everything interesting,
;;; esp. send/recv

(s/fdef ctx-ctor
        :args (s/cat :options #(-> % (fnil :thread-count 1) int?))
        :ret ::context-wrapper)
(defn ctx-ctor
  "TODO: This doesn't belong in a socket namespace"
  [{:keys [thread-count]
    :or {thread-count 1}
    :as options}]
  (map->ContextWrapper options))

(s/fdef ctor
        :args (s/cat :options ::socket-description-ctor-opts)
        :ret ::socket-description)
(defn ctor
  [{:keys [client-keys direction server-key sock-type url]
    :or {direction :connect}
    :as options}]
  (map->SocketDescription options))
