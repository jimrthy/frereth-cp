(ns com.frereth.common.zmq-socket
  "This should be a wrapper interface that hides as many low-level queue implementation details as possible"
  (:require [cljeromq
             [common :as mq-cmn]
             [core :as mq]
             [curve :as curve]]
            [clojure.pprint :refer (pprint)]
            [clojure.spec :as s]
            [com.frereth.common
             [schema :as schema]
             [util :as util]]
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

(s/def ::client-keys (s/nilable :cljeromq.curve/key-pair))
(s/def ::port (s/nilable (s/and nat-int? #(< % 65536))))
(s/def ::public-server-key :cljeromq.curve/public)
(s/def ::private-server-key :cljeromq.curve/private)
(s/def ::sock-type :cljeromq.common/socket-type)
(s/def ::base-socket-description (s/keys :opt-un [::port]
                                         :req-un [::context-wrapper
                                                  :cljeromq.common/direction
                                                  ::sock-type
                                                  :cljeromq.common/socket
                                                  :cljeromq.common/zmq-url]))
;; It's very tempting to make the client/server keys optional. There are
;; organizations that very deliberately do not allow encrypted communications
;; across their internal network so they can monitor everything for malicious
;; anomalies.
;; And encryption is meaningless/pointless over inproc sockets.
;; TODO: Figure out a way to make these optional again
(s/def ::client-socket-description (s/and
                                    (s/merge ::base-socket-description
                                             (s/keys :opt-un [::client-keys]))
                                    #(if-let [server-key (:server-key %)]
                                       (s/valid? ::public-server-key server-key)
                                       %)))
(s/def ::server-socket-description
  (s/and ::base-socket-description
         #(if-let [server-key (:server-key %)]
            (s/valid? ::private-server-key server-key)
            %)))
(s/def ::socket-description (s/or :client ::client-socket-description
                                  :server ::server-socket-description))
(s/def socket-description-ctor-opts
  (s/keys (opt-un [:cljeromq.common/direction])
          (:req-un [::sock-type :cljeromq.common/zmq-url])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Components

;; TODO: Refactor this to the zmq-context namespace
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
    [context-wrapper
     direction
     port
     client-keys
     server-key
     sock-type
     socket
     zmq-url]
  component/Lifecycle
  (start
   [this]
   (if-not socket
     (do
       (when-not context-wrapper
         (assert context-wrapper
                 (str "Can't do anything without a Messaging Context\n"
                      "Available keys:\n"
                      (keys this))))
       (assert zmq-url "Nowhere to connect")
       (comment) (log/debug "Getting ready to try to create and start a"
                            sock-type
                            "socket based on context\n"
                            (util/pretty context-wrapper)
                            "a" (class context-wrapper)
                            "\nat" zmq-url)
       (let [sock (mq/socket! (:ctx context-wrapper) sock-type)]
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
         (let [uri (mq/connection-string zmq-url)]
           (if (= direction :bind)
             (try
               (mq/bind! sock uri)
               (catch ExceptionInfo ex
                 (let [cause (.getCause ex)
                       errno (.getErrorCode cause)]
                   ;; TODO: Find a symbolic constant to eliminate this magic number
                   ;; (it's EADDRINUSE)
                   (if (= 98 errno)
                     (log/error ex "Address already in use")
                     (log/error ex (str "Problem binding\n"
                                        (util/pretty zmq-url)
                                        "\nAre you having internet issues?"))))
                 (throw ex)))
             (try
               (mq/connect! sock uri)
               (catch ExceptionInfo ex
                 (log/error ex (str "Problem connecting to\n"
                                    (util/pretty zmq-url)
                                    "\nAre you having internet issues?"))
                 (throw ex)))))
         (log/info "Socket created/started successfully")
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
  [{:keys [client-keys direction server-key sock-type zmq-url]
    :or {direction :connect}
    :as options}]
  (map->SocketDescription options))
