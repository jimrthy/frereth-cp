(ns com.frereth.common.communication
  "This is really about higher-level messaging abstractions"
  (:require [cljeromq.common :as mq-cmn]
            [cljeromq.core :as mq]
            [clojure.spec :as s]
            [com.frereth.common.schema :as fr-sch]
            [com.frereth.common.util :as util]
            [hara.event :refer (raise)]
            [schema.core :as s2]
            [taoensso.timbre :as log]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

;; Something at least vaguely similar to a REST
;; endpoint. Or maybe just something that would
;; typically go over a fairly standard message
;; queue.

;; Note that, in all honesty, this is pretty
;; inefficient.
(def request {:version {:major s2/Int
                        :minor s2/Int
                        :detail s2/Int}
              :protocol s2/Str
              ;; For dispatching messages that arrive on the same socket
              ;; but are really directed toward different end-points
              (s2/optional-key :channel) s2/Str
              :headers {(s2/either s2/Str s2/Keyword) s2/Any}
              :locator s2/Str  ; think URL
              (s2/optional-key :parameters) {:s2/Keyword s2/Any}  ; think GET
              ;; It's very tempting for the body to be just another dict like
              ;; :parameters. But it seems like we need to have some justification
              ;; for including them both.
              ;; And sticking GET params in the URL has always seemed pretty suspect
              (s2/optional-key :body) s2/Str})

(s/def ::major int?)
(s/def ::minor int?)
(s/def ::detail string?)
(s/def ::version (s/keys :req [::major ::minor::detail]))
(s/def ::protocol #{::lolcatz})
(s/def ::header-key (s/or :name string?
                          :keyed keyword?
                          :symbol symbol?))
(s/def ::headers (s/map-of ::header-key (complement nil?)))
;;; Note that it really *is* pretty inefficient to include the boilerplate with every request.
;;; Should really just negotiate the protocol version during the initial handshake.
(s/def ::request (s/keys :req [::version ::protocol]
                         :opt [::headers]))

(def router-message
  "The contents are byte-arrays? Really??
Q: Is there ever any imaginable scenario where I
wouldn't want this to handle the marshalling?"
  {:id fr-sch/java-byte-array
   :addresses fr-sch/byte-arrays
   :contents s2/Any})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s2/defn read-all! :- (s2/maybe fr-sch/byte-arrays)
  "N.B. Pretty much by definition, this is non-blocking, as-written.
This is almost definitely a bug"
  [s ;  :- mq/Socket ;;
   flags :- fr-sch/korks]
  (log/debug "read-all: Top")
  ;; It's very tempting to just do recv! here,
  ;; but callers may not need/want to take the time
  ;; to do the string conversion.
  ;; Besides, that's pretty silly for the initial
  ;; address/identifier frame(s)
  (when-let [initial-frame (mq/raw-recv! s :dont-wait)]
    (loop [acc [initial-frame]
           more? (mq/has-more? s)]
      (if more?
        (do
          (log/debug "read-all: Reading more")
          (recur (conj acc (mq/raw-recv! s flags))
                 (mq/has-more? s)))
        (do
          (when-let [result (seq acc)]
            (println "Incoming: " result)
            (println "has: " (count result) "entries")
            (log/debug "read-all: Done. Incoming:\n" (map #(String. %) result))
            result))))))

(s2/defn extract-router-message :- router-message
  "Note that this limits the actual message to 1 frame of EDN"
  [frames :- fr-sch/byte-arrays]
  (log/debug "Extracting Router Message from "
             (count frames) " frames")
  (when-let [identity-frame (first frames)]
     (if-let [remainder (next frames)]
       ;; No, this approach isn't particularly efficient.
       ;; But we really shouldn't be dealing with many frames
       ;; The address frames are the ones between the identifier and the NULL separator
       (let [address-frames (take-while #(< 0 (count %)) remainder)
             address-size (count address-frames)
             message-frames (drop (inc address-size) remainder)]
         (when (not= 1 (count message-frames))
           (raise {:problem :multi-frame-message
                   :details {:id identity-frame
                             :addresses address-frames
                             :address-size address-size
                             :contents message-frames}}))
         (try
           (let [contents (-> message-frames first util/deserialize)]
             {:id identity-frame
              :addresses address-frames
              :contents contents})
           (catch RuntimeException ex
             (log/error ex
                        "\nCaused by:\n"
                        (util/pretty message-frames)
                        "\n\nVery tempting to make this fatal during dev time"
                        "\nBut a misbehaving client should not be able to disrupt the server"))))
       (raise {:how-did-this-happen? "We shouldn't be able to get an empty vector here, much less falsey"}))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

;;;; Pretty much everything that follows that takes an mq/Socket
;;;; parameter should be refactored to accept a zmq-socket/SocketDescription
;;;; instead
;;;; TODO: Make that so.
(s2/defn router-recv! :- (s2/maybe router-message)
  ([s :- mq-cmn/Socket]
   (router-recv! s :wait))
  ([s :- mq-cmn/Socket
    flags :- fr-sch/korks]
   (when-let [all-frames (read-all! s flags)]
     (extract-router-message all-frames))))

(s2/defn dealer-recv! :- s2/Any
  "Really only for the simplest possible case"
  ([s :- mq-cmn/Socket]
   (dealer-recv! s :dont-wait))
  ([s :- mq-cmn/Socket
   flags :- fr-sch/korks]
   (when-let [frames (read-all! s flags)]
     ;; Assume we aren't proxying. Drop the NULL separator
     (let [content (drop 1 frames)]
       (assert (= 1 (count content)))
       (-> content first util/deserialize)))))

(s2/defn dealer-send!
  "For the very simplest scenario, just mimic the req/rep empty address frames"
  ;; TODO: Add an arity that defaults to nil flags
  ([s :- mq-cmn/Socket
    frames :- fr-sch/byte-arrays
    flags :- fr-sch/korks]
   (let [more-flags (conj flags :send-more)]
     ;; Separator frame
     ;; In theory, this could just be acting as a
     ;; proxy and forwarding along messages.
     ;; In practice, I don't see that use case
     ;; ever happening here.
     (mq/send! s (byte-array 0) more-flags)
     (doseq [frame (butlast frames)]
       (mq/send! s frame more-flags))
     (log/debug "Wrapping up dealer send w/ final frame:\n" (last frames)
                "\na " (class (last frames)))
     (mq/send! s (util/serialize (last frames)) flags)))
  ([s :- mq-cmn/Socket
    frames :- fr-sch/byte-arrays]
   (dealer-send! s frames [])))

(s2/defn router-send!
  ([sock :- mq-cmn/Socket
    msg :- router-message]
   (router-send! sock msg []))
  ([sock :- mq-cmn/Socket
    msg :- router-message
    flags :- fr-sch/korks]
   (when-let [contents (:contents msg)]
     (let [more-flags (conj flags :send-more)
           addresses (:addresses msg)]
       (try
         (mq/send! sock (:id msg) more-flags)
         (catch NullPointerException ex
           (log/error ex "Trying to send " (:id msg) "\nacross " sock
                      "\nusing flags: " more-flags)))

       (if (seq? addresses)
         (doseq [addr addresses]
           (mq/send! sock addr more-flags)))
       ;; Note that dealer-send will account for the NULL separator
       (if (string? contents)
         (dealer-send! sock [contents] flags)
         (if (or (seq? contents) (vector? contents))
           (dealer-send! sock contents flags)
           (dealer-send! sock[contents] flags)))))))

(comment
  (let [ctx (mq/context 3)
        sock (mq/socket! ctx :router)
        url "tcp://127.0.0.1:7843"
        _ (mq/bind! sock url)]
    (try
      (Thread/sleep 5000)
      (let [incoming (router-recv! sock)]
        (log/debug incoming)
        (router-send! sock (assoc incoming :contents "PONG"))
        incoming)
      (finally
        (mq/unbind! sock url)
        (mq/set-linger! sock 0)
        (mq/close! sock)
        (mq/terminate! ctx)))))

(comment
  (def ctx (mq/context 3))
  (def sock (mq/socket! ctx :router))
  (def url "tcp://127.0.0.1:7843")
  (mq/bind! sock url)

  (def incoming (router-recv! sock))
  incoming
  (router-send! sock (assoc incoming :contents "PONG"))

  (def raw-frames (read-all! sock :dont-wait))
  raw-frames

  (mq/unbind! sock url)
  (mq/set-linger! sock 0)
  (mq/close! sock)
  (mq/terminate! ctx))
