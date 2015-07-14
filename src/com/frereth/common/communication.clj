(ns com.frereth.common.communication
  "This is really about higher-level messaging abstractions"
  (:require [cljeromq.core :as mq]
            [com.frereth.common.schema :as fr-sch]
            [ribol.core :refer (raise)]
            [schema.core :as s]
            [taoensso.timbre :as log]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schema

;; Something at least vaguely similar to a REST
;; endpoint. Or maybe just something that would
;; typically go over a fairly standard message
;; queue.

;; Note that, in all honesty, this is pretty
;; inefficient.
(def request {:version {:major s/Int
                        :minor s/Int
                        :detail s/Int}
              :protocol s/Str
              ;; For dispatching messages that arrive on the same socket
              ;; but are really directed toward different end-points
              (s/optional-key :channel) s/Str
              :headers {(s/either s/Str s/Keyword) s/Any}
              :locator s/Str  ; think URL
              (s/optional-key :parameters) {:s/Keyword s/Any}  ; think GET
              ;; It's very tempting for the body to be just another dict like
              ;; :parameters. But it seems like we need to have some justification
              ;; for including them both.
              ;; And sticking GET params in the URL has always seemed pretty suspect
              (s/optional-key :body) s/Str})

(def router-message
  "The contents are byte-arrays? Really??
Q: Is there ever any imaginable scenario where I
wouldn't want this to handle the marshalling?"
  {:id fr-sch/java-byte-array
   :addresses fr-sch/byte-arrays
   :contents fr-sch/byte-arrays
   ;; Without this, the message is useless
   ;; It seems like a waste of memory, but...
   ;; without this, the socket just has to be passed
   ;; into every function that uses it.
   ;; Realistically, that part's sitting inside an event loop.
   ;; So this gains us nothing.
   ;; TODO: Make this go away.
   :socket mq/Socket})

(def generic-router-message
  "Really pretty useless, except as an intermediate step"
  (dissoc router-message :socket))

;; More importantly, it conflicts with native
;; Java's URI. This will be confusing
(comment
  (def URI {:protocol s/Str
            :address s/Str
            :port s/Int}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/defn read-all! :- (s/maybe fr-sch/byte-arrays)
  "N.B. Pretty much by definition, this is non-blocking, as-written.
This is almost definitely a bug"
  [s :- mq/Socket
   flags :- fr-sch/korks]
  (log/debug "read-all3: Top")
  (loop [acc [mq/recv! s :dont-wait]
         more? (mq/has-more? s)]
    (if more?
      (do
        (log/debug "read-all: Reading more")
        (recur (conj acc (mq/raw-recv! s flags))
               (mq/has-more? s)))
      (do
        (log/debug "read-all: Done. Incoming:\n" acc)
        (seq acc)))))

(s/defn extract-router-message :- generic-router-message
  [frames :- fr-sch/byte-arrays]
  (log/debug "Extracting Router Message from "
             (count frames) " frames")
  (when-let [identity-frame (first frames)]
     (if-let [remainder (next frames)]
       ;; No, this approach isn't particularly efficient.
       ;; But we really shouldn't be dealing with many frames
       (let [address-frames (take-while #(< 0 (count %)) remainder)
             address-size (count address-frames)
             message-frames (drop (+ 2 address-size) remainder)]
         {:id identity-frame
          :addresses address-frames
          :contents message-frames})
       (raise {:how-did-this-happen? "We shouldn't be able to get an empty vector here, much less falsey"}))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(comment
  (s/defn build-url :- s/Str
     [url :- URI]
     (str (:protocol url) "://"
          (:address url)
          ;; port is meaningless for inproc
          (when-let [port (:port url)]
            (str ":" port)))))

(s/defn router-recv! :- (s/maybe router-message)
  ([s :- mq/Socket]
   (router-recv! s :wait))
  ([s :- mq/Socket
    flags :- fr-sch/korks]
   (when-let [all-frames (read-all! s flags)]
     (assoc (extract-router-message all-frames) :socket s))))

(s/defn dealer-recv! :- fr-sch/byte-arrays
  "Really only for the simplest possible case"
  ([s :- mq/Socket]
   (dealer-recv! s :dont-wait))
  ([s :- mq/Socket
   flags :- fr-sch/korks]
   (when-let [frames (read-all! s flags)]
     ;; Assume we aren't proxying. Drop the NULL separator
     (drop 1 frames))))

(s/defn dealer-send!
  "For the very simplest scenario, just mimic the req/rep empty address frames"
  ;; TODO: Add an arity that defaults to nil flags
  [s :- mq/Socket
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
    (mq/send! s (last frames) flags)))

(s/defn router-send!
  ([msg :- router-message]
   (router-send! msg nil))
  ([msg :- router-message
    flags :- fr-sch/korks]
   (when-let [contents (:contents msg)]
     (let [s (:socket msg)
           more-flags (conj flags :send-more)
           addresses (:addresses msg)]
       (mq/send! s (:id msg) more-flags)
       (if (seq? addresses)
         (doseq [addr addresses]
           (mq/send! s addr more-flags))
         ;; Empty address frame
         (mq/send! s (byte-array 0) more-flags))
       ;; This doesn't match schema.
       ;; This assumes :contents is a single frame
       ;; Schema declares it to be a seq of frames
       (dealer-send! s contents flags)))))

(comment
  (let [ctx (mq/context 3)
        sock (mq/socket! ctx :router)
        url "tcp://127.0.0.1:7843"
        _ (mq/bind! sock url)]
    (try
      (Thread/sleep 5000)
      (let [incoming (router-recv! sock)]
        (log/debug incoming)
        (router-send! (assoc incoming :contents "PONG"))
        incoming)
      (finally
        (mq/unbind! sock url)
        (mq/set-linger! sock 0)
        (mq/close! sock)
        (mq/terminate! ctx)))))

(raise {:not-implemented "Start here"})
(comment
  (def ctx (mq/context 3))
  (def sock (mq/socket! ctx :router))
  (def url "tcp://127.0.0.1:7843")
  (mq/bind! sock url)

  (def incoming (router-recv! sock))
  incoming
  (router-send! (assoc incoming :contents "PONG"))

  (mq/unbind! sock url)
  (mq/set-linger! sock 0)
  (mq/close! sock)
  (mq/terminate! ctx))
