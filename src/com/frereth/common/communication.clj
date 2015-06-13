(ns com.frereth.common.communication
  (:require [cljeromq.core :as mq]
            [com.frereth.common.schema :as fr-sch]
            [ribol.core :refer (raise)]
            [schema.core :as s]))

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

(def byte-arrays [fr-sch/java-byte-array])

(def router-message
  {:id fr-sch/java-byte-array
   :addresses byte-arrays
   :contents byte-arrays
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

(comment
  (s/defrecord URI [protocol :- s/Str
                    address :- s/Str
                    port :- s/Int]
    ;; TODO: This could really just as easily
    ;; be a plain dictionary.
    ;; More importantly, it conflicts with native
    ;; Java's URI. This will be confusing
    component/Lifecycle
    (start [this] this)
    (stop [this] this)))

(def URI {:protocol s/Str
          :address s/Str
          :port s/Int})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(s/defn read-all! :- (s/maybe byte-arrays)
  "N.B. Pretty much by definition, this is non-blocking, as-written.
This is almost definitely a bug"
  [s :- mq/Socket
   flags :- fr-sch/korks]
  (loop [acc []
         more? (mq/has-more? s)]
    (if more?
      (recur (conj acc (mq/raw-recv! s flags))
             (mq/has-more? s))
      (seq acc))))

(s/defn extract-router-message :- generic-router-message
  [frames :- byte-arrays]
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

(s/defn build-url :- s/Str
  [url :- URI]
  (str (:protocol url) "://"
       (:address url)
       ;; port is meaningless for inproc
       (when-let [port (:port url)]
         (str ":" port))))

(s/defn router-recv! :- (s/maybe router-message)
  ([s :- mq/Socket]
   (router-recv! s :wait))
  ([s :- mq/Socket
    flags :- fr-sch/korks]
   (when-let [all-frames (read-all! s flags)]
     (assoc (extract-router-message) :socket s))))

(s/defn dealer-recv! :- byte-arrays
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
  [s :- mq/Socket
   frames :- byte-arrays
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
   (let [s (:socket msg)
         more-flags (conj flags :send-more)
         addresses (:addresses msg)]
     (mq/send! s (:id msg) more-flags)
     (if (seq? addresses)
       (doseq [addr addresses]
         (mq/send! s addr more-flags))
       ;; Empty address frame
       (mq/send! s (byte-array 0) more-flags))
     (dealer-send! s (:contents msg) flags))))
