(ns com.frereth.common.communication
  "This is really about higher-level messaging abstractions
Originally written over 0mq. There's an open question about
how useful they might be in the netty world."
  ;; One way or another, there's no excuse for referencing
  ;; cljeromq here.
  ;; Except possibly as a questionable optimization.
  ;; Well, and it was easy.
  (:require #_[cljeromq.common :as mq-cmn]
            #_[cljeromq.core :as mq]
            [clojure.spec :as s]
            [com.frereth.common.schema :as fr-sch]
            [com.frereth.common.util :as util]
            [hara.event :refer (raise)]
            [taoensso.timbre :as log]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;; Something at least vaguely similar to a REST
;; endpoint. Or maybe just something that would
;; typically go over a fairly standard message
;; queue.

;; Note that, in all honesty, this is pretty
;; inefficient.

(s/def ::major int?)
(s/def ::minor int?)
(s/def ::detail string?)
(s/def ::version (s/keys :req [::major ::minor ::detail]))
(s/def ::protocol #{::lolcatz})
(s/def ::protocol-version (s/keys :req [::protocol ::major ::minor ::detail]))

(s/def ::named (s/or :name string?
                     :keyed keyword?
                     :symbol symbol?))
(s/def ::header-key ::named)
(s/def ::headers (s/map-of ::header-key (complement nil?)))
(s/def ::locator (s/or :named ::named
                       :uuid uuid?))
(s/def ::parameters (s/map-of ::named (complement nil?)))
(s/def ::body string?)

;; Q: What about details like a lamport clock?
(s/def ::message (s/keys :req [::locator]
                         :opt [::headers ::parameters ::body]))
(s/def ::request (s/merge ::message
                          (s/keys :req [::protocol ::version])))

;; This is where having a higher-level typedef kind-of spec to distinguish between variants of bytes? seems tempting.

;; Need to ponder that temptation...do I really need to distinguish id's from, say, public-keys?

;; It seems like an obvious step to take, but that doesn't mean it will make the code better in the long run.

;; I guess the real question is:
;; Is it better to have an abstract named type predicate for specific pieces like this, or just stick with the
;; generic bytes? everywhere I'm using variations on that theme?
(s/def ::id bytes?)
(s/def ::addresses :com.frereth.common.schema/byte-array-seq)
;; This seems dubious. Will it ever be anything except byte-array(s)?
;; And any situations where I wouldn't want this marshalled?
(s/def ::contents identity)
(s/def ::router-message (s/keys :req [::id ::addresses ::contents]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn read-all!
  "N.B. Pretty much by definition, this is non-blocking, as-written.
This is almost definitely a bug"
  [s flags]
  (log/debug "read-all: Top")
  ;; It's very tempting to just do recv! here,
  ;; but callers may not need/want to take the time
  ;; to do the string conversion.
  ;; Besides, that's pretty silly for the initial
  ;; address/identifier frame(s)
  (throw (RuntimeException. "Rewrite that")))

(s/fdef extract-router-message
        :args (s/cat :frames :com.frereth.common.schema/byte-array-seq)
        :ret ::router-message)
(defn extract-router-message
  "Note that this limits the actual message to 1 frame of EDN"
  [frames]
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
;;;; parameter must be refactored to accept a zmq-socket/SocketDescription
;;;; instead
;;;; TODO: Make that so.

;;; :args is a regex that works like apply
;;; Supposed to handle multi-arity seamlessly.
;;; Q: How does this actually work?
(defn router-recv!
  ([s]
   (router-recv! s :wait))
  ([s flags]
   (when-let [all-frames (read-all! s flags)]
     (extract-router-message all-frames))))

(defn dealer-recv!
  "Really only for the simplest possible case"
  ([s]
   (dealer-recv! s :dont-wait))
  ([s flags]
   (when-let [frames (read-all! s flags)]
     ;; Assume we aren't proxying. Drop the NULL separator
     (let [content (drop 1 frames)]
       (assert (= 1 (count content)))
       (-> content first util/deserialize)))))

(defn dealer-send!
  "For the very simplest scenario, just mimic the req/rep empty address frames"
  ;; TODO: Add an arity that defaults to nil flags
  ([s
    frames
    flags]
   (throw (RuntimeException. "Also needs to be translated")))
  ([s frames]
   (dealer-send! s frames [])))

(defn router-send!
  ([sock
    msg]
   (router-send! sock msg []))
  ([sock
    msg
    flags]
   (when-let [contents (:contents msg)]
     (let [more-flags (conj flags :send-more)
           addresses (:addresses msg)]
       (throw (RuntimeException. "also needs to be translated"))))))
