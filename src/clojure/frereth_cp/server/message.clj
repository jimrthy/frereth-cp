(ns frereth-cp.server.message
  (:require [clojure.spec.alpha :as s]
            [frereth-cp.server.state :as state]
            [manifold.stream :as strm]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal helpers

(defn child-reader
  [buffer]
  ;; This may be something that needs to happen higher up in a
  ;; real message-specific ns that encompasses both client and
  ;; server.
  ;; Really, curvecpserver.c lines 425-427 cover everything that
  ;; needs to happen in here
  ;; Note the similarities to lines 351-355.
  ;; The part I was reference was probably the magic "* 16"
  ;; part of the protocol to get the byte count of the next
  ;; block in the queue.
  (throw (RuntimeException. "Where does this ball go?")))

(defn child-writer
  [buffer]
  ;; This really needs to encompass lines 453-495 of curvecpserver.c
  ;; I think I really should be seeing this exception now, when my
  ;; unit test echoes back its initial message.
  (throw (RuntimeException. "How do I get the messages back?")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef add-listener!
        :args (s/cat :state ::state/state
                     :child ::state/child-interaction)
        :ret strm/stream?)
(defn add-listener!
  [state
   {:keys [::state/client-ip
           ::state/client-port
           ::state/read<-child]
    :as child}]
  ;; I've turned this inside out by switching
  ;; the other side to use a pure callback mechanism,
  ;; instead of manifold. Maybe I should rethink
  ;; that choice, since I've at least set the
  ;; expectation here that I'd be handling incoming
  ;; messages like this instead.
  ;; Except that, really, this is an implementation
  ;; detail, and I'd very much like to keep these
  ;; implementations very distinct.
  ;; Besides, a function callback is guaranteed
  ;; to have less overhead than a queue insertion,
  ;; unless I wrote this side to require that
  ;; insertion in the callback.
  (strm/consume child-reader
                read<-child))
