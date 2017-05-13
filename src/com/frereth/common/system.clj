(ns com.frereth.common.system
  "This is another one that doesn't make a lot of sense"
  (:require #_[cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.spec :as s]
            [com.frereth.common.async-component]
            [com.frereth.common.curve.shared :as curve]
            [component-dsl.system :as cpt-dsl]
            [hara.event :refer (raise)])
  (:import [com.stuartsierra.component SystemMap]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(s/fdef build-event-loop-description
        :args (s/cat :options (s/keys :unq-opt {::client-keys ::curve/client-keys
                                                ; ::direction :cljeromq.common/direction
                                                ::server-key ::curve/public-key
                                                ; ::socket-type :cljeromq.common/socket-type
                                                }
                                      :unq-req {::context :com.frereth.common.zmq-socket/context-wrapper
                                                ::event-loop-name string?
                                                ::url ::curve/url}))
        :ret :component-dsl.system/nested-definition)
(defn build-event-loop-description
  "Return a component description that's suitable for nesting into yours to pass along to cpt-dsl/build

For running as an integrated library

At one point I thought I was really jumping the gun on this one.
It provides a decent example, but it really seems to just belong
inside frereth.client.

And frereth.server. And, if there's ever a 'real' stand-alone
frereth.renderer, there.

So this abstraction absolutely does belong in common.

It seems to make less sense under the system namespace, but
I'm not sure which alternatives make more sense."
  [{:keys [client-keys
           context
           direction
           event-loop-name
           server-key
           socket-type
           thread-count
           url]
    :or {direction :connect
         socket-type :dealer
         thread-count 2}}]
  (let [url #_(cond-> url
              (not (:cljeromq.common/zmq-protocol url)) (assoc :cljeromq.common/zmq-protocol :tcp)
              (not (:cljeromq.common/zmq-address url)) (assoc :cljeromq.common/zmq-address [127 0 0 1])
              (not (:cljeromq.common/port url)) (assoc :cljeromq.common/port 9182))
        (throw (RuntimeException. "What makes sense here?"))]
    (let [options {::context {:thread-count thread-count}
                   ::event-loop {:_name event-loop-name}
                   ::ex-sock {:zmq-url url
                              :direction direction
                              :sock-type socket-type}}
          ;; TODO: Improve component-dsl so I can override
          ;; the values here with a dependency on
          ;; an external context
          ;; the way I need to for frereth-client.
          ;; That needs a bunch of these, but there's no reason
          ;; (?) to create multiple contexts.
          ;; Then again...is there a serious reason not to?
          ;; (from Pieter Hintjens: not really. Although newer
          ;; [post 3.1] versions do offer some nice API conveniences,
          ;; such as cleaning up all the associated sockets when
          ;; you delete the context).
          ;; Oh, and inproc sockets from different contexts can't
          ;; communicate.
          ;; OTOH, this sort of dependency injection is one of
          ;; the main selling points behind Components
          struc '{;; Q: Does it make sense to come up with something
                  ;; to explicitly replace the 0mq Context?
                  ;; We definitely do need netty/aleph loops,
                  ;; but the client/server implementations are
                  ;; quite different. And small enough that it
                  ;; doesn't seem worth the effort to try to
                  ;; refactor out the common parts.
                  ;; ::context com.frereth.common.zmq-socket/ctor
                  ;; These next two seem more difficult/vital to replace
                  ;; ::event-loop com.frereth.common.async-zmq/ctor
                  ;; ::evt-iface com.frereth.common.async-zmq/ctor-interface
                  ::ex-chan com.frereth.common.async-component/chan-ctor
                  ;; And...I'm not sure how I'll even start to replace
                  ;; this.
                  ;; If/when I really need to.
                  ;; ::ex-sock com.frereth.common.zmq-socket/ctor
                  ::in-chan com.frereth.common.async-component/chan-ctor
                  ::status-chan com.frereth.common.async-component/chan-ctor}
          deps {::evt-iface {:ex-sock ::ex-sock
                             :in-chan ::in-chan
                             :status-chan ::status-chan}
                ::event-loop {:interface ::evt-iface
                              :ex-chan ::ex-chan}
                ::ex-sock {:context-wrapper ::context}}
          description {:component-dsl.system/structure struc
                       :component-dsl.system/dependencies deps}]
      #:component-dsl.system{:system-configuration description
                             :configuration-tree options
                             :primary-component ::event-loop})))
