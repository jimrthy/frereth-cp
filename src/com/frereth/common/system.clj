(ns com.frereth.common.system
  "This is another one that doesn't make a lot of sense"
  (:require [cljeromq.core :as mq]
            [clojure.core.async :as async]
            [clojure.spec :as s]
            [com.frereth.common.async-component]
            [component-dsl.system :as cpt-dsl]
            [hara.event :refer (raise)])
  (:import [com.stuartsierra.component SystemMap]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Specs


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn build-event-loop-broken
  "For running as an integrated library inside the Renderer

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
           url]
    :or {socket-type :dealer
         direction :connect}}]
  ;;; Q: Is this still true?
  (throw (ex-info "Just flat-out doesn't work" {:problem "Nested SystemMap doesn't correctly receive dependencies"}))
  (let [url (cond-> url
              (not (:protocol url)) (assoc :protocol :tcp)
              (not (:address url)) (assoc :address [127 0 0 1])
              (not (:port url)) (assoc :port 9182))]
    (let [defaults {:event-loop {:_name event-loop-name}
                    :ex-sock {:url url
                              :direction direction
                              :sock-type socket-type
                              :ctx context}}
          struc '#:frereth.com.common{:event-loop com.frereth.common.async-zmq/ctor
                                      :evt-iface com.frereth.common.async-zmq/ctor-interface
                                      :ex-chan com.frereth.common.async-component/chan-ctor
                                      :ex-sock com.frereth.common.zmq-socket/ctor
                                      :in-chan com.frereth.common.async-component/chan-ctor
                                      :status-chan com.frereth.common.async-component/chan-ctor}
          deps '#:frereth.com.common{:evt-iface {:ex-sock :frereth.com.common/ex-sock
                                                 :in-chan :frereth.com.common/in-chan
                                                 :status-chan :frereth.com.common/status-chan}
                                     :event-loop {:interface :frereth.com.common/evt-iface
                                                  :ex-chan :frereth.com.common/ex-chan}}
          description #:component-dsl.system{:structure struc
                                             :dependencies deps}
          default-result (cpt-dsl/build description defaults)]
      default-result)))

(s/fdef build-event-loop-description
        :args (s/cat :options (s/keys :unq-opt {::client-keys :cljeromq.curve/key-pair
                                                ::direction :cljeromq.common/direction
                                                ::server-key :cljeromq.common/byte-array-type
                                                ::socket-type :cljeromq.common/socket-type}
                                      :unq-req {::context :com.frereth.common.zmq-socket/context-wrapper
                                                ::event-loop-name string?
                                                ::url :cljeromq.core/zmq-url}))
        :ret :component-dsl.system/nested-definition)
(defn build-event-loop-description
  "Return a component description that's suitable for merging into yours to pass along to cpt-dsl/build"
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
  (let [url (cond-> url
              (not (:protocol url)) (assoc :protocol :tcp)
              (not (:address url)) (assoc :address [127 0 0 1])
              (not (:port url)) (assoc :port 9182))]
    (let [options {::context {:thread-count thread-count}
                   ::event-loop {:_name event-loop-name}
                   ::ex-sock {:url url
                              :direction direction
                              :sock-type socket-type}}
          ;; TODO: Improve component-dsl so I can pass in an
          ;; already-created instance the way I need to for frereth-client.
          ;; Actually, I'm just trying to supply my own ctor.
          ;; Which really should work fine.
          ;; Note that I need to unquote this.
          struc `{::context #_(if context
                               context
                               com.frereth.common.zmq-socket/ctx-ctor)
                  com.frereth.common.zmq-socket/ctx-ctor
                  ::event-loop com.frereth.common.async-zmq/ctor
                  ::evt-iface com.frereth.common.async-zmq/ctor-interface
                  ::ex-chan com.frereth.common.async-component/chan-ctor
                  ::ex-sock com.frereth.common.zmq-socket/ctor
                  ::in-chan com.frereth.common.async-component/chan-ctor
                  ::status-chan com.frereth.common.async-component/chan-ctor}
          deps {::evt-iface {:ex-sock ::ex-sock
                             :in-chan ::in-chan
                             :status-chan ::status-chan}
                ::event-loop {:interface ::evt-iface
                              :ex-chan ::ex-chan}
                ::ex-sock {:ctx ::context}}
          description {:component-dsl.system/structure struc
                       :component-dsl.system/dependencies deps}]
      #:component-dsl.system{:system-configuration description
                             :configuration-tree options
                             :primary-component ::event-loop})))
