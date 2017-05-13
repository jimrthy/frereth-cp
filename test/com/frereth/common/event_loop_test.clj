(ns com.frereth.common.event-loop-test
  (:require [clojure.test :refer (deftest is testing)]
            [com.frereth.common.system :as sys]
            [com.stuartsierra.component :as component]
            [component-dsl.system :as cpt-dsl]))

(deftest start-stop
  []
  (testing "Can start and stop an Event Loop successfully"
    (let [wrapper-frame (cpt-dsl/build {:structure '{:ctx com.frereth.common.zmq-socket/ctx-ctor}
                                        :dependencies {}}
                                       {})
          wrapper (component/start wrapper-frame)
          context-wrapper (:ctx wrapper)]
      (try
        (let [initial (sys/build-event-loop-description {:context context-wrapper})
              started (component/start initial)]
          (is started "Managed to start an Event Loop")
          (try
            (component/stop started)
            (catch Exception ex
              (is false "Stopping the event loop failed"))))
        (finally
          (component/stop wrapper))))))
