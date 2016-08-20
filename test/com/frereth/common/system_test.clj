(ns com.frereth.common.system-test
  (:require [clojure.test :refer (are deftest is testing)]
            [com.frereth.common.system :as sys]
            [com.stuartsierra.component :as component]))

(deftest start-stop
  (testing "Can start/stop basic event loop"
    (throw (ex-info "Duplicate"
                    {:better-version 'com.frereth.common.event-loop-test}))
    (let [initial (sys/build-event-loop nil)
          started (component/start initial)]
      (is started "start should either return truthy or throw")
      (component/stop started))))
