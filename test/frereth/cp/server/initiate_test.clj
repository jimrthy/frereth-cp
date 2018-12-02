(ns frereth.cp.server.initiate-test
  "Test out pieces involved in Server Cookie handling"
  (:require [clojure.test :refer (deftest is testing)]
            [frereth.cp.server
             [initiate :as initiate]
             [state :as state]]
            [frereth.cp.shared
             [crypto :as crypto]
             [specs :as specs]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]))

(deftest fork-nameless-loop
  (let [log-state (log/init ::fork-without-loop-name)
        {log-state ::weald/state
         :keys [::state/client-state]
         :as result} (initiate/do-fork-child! {::weald/state log-state} nil)]
    (println "do-fork-child! returned: " result)
    (is log-state)
    (is (not client-state))))
