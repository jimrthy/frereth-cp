(ns frereth.cp.client.hello-test
  (:require [clojure.test :refer (deftest is testing)]
            [frereth.cp.client
             [hello :as hello]
             [state :as state]]
            [frereth.cp.shared :as shared]
            [frereth.cp.shared
             [specs :as specs]]
            [frereth.weald
             [logging :as log]
             [specs :as weald]]))

(deftest packet-building
  (let [log-state (log/init ::packet-building)
        ;; FIXME: Make these parameters reasonable.
        ;; This seems to be begging for a spec test.
        short-term-nonce 17
        safe-nonce (byte-array (range (+ specs/server-nonce-prefix-length
                                         specs/server-nonce-suffix-length)))
        {log-state ::weald/state
         :keys [::shared/packet]
         :as state} (hello/build-actual-packet {::weald/state log-state
                                                ::shared/extension nil
                                                ::shared/my-keys nil
                                                ::state/server-extension nil
                                                ::state/server-security nil
                                                ::state/shared-secrets nil}
                                               short-term-nonce
                                               safe-nonce)]
    (is log-state)
    (is packet)))
