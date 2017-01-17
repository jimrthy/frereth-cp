(ns com.frereth.common.curve.client-test
  (:require [clojure.test :refer (deftest is)]
            [com.frereth.common.curve.client :as clnt]
            [com.frereth.common.curve.shared :as shared]
            [manifold.stream :as strm]))

(defn raw-client
  []
  (let [server-extension (byte-array [0x01 0x02 0x03 0x04
                                      0x05 0x06 0x07 0x08
                                      0x09 0x0a 0x0b 0x0c
                                      0x0d 0x0e 0x0f 0x10])
        server-long-pk (byte-array [37 108 -55 -28 25 -45 24 93
                                    51 -105 -107 -125 -120 -41 83 -46
                                    -23 -72 109 -58 -100 87 115 95
                                    89 -74 -21 -33 20 21 110 95])
        server-name (shared/encode-server-name "hypothet.i.cal")]
    (clnt/ctor {;; Note that, as-written, this gets discarded immediately.
                ;; Q: Why? (i.e. Why did djb write it this way?)
                :extension (byte-array [0x10 0x0f 0x0e 0x0d
                                        0x0c 0x0b 0x0a 0x09
                                        0x08 0x07 0x06 0x05
                                        0x04 0x03 0x02 0x01])
                :server-chan (strm/stream)
                :server-extension server-extension
                ;; Q: Where do I get the server's public key?
                ;; A: Right now, I just have the secret key's 32 bytes encoded as
                ;; the alphabet.
                ;; TODO: Really need to mirror what the code does to load the
                ;; secret key from a file.
                ;; Then I can just generate a random key pair for the server.
                ;; Use the key-put functionality to store the secret, then
                ;; hard-code the public key here.
                :server-security {::clnt/server-long-term-pk server-long-pk
                                  ::shared/server-name server-name}})
    (throw (ex-info "This is also wrong" {:problem ":server-chan needs to be a Component"}))))

(deftest start-stop
  (let [init (raw-client)
        started (.start init)]
    (is (.stop started))))

(comment
  (def junk (raw-client))
  (-> junk :extension vec)
  (-> junk :server-extension vec)o
  junk
  (-> junk keys)
  (alter-var-root #'junk #(.start %))
  (alter-var-root #'junk #(.stop %)))
