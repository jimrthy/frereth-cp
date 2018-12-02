(ns frereth-cp.message.headers
  (:require [frereth-cp.message.specs :as specs]
            [frereth-cp.shared.constants :as K]))

(def message-header-dscr
  "This is the first, metadata portion of the message

  It's mainly a set of ACK'd address ranges, with some fields
  for addresses, IDs, sizes, and flags that signal the
  end of the stream."
  (array-map ::specs/message-id {::K/type ::K/uint-32}
             ::specs/acked-message {::K/type ::K/uint-32}
             ::specs/ack-length-1 {::K/type ::K/uint-64}
             ::specs/ack-gap-1->2 {::K/type ::K/uint-32}
             ::specs/ack-length-2 {::K/type ::K/uint-16}
             ::specs/ack-gap-2->3 {::K/type ::K/uint-16}
             ::specs/ack-length-3 {::K/type ::K/uint-16}
             ::specs/ack-gap-3->4 {::K/type ::K/uint-16}
             ::specs/ack-length-4 {::K/type ::K/uint-16}
             ::specs/ack-gap-4->5 {::K/type ::K/uint-16}
             ::specs/ack-length-5 {::K/type ::K/uint-16}
             ::specs/ack-gap-5->6 {::K/type ::K/uint-16}
             ::specs/ack-length-6 {::K/type ::K/uint-16}
             ::specs/size-and-flags {::K/type ::K/uint-16}
             ::specs/start-byte {::K/type ::K/uint-64}))

(def message-payload-dscr
  "This is the 'important' part of the message packet

  Decomposing this is probably more trouble than just
  skipping the zero padding (et al) and reading the
  data bytes directly. But it seemed worth documenting."
  (array-map ::zero-padding {::K/type ::K/zeroes ::K/length '?zero-padding-length}
             ::specs/buf {::K/type ::K/bytes ::K/length '?data-block-length}))
