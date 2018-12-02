# Initiate Packet Handling

This should probably be documented elsewhere.

Initiate packets are built on the idea that the nonces being sent from
the Client increase monotically.

TODO: Identify exactly which nonce is under discussion here

If we receive an Initiate packet with a "packet-nonce" that is <=
the highest packet-nonce we've received so far (for any given client),
we just discard it.

There really should be subtleties here. If we receive packets for
nonces 10 and 12, we obviously shouldn't just discard 11 (right?).

It's probably fine. If the packets do arrive out of order that way, the
messaging algorithm will get around to resending the portion of this
packet that we're dropping here.

Q: Won't it?

This is something I haven't explored/considered to any extent at all. I
just noticed it and wanted to write it down while it was stuck in my
head as a "that don't seem right" kind of thing.
