# frereth-cp

CurveCP is a low-level protocol for streaming bytes across
the network, much like TCP. Except in a secure manner.

This is an attempt to translate the reference implementation
into clojure.

## Background

It was initially designed by Daniel J. Bernstein. The spec,
justification, and explanation can be found at
[CurveCP](http://curvecp.org/index.html "Usable
security for the Internet").

## Status

Not even pre-alpha. I have most of the handshake translated,
but I'm just starting to get to the really interesting parts.

In retrospect, this probably wasn't a great
idea. A pure java implementation would seem like a much
wiser choice.

But, hey, I've taken it this far.

## Usage

lein install

Although you probably don't want to actually use it.

## Notes

## License

Copyright © 2017 James Gatannah

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
