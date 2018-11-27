# frereth-cp

[![Clojars Project](https://img.shields.io/clojars/v/frereth/cp.svg)](https://clojars.org/frereth/cp)

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
and I've been able to round-trip a single echo message without
encryption or network access, but there's still a lot to be done.

In retrospect, this probably wasn't a great
idea. A pure java implementation seems like it would have been
a much wiser choice.

But, hey, I've taken it this far. And this *does* give me a
higher-level perspective to really think about what's going
on, above and beyond the bit twiddling.

## Usage

Although you probably don't want to actually use it yet.

### Docker creation

    docker build -t frereth/curve-cp .

### Local Installation

    boot install

### Publish to clojars

#### From the master branch

    boot build-jar push-snapshot

or

    boot build-jar push-release

#### From a working branch

    boot publish-from-branch

## Notes

### Line numbers in comments

A lot of comments reference line numbers. Those really point
back to the reference implementation, from
https://github.com/krig/nacl

### tweetnacl

Having the tweetnacl java source just copy/pasted in the middle
breaks every linter I've tried to use. It seems like that part
really needs to be published somewhere as its own library.

Then again, maybe not. Maybe that violates the entire point
behind using tweetnacl.

## License

Copyright © 2017-2018 James Gatannah

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
