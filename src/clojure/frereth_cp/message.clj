(ns frereth-cp.message
  "Translation of curvecpmessage.c

This is really a generic buffer program

The \"parent\" child/server reads/writes to pipes that this provides,
in a specific (and apparently undocumented) communications protocol.

This, in turn, reads/writes data from/to a child that it spawns.

At least, that's the impression I'm getting based on my
preliminary first few pages of the file I'm getting ready to
translate.

And then immediately after that, I think I hit the Chicago
congestion control algorithm")
