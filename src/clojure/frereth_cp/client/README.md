# Handshake

This gets pretty convoluted, with lots of manifold streams and deferreds.

It's really all driven by client.clj, in the root directory. But it seems to
make more sense to document it here, since this is where the pieces mostly
wound up.

(TODO: Flesh this out with something like a swim-lane diagram)

## client/start!

This sets up a couple of end-game pieces, then sets up server polling.

One of the pieces that I keep missing whenever I revisit this is the
servers-polled parameter to hello/set-up-server-polling!

## hello/set-up-server-polling!

Starts polling the server(s) with HELLO Packets

Calls hello/poll-servers! with cookie/wait-for-cookie! as the cookie-waiter
callback.

## hello/poll-servers!

Calls do-polling-loop, passing along the cookie-waiter callback.

## hello/do-polling-loop

This renames the cookie-waiter callback to cookie-sent-callback.

Then it creates a new binding, confusingly named cookie-waiter,
which is really just a partial built around that cookie-sent-callback.

One of the parameters baked into that partial is the cookie-response
deferred.

This calls state/do-send-packet with that new cookie-waiter callback.

## state/do-send-packet

That cookie-waiter parameter is its on-success parameter. So, once the
packet gets put onto the wire, it finally gets called.

## cookie/wait-for-cookie!

This takes a notifier parameter. Which is the cookie-response deferred
from do-polling-loop.

It tries to pull from the chan<-server stream.

The on-success callback for that is a partial built around
cookie/received-response and that notifier deferred.

## cookie/received-response!

We got something that looks like it might be a Cookie Packet from the
Server.

Run some basic checks, then try to decrypt it.

It's going to set its notifier deferred to a map that includes the
log-state we've been accumulating.

If we got back a valid Cookie Packet (which mostly means we were
able to open its crypto box), that delivery will also include
the network packet and the shared secrets.

This takes us back to hello/do-polling-loop.

## hello/do-polling-loop

If we got back a valid network packet, it moves the FSM forward by
delivering the completion deferred.

That was its first parameter, set up in hello/poll-servers! It
triggers a partial to send-succeeded!

If not, it works through some possibly-retry logic.

## hello/send-succeeded!

This doesn't do anything except flush the logs.

hello/do-polling-loop includes a comment that this
*should* trigger servers-polled.

That rolls back up into client/set-up-server-hello-polling!

## hello/set-up-server-polling!

Way back when we first called hello/poll-servers! it returned
a deferrable that this calls `outcome` (plus the inevitable log
state).

We finally stick that into a deferred/chain.

It starts by calling
