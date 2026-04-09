TOR SUPPORT IN FLUX
====================

fluxd supports TORv3 hidden services end-to-end:

  - It can host its own v3 onion service via Tor's control port.
  - It exchanges v3 onion addresses with peers using BIP155 (`addrv2`).
  - It persists v3 onion peers to `peers.dat` across restarts.

TORv2 was removed from the live Tor network in October 2021 and is no longer
supported by fluxd. You need a recent Tor (>= 0.3.5 for the control protocol;
0.4.7 or newer is recommended). The instructions below assume you have a Tor
proxy running on port 9050. Many distributions default to listening on 9050;
the Tor Browser Bundle defaults to 9150. See [Tor Project FAQ:TBBSocksPort](
https://www.torproject.org/docs/faq.html.en#TBBSocksPort) for how to configure
Tor.


1. Run fluxd behind a Tor proxy
-------------------------------

Running fluxd behind a Tor proxy anonymizes all of fluxd's outgoing
connections. Combined with `-listen` and `-listenonion` (see section 3) it
also makes fluxd reachable as a v3 hidden service.

    -proxy=ip:port  Set the proxy server. If SOCKS5 is selected (default), this
                    proxy server will be used to try to reach .onion addresses
                    as well.

    -onion=ip:port  Set the proxy server to use for Tor hidden services. You do
                    not need to set this if it's the same as -proxy. You can
                    use -noonion to explicitly disable access to hidden
                    services.

    -listen         When using -proxy, listening is disabled by default. If you
                    want to run a hidden service (see section 2 or 3), you'll
                    need to enable it explicitly.

    -connect=X      When behind a Tor proxy, you can specify .onion addresses
    -addnode=X      instead of IP addresses or hostnames in these parameters.
    -seednode=X     It requires SOCKS5. In Tor mode, such addresses can also be
                    exchanged with other P2P nodes via BIP155 addrv2 messages.

In a typical situation, this suffices to run behind a Tor proxy:

    ./fluxd -proxy=127.0.0.1:9050


2. Manually configure a Flux hidden service
-------------------------------------------

If you prefer to manage the hidden service yourself (rather than letting
fluxd negotiate one via the control port — see section 3), add these lines to
your `/etc/tor/torrc` (or equivalent config file):

    HiddenServiceDir /var/lib/tor/flux-service/
    HiddenServiceVersion 3
    HiddenServicePort 16125 127.0.0.1:16125
    HiddenServicePort 26125 127.0.0.1:26125

`HiddenServiceVersion 3` is the default in modern Tor and produces a 56-char
v3 .onion address. The directory can be different of course, but the port
numbers should match your fluxd P2P listen port (16125 by default).

    -externalip=X   Tell Flux about its publicly reachable address. With the
                    above configuration, you can find your onion address in
                    /var/lib/tor/flux-service/hostname (it will be a 56-character
                    string ending in .onion). Onion addresses are given
                    preference for the node to advertise itself with for
                    connections coming from unroutable addresses (such as
                    127.0.0.1, where the Tor proxy typically runs).

    -listen         You'll need to enable listening for incoming connections,
                    as this is off by default behind a proxy.

    -discover       When -externalip is specified, no attempt is made to
                    discover local IPv4 or IPv6 addresses. If you want to run a
                    dual stack reachable from both Tor and IPv4 (or IPv6),
                    you'll need to either pass your other addresses using
                    -externalip, or explicitly enable -discover. Note that both
                    addresses of a dual-stack system may be linkable through
                    traffic analysis.

In a typical Tor-only situation:

    ./fluxd -proxy=127.0.0.1:9050 \
            -externalip=kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion \
            -listen

(replace the address with your own from `/var/lib/tor/flux-service/hostname`).
You may also want to bind only to localhost so a clearnet attacker can't
connect directly:

    ./fluxd ... -bind=127.0.0.1


3. Automatically host a v3 hidden service via the Tor control port
------------------------------------------------------------------

This is the easiest setup. fluxd will talk to Tor's control socket, ask it to
create an ephemeral v3 hidden service, and persist the ed25519 private key to
`onion_v3_private_key` in the data directory so the same address comes back
on every restart.

The feature is enabled by default if fluxd is listening (`-listen`) and a Tor
control port is reachable. It can be disabled with `-listenonion=0` and
configured with the `-torcontrol` and `-torpassword` settings. To see verbose
debugging information, pass `-debug=tor`.

Connecting to Tor's control socket requires one of two authentication methods.
For SAFECOOKIE authentication, the user running fluxd must have read access
to the `CookieAuthFile` specified in Tor's configuration. On Debian-based
systems, the user running fluxd can be added to the `debian-tor` group, which
has the right permissions. The alternative is `-torpassword=<value>` paired
with a `HashedControlPassword` line in `torrc`.

When fluxd successfully creates the service you'll see a log line like:

    tor: Got service ID kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid,
         advertising service kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion:16125

and a file named `onion_v3_private_key` (starting with `ED25519-V3:`) will
appear in your data directory. Back this up if you want the same address to
survive a data-directory wipe.

**Note on TORv2 keys.** A pre-upgrade fluxd may have a file named
`onion_private_key` (without the `_v3_` infix) holding an RSA1024 v2 key.
This file is intentionally NOT migrated — TORv2 was removed from the Tor
network in 2021 and the key material cannot be reused for a v3 service. The
file can be safely deleted.


4. BIP155 (addrv2) and v3 onion peer gossip
-------------------------------------------

fluxd advertises BIP155 support during the version handshake (it sends
`sendaddrv2` before `verack` to peers running protocol version 170021 or
higher). Two upgraded peers will exchange v3 onion addresses via the
`addrv2` message; either side talking to a legacy peer falls back to the
plain `addr` message and silently filters out any v3 onion entries before
sending (legacy `addr` cannot represent them).

You can verify the negotiation worked using `getpeerinfo`:

    flux-cli getpeerinfo

    [
        {
            "id": 1,
            "addr": "kpgvmscir...nqaid.onion:16125",
            "network": "onion",
            "addrv2": true,
            ...
            "version": 170021,
            ...
        }
    ]

The `network` field shows the per-peer classification (`ipv4`, `ipv6`,
`onion`, or `unroutable`) and the `addrv2` field shows whether the peer
negotiated BIP155 with us before VERACK.

`getnetworkinfo` continues to report onion reachability under the `networks`
array:

    flux-cli getnetworkinfo

    {
        ...
        "networks": [
            { "name": "ipv4",  "limited": false, "reachable": true,  ... },
            { "name": "ipv6",  "limited": false, "reachable": true,  ... },
            { "name": "onion", "limited": false, "reachable": true,  ... }
        ],
        ...
    }


5. Connect to a Flux hidden server
-----------------------------------

To test your setup, connect via Tor on a different machine to a single
hidden server:

    ./fluxd -onion=127.0.0.1:9050 \
            -connect=kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion

Verify there is only a single peer connection:

    flux-cli getpeerinfo

To connect to multiple Tor nodes only:

    ./fluxd -onion=127.0.0.1:9050 \
            -addnode=kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion \
            -dnsseed=0 -onlynet=onion


6. Persistence
--------------

v3 onion peers learned via the network are persisted to `peers.dat` using
the addrman on-disk format version 2 (BIP155-aware). On a clean restart,
fluxd will reload the same v3 peers and reconnect to them.

A pre-upgrade fluxd reading a post-upgrade `peers.dat` will see an unknown
format version and start with an empty address book — the file is not
"corrupted", just newer than the binary can read. Run the new fluxd to use
it. addrman is a peer cache, not consensus state, so an empty start just
means relearning peers from the network and dnsseed entries.
