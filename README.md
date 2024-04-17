# Flux 7.1.0
[![Build Status](https://app.travis-ci.com/RunOnFlux/fluxd.svg?branch=master)](https://app.travis-ci.com/github/RunOnFlux/fluxd)

What is Flux?
--------------

[Flux](https://runonflux.io/) (formerly known as Zel) is a fork of 2.1.0-1 Zcash aiming to provide a decentralized development platform via FluxOS, FluxNodes, ZelCore and more.

Flux is PoW and "ASIC resistant" with ZelHash (Modified Equihash 125,4) with the personalisation string ZelProof and utilises the LWMA3 difficulty algorithm.

## :rocket: Getting Started

Please see our [wiki](https://wiki.runonflux.io/) for any and all info.

To setup a FluxNode please follow this [guide](https://medium.com/@mmalik4/flux-light-node-setup-as-easy-as-it-gets-833f17c73dbb) and this [video guide](https://www.youtube.com/watch?v=KYWUXrKP9do).

### Building

If you are building for Ubuntu 20.04 or Ubuntu 22.04 use the following to install the dependencies:

```
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf2.64 libtool ncurses-dev unzip git zlib1g-dev wget curl bsdmainutils automake
```

For other targets or additional information see the Flux Daemon build and installation guide is [here](https://zel.gitbook.io/zelcurrency/installing-zel-daemon).


Once you have the dependencies you can build Flux Daemon from source by running:

```
./zcutil/build.sh -j$(nproc)
```

### Need Help?

* :blue_book: See the documentation at the [Zel GitBook](https://zel.gitbook.io/zelcurrency/installing-zel-daemon)
  for help and more information.
* :mag: Join us on [Discord.gg/RunOnFlux](https://discord.gg/runonflux) for support and to join the community conversation. 

#### :lock: Security Warnings

See important security warnings on Zcash 
[Security Information page](https://z.cash/support/security/).

License
-------

For license information see the file [COPYING](COPYING).
