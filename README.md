# Zel 4.0.0 Kamata [![Build Status](https://travis-ci.com/zelcash/zelcash.svg?branch=master)](https://travis-ci.com/zelcash/zelcash)
<img align="right" height=112 width=562 src="doc/imgs/Kamiooka.png">

## Mandatory Upgrade to at least version 4.0.0

What is Zel?
--------------

[Zel](https://zel.network/) is a fork of 2.1.0-1 Zcash aiming to provide a decentralized development platform via ZelFlux, ZelNodes, ZelCore and more.

Zel is PoW and "ASIC resistant" with ZelHash (Modified Equihash 125,4) with the personalisation string ZelProof and utilises the LWMA3 difficulty algorithm.
The Kamata network upgrade which activates in December 2019 brings ZelFlux, ZelBenchd and Determenistic ZelNodes.

To speed up synchronisation you can download the Zel blockchain (state 18. 12. 2018) here https://zelcore.io/Zelcash.zip
For ZelNodes/Control Wallets you need to use this bootstrap with txindex enabled (state 18. 02. 2019) https://zelcore.io/zelcashbootstraptxindex.zip


<p align="center">
  <img src="doc/imgs/mandatory-kamiooka.png" height=500 >
</p>

## :rocket: Getting Started

Please see our [user guide](https://zel.gitbook.io/zeldocs/) for any and all info.

### Need Help?

* :blue_book: See the documentation at the [Zel GitBook](https://zel.gitbook.io/zelcurrency/installing-zel-daemon)
  for help and more information.
* :mag: Join us on [Discord.io/Zel](https://discord.io/zel) for support and to join the community conversation. 

### Building

Dependencies and build instructions for all supported platforms: [Zel GitBook](https://zel.gitbook.io/zelcurrency/installing-zel-daemon)

If you have the dependencies you can build Zel from source by running:

```
./zcutil/build.sh -j$(nproc)
```

#### :lock: Security Warnings

See important security warnings on the Zcash 
[Security Information page](https://z.cash/support/security/).

License
-------

For license information see the file [COPYING](COPYING).
