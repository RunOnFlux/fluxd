<<<<<<< HEAD
Zcash 2.0.2
<img align="right" width="120" height="80" src="doc/imgs/logo.png">
===========
=======
<<<<<<< HEAD
Zcash 1.1.0
=============
>>>>>>> adfdef7... initial ZEL changes to Overwinter

What is Zcash?
--------------

[Zcash](https://z.cash/) is an implementation of the "Zerocash" protocol.
Based on Bitcoin's code, it intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. Technical details are available
in our [Protocol Specification](https://github.com/zcash/zips/raw/master/protocol/protocol.pdf).

This software is the Zcash client. It downloads and stores the entire history
of Zcash transactions; depending on the speed of your computer and network
connection, the synchronization process could take a day or more once the
blockchain has reached a significant size.

<p align="center">
  <img src="doc/imgs/zcashd_screen.gif" height="500">
</p>

#### :lock: Security Warnings

See important security warnings on the
[Security Information page](https://z.cash/support/security/).

**Zcash is experimental and a work-in-progress.** Use at your own risk.

####  :ledger: Deprecation Policy

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16 week time period. The automatic feature is based on block
height.

## Getting Started

Please see our [user guide](https://zcash.readthedocs.io/en/latest/rtd_pages/rtd_docs/user_guide.html) for joining the main Zcash network.

### Need Help?

* :blue_book: See the documentation at the [ReadtheDocs](https://zcash.readthedocs.io)
  for help and more information.
* :incoming_envelope: Ask for help on the [Zcash](https://forum.z.cash/) forum.
* :mag: Chat with our support community on [Rocket.Chat](https://chat.zcashcommunity.com/channel/user-support)

Participation in the Zcash project is subject to a
[Code of Conduct](code_of_conduct.md).

### Building

Build Zcash along with most dependencies from source by running:

```
./zcutil/build.sh -j$(nproc)
```

Currently only Linux is officially supported.

License
-------

For license information see the file [COPYING](COPYING).
=======
# Zelcash
INNOVATIVE  INTELLIGENT  INSPIRING

Zelcash is a fork of 1.0.14 Zcash aiming to provide decentralised development platform via ZelNodes and ZelTreZ.
POW asic resistant with Equihash (144,5) also known as Zhash with personalisation string ZelProof. 
To speed up synchronisation you can also download our blockchain (state Fri 6. 7. 2018) at https://drive.google.com/file/d/1Vn8HWau24wjTtUc9QZU2stliKevaEFx1/view?usp=sharing (pw: zelcash).

## Build (Ubuntu 16.04 Tested)
```
sudo apt-get update
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python python-zmq \
      zlib1g-dev wget bsdmainutils automake curl
```

```
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install g++-4.9
```

```
cd
mkdir .zelcash
echo "rpcuser=username" >> ~/.zelcash/zelcash.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >> ~/.zelcash/zelcash.conf
echo "addnode=node.zel.cash" >> ~/.zelcash/zelcash.conf
echo "addnode=explorer.zel.cash" >> ~/.zelcash/zelcash.conf
echo "addnode=explorer2.zel.cash" >> ~/.zelcash/zelcash.conf
echo "addnode=explorer.zelcash.online" >> ~/.zelcash/zelcash.conf
echo "addnode=node-eu.zelcash.com" >> ~/.zelcash/zelcash.conf
echo "addnode=node-uk.zelcash.com" >> ~/.zelcash/zelcash.conf
echo "addnode=node-asia.zelcash.com" >> ~/.zelcash/zelcash.conf
```

```{r, engine='bash'}
# pull
git clone https://github.com/zelcash/zelcash.git
cd zelcash
# fetch key
./zcutil/fetch-params.sh
# Build
./zcutil/build.sh -j$(nproc)
# Run a Zelcash node
./src/zelcashd
```
>>>>>>> 58446c9... sync init
