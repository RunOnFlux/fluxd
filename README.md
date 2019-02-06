=======
# ZelCash [![Build Status](https://travis-ci.com/zelcash/zelcash.svg?branch=master)](https://travis-ci.com/zelcash/zelcash)
=======
# ZelCash 2.0.0 BETA ZELNODES TESTNET
INNOVATIVE  INTELLIGENT  INSPIRING

## This branch is BETA and hardcoded to access TESTNET for the public testing of ZelNodes. Please use master for any other use case. 

This is beta testnet release. We have done a lot of testing, but there will be things that can break most likely. Use with caution, backup any wallet.dat files on your computer, don;t send real ZelCash to these addresses, etc. The blockchain will sync to a testnet folder within ZelCash folder.

We have testnet Zel available and will set up a channel to request testnet Zel (TEL) to stand up a testnet ZelNode.
There are no ZelNode rewards yet. That will come at activation on Feb. 21st.

Testnet ZelNodes is meant for us to test the entire ZelNodes environment, and for you to get comfortable setting up your node, learning the VPS and control wallet ins and outs, etc. If you are comfortable with the process already, you can wait to set up your node closer to activation to save the VPS costs.
We have a Github Wiki that will continually be built during the next couple weeks. Right now there is a guide for setting up your VPS/ZelNode and the daemon as your control wallet. In the next day or two you will be able to set up ZelCore as your control wallet.

Wiki: https://github.com/zelcash/zelcash/wiki \
Benchmarking: https://github.com/zelcash/zelcash/wiki/Benchmarking-Synopsis-Beta \
Setup guide using Daemon: https://github.com/zelcash/zelcash/wiki/ZelNode-Setup-Guide-%7C-Daemon 

Precompiled binaries \
Mac: \
https://zelcore.io/downloads/nodes/testnetv6/zelcashd-mac \
https://zelcore.io/downloads/nodes/testnetv6/zelcash-cli-mac \
Linux: \
https://zelcore.io/downloads/nodes/testnetv6/zelcashd \
https://zelcore.io/downloads/nodes/testnetv6/zelcash-cli \
Windows: \
https://zelcore.io/downloads/nodes/testnetv6/zelcashd.exe \
https://zelcore.io/downloads/nodes/testnetv6/zelcash-cli.exe

Either use the precompiled binaries above or compile from source ensuring that you are on the correct branch by: 
```
git clone https://github.com/zelcash/zelcash.git
cd zelcash
git checkout beta_nodes
```
Finally follow this README.md to compile for your OS and create your zelcash.conf

### Join discord to catch up with the community as you test and share your results: https://discord.io/zelcash

ZelCash is a fork of 2.0.2 Zcash aiming to provide decentralised development platform via ZelNodes and ZelCore.

POW asic resistant with Equihash (144,5) also known as Zhash with personalisation string ZelProof.

Fork to Acadia will be at the blockheight 250 000 which is estimated to occur on the 12th of January 2019. Please update to the latest release prior this date. Acadia release activates latest Zcash technology - Overwinter and Sapling upgrade. We are also modifying our difficulty algorithm to its next generation from LWMA to LWMA3. It is also neccesarry to download new Zcash network parameters via /zcutil/fetch-params.sh script.

To speed up synchronisation you can also download our blockchain (state 18. 12. 2018) at https://zelcore.io/Zelcash.zip 


# Build Guides
## Build for Linux
#### Install dependencies

On Ubuntu/Debian-based systems:

```
$ sudo apt-get update
$ sudo apt-get upgrade
$ sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python python-zmq \
      zlib1g-dev wget curl bsdmainutils automake 
```

On Fedora-based systems:

```
$ sudo dnf install \
      git pkgconfig automake autoconf ncurses-devel python \
      python-zmq wget gtest-devel gcc gcc-c++ libtool curl patch
```

#### Build
```
git clone https://github.com/zelcash/zelcash.git
cd zelcash
./zcutil/build.sh -j$(nproc)
```

#### Run ZelCash 
1. Create zelcash.conf file (copy and paste this block in one into your terminial)
```
mkdir ~/.zelcash
echo "rpcuser=username" >> ~/.zelcash/zelcash.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >> ~/.zelcash/zelcash.conf
echo "rpcallowip=127.0.0.1" >> ~/.zelcash/zelcash.conf
echo "listen=1" >> ~/.zelcash/zelcash.conf
echo "server=1" >> ~/.zelcash/zelcash.conf
echo "daemon=1" >> ~/.zelcash/zelcash.conf
echo "logtimestamps=1" >> ~/.zelcash/zelcash.conf
echo "testnet=1" >> ~/.zelcash/zelcash.conf
echo "txindex=1" >> ~/.zelcash/zelcash.conf
echo "addnode=testnet.zel.cash" >> ~/.zelcash/zelcash.conf
echo "addnode=testnetnodes.zel.cash" >> ~/.zelcash/zelcash.conf
echo "addnode=188.166.56.40" >> ~/.zelcash/zelcash.conf
echo "addnode=165.227.163.183" >> ~/.zelcash/zelcash.conf
echo "addnode=104.248.118.1" >> ~/.zelcash/zelcash.conf
echo "addnode=167.99.82.56" >> ~/.zelcash/zelcash.conf
echo "addnode=165.227.156.125" >> ~/.zelcash/zelcash.conf
echo "addnode=46.101.228.207" >> ~/.zelcash/zelcash.conf
echo "addnode=46.36.41.83" >> ~/.zelcash/zelcash.conf
echo "addnode=178.128.195.196" >> ~/.zelcash/zelcash.conf

```
2. Fetch keys
```
cd zelcash
./zcutil/fetch-params.sh
```

3. Run ZelCash node
```
./src/zelcashd
```


## Build for Windows
#### Install dependencies

Windows:

```
sudo apt-get install \
    build-essential pkg-config libc6-dev m4 g++-multilib \
    autoconf libtool ncurses-dev unzip git python \
    zlib1g-dev wget bsdmainutils automake mingw-w64
```

#### Build
```
git clone https://github.com/zelcash/zelcash.git
cd zelcash
./zcutil/build-win.sh -j$(nproc)
```
This will create zelcashd.exe zelcash-cli.exe and zelcash-tx.exe in src directory. 
#### Run ZelCash
1. Create ZelCash folder and configuration file

Create following zelcash.conf file in %AppData%/Roaming/ZelCash 
```
rpcuser=randomusername
rpcpassword=RandomPasswordChangeme
rpcallowip=127.0.0.1
listen=1
server=1
daemon=1
logtimestamps=1
testnet=1
txindex=1
addnode=testnet.zel.cash
addnode=testnetnodes.zel.cash
addnode=188.166.56.40
addnode=165.227.163.183
addnode=104.248.118.1
addnode=167.99.82.56
addnode=165.227.156.125
addnode=46.101.228.207
addnode=46.36.41.83
addnode=178.128.195.196
```

2. Download Zcash parameters to  %AppData%/Roaming/ZcashParams
https://zelcore.io/zelcore/sapling-output.params \
https://zelcore.io/zelcore/sapling-spend.params \
https://zelcore.io/zelcore/sprout-groth16.params \
https://zelcore.io/zelcore/sprout-proving.key \
https://zelcore.io/zelcore/sprout-verifying.key

3. Run ZelCash Node
```
zelcashd.exe
```

## Build for Mac
#### Install dependencies

macOS:

```{r, engine='bash'}
#install xcode
xcode-select --install

/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install cmake autoconf libtool automake coreutils pkgconfig gmp wget

brew install gcc5 --without-multilib
```
#### Build

```{r, engine='bash'}
# Pull
git clone https://github.com/zelcash/zelcash.git
cd zelcash
# Build
./zcutil/build.sh -j$(sysctl -n hw.ncpu)
```
#### Run ZelCash
1. Fetch keys
```{r, engine='bash'}
./zcutil/fetch-params.sh
```

2. Create configuration file
```{r, engine='bash'}
mkdir ~/Library/Application Support/zelcash/
echo "rpcuser=username" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "rpcallowip=127.0.0.1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "listen=1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "server=1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "daemon=1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "logtimestamps=1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "testnet=1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "txindex=1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=testnet.zel.cash" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=testnetnodes.zel.cash" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=188.166.56.40" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=165.227.163.183" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=104.248.118.1" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=167.99.82.56" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=165.227.156.125" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=46.101.228.207" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=46.36.41.83" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=178.128.195.196" >> ~/Library/Application Support/zelcash/zelcash.conf

```

3. Run ZelCash Node
```{r, engine='bash'}
./src/zelcashd
```

### Known errors
**autoreconf: failed to run libtoolize: No such file or directory**
```{r, engine='bash'}
sudo ln -s /usr/local/bin/glibtoolize /usr/local/bin/libtoolize
```
