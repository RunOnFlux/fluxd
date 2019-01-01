=======
# ZelCash [![Build Status](https://travis-ci.com/zelcash/zelcash.svg?branch=master)](https://travis-ci.com/zelcash/zelcash)
=======
# ZelCash 2.0.0
INNOVATIVE  INTELLIGENT  INSPIRING

ZelCash is a fork of 2.0.2 Zcash aiming to provide decentralised development platform via ZelNodes and ZelCore.

POW asic resistant with Equihash (144,5) also known as Zhash with personalisation string ZelProof.

Fork to Acadia will be at the blockheight 250 000 which is estimated to occur on the 12th of January 2019. Please update to the latest release prior this date. Acadia release activates latest Zcash technology - Overwinter and Sapling upgrade. We are also modifying our difficulty algorithm to its next generation from LWMA to LWMA3. It is also neccesarry to download new Zcash network parameters via /zcutil/fetch-params.sh script.

To speed up synchronisation you can also download our blockchain (state 18. 12. 2018) at https://zelcore.io/Zelcash.zip 


# Build Guides
## Build for Linux
#### Install dependencies

On Ubuntu/Debian-based systems:

```
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
1. Create zelcash.conf file
```
mkdir ~/.zelcash
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
rpcuser=username
rpcpassword=RandomPasswordChangeME
addnode=node.zel.cash
addnode=explorer.zel.cash
addnode=explorer2.zel.cash
addnode=explorer.zelcash.online
addnode=node-eu.zelcash.com
addnode=node-uk.zelcash.com
addnode=node-asia.zelcash.com
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
mkdir  ~/Library/Application Support/zelcash/
echo "rpcuser=username" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=node.zel.cash" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=explorer.zel.cash" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=explorer2.zel.cash" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=explorer.zelcash.online" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=node-eu.zelcash.com" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=node-uk.zelcash.com" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=node-asia.zelcash.com" >> ~/Library/Application Support/zelcash/zelcash.conf
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
