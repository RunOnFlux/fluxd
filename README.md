=======
# ZelCash [![Build Status](https://travis-ci.com/zelcash/zelcash.svg?branch=master)](https://travis-ci.com/zelcash/zelcash)
=======
# ZelCash 3.1.1 ZelNodes
INNOVATIVE  INTELLIGENT  INSPIRING

ZelCash is a fork of 2.0.3 Zcash aiming to provide decentralised development platform via ZelNodes and ZelCore.

POW asic resistant with Equihash (144,5) also known as Zhash with personalisation string ZelProof and LWMA3 difficulty algorithm.

To speed up synchronisation you can also download our blockchain (state 18. 12. 2018) at https://zelcore.io/Zelcash.zip 
For ZelNodes/Control Wallets use this bootstrap with txindex enabled (state 18. 02. 2019) https://zelcore.io/zelcashbootstraptxindex.zip

# Install and run from APT

On Ubuntu/Debian-based systems:

```
echo 'deb https://zelcash.github.io/aptrepo/ all main' | sudo tee --append /etc/apt/sources.list.d/zelcash.list
gpg --keyserver keyserver.ubuntu.com --recv 4B69CA27A986265D
gpg --export 4B69CA27A986265D | sudo apt-key add -

sudo apt-get update
sudo apt-get install zelcash
```
This installs zelcashd, zelcash-cli, zelcash-tx and zelcash-fetch-params

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
1. Create zelcash.conf file (copy and paste this block in one into your terminal)
```
mkdir ~/.zelcash
echo "rpcuser=username" >> ~/.zelcash/zelcash.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >> ~/.zelcash/zelcash.conf
echo "rpcallowip=127.0.0.1" >> ~/.zelcash/zelcash.conf
echo "addnode=explorer.zel.cash" >> ~/.zelcash/zelcash.conf
echo "addnode=explorer.zel.zelcore.io" >> ~/.zelcash/zelcash.conf

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
    autoconf libtool ncurses-dev cmake unzip git python \
    zlib1g-dev wget bsdmainutils automake mingw-w64 curl
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
addnode=explorer.zel.cash
addnode=explorer.zel.zelcore.io
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
echo "addnode=explorer.zel.cash" >> ~/Library/Application Support/zelcash/zelcash.conf
echo "addnode=explorer.zel.zelcore.io" >> ~/Library/Application Support/zelcash/zelcash.conf

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
