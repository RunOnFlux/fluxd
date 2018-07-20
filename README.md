# Zelcash 1.1.0
INNOVATIVE  INTELLIGENT  INSPIRING

Zelcash is a fork of 1.0.14 Zcash aiming to provide decentralised development platform via ZelNodes and ZelTreZ.

POW asic resistant with Equihash (144,5) also known as Zhash with personalisation string ZelProof. 

To speed up synchronisation you can also download our blockchain (state Fri 6. 7. 2018) at https://drive.google.com/file/d/1Vn8HWau24wjTtUc9QZU2stliKevaEFx1/view?usp=sharing (pw: zelcash).

## Install and run from APT
```
echo 'deb https://zelcash.github.io/aptrepo/ all main' | sudo tee --append /etc/apt/sources.list.d/zelcash.list
gpg --keyserver keyserver.ubuntu.com --recv 69FAF6DE41B8AC51
gpg --export 69FAF6DE41B8AC51| sudo apt-key add -

sudo apt-get update
sudo apt-get install zelcash
```
This installs zelcashd, zelcash-cli, zelcash-tx and fetch-params

#### Run Zelcash 
1. Create zelcash.conf file
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

2. Fetch keys
```
fetch-params
```

3. Run a Zelcash node
```
zelcashd
```

## Build (Ubuntu 16.04 Tested)
1. Get dependencies
```
sudo apt-get update
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake curl
```

2. Build
```
# pull
git clone https://github.com/zelcash/zelcash.git
cd zelcash
# Build
./zcutil/build.sh -j$(nproc)
```

#### Run Zelcash 
1. Create zelcash.conf file
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

2. Fetch keys
```
cd zelcash
./zcutil/fetch-params.sh
```

3. Run a Zelcash node
```
./src/zelcashd
```


## Build for Windows 64Bit (Ubuntu 16.04 Tested)
1. Get dependencies
```
sudo apt-get update
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python curl \
      zlib1g-dev wget bsdmainutils automake cmake mingw-w64
```

2. Configure to use POSIX variant
```
sudo update-alternatives --config x86_64-w64-mingw32-gcc
sudo update-alternatives --config x86_64-w64-mingw32-g++
```

3. Install rust by running following script
```
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
rustup install stable-x86_64-unknown-linux-gnu
rustup install stable-x86_64-pc-windows-gnu
rustup target add x86_64-pc-windows-gnu
echo "[target.x86_64-pc-windows-gnu]" >> ~/.cargo/config
echo "linker = \"/usr/bin/x86_64-w64-mingw32-gcc\"" >> ~/.cargo/config
source ~/.cargo/env
```

4. Compile for windows
```
# pull
git clone https://github.com/zelcash/zelcash.git
cd zelcash
# Build
./zcutil/build-win.sh -j$(nproc)
```
This will create zelcashd.exe zelcash-cli.exe and zelcash-tx.exe in src directory.