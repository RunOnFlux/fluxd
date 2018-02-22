# Zelcash
INNOVATIVE  INTELLIGENT  INSPIRING


Build (Ubuntu 16.04 Tested)
```
sudo apt-get update
```
```
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
git clone https://github.com/Scribbles-MCAMK/Zelcash.git
git clone https://gitlab.com/zcashcommunity/params.git
```
```
cd zelcash
chmod +x zcutil/build.sh depends/config.guess depends/config.sub autogen.sh share/genbuild.sh src/leveldb/build_detect_platform
```
```
./zcutil/build.sh --disable-rust -j$(nproc)
```
```
cd
mkdir .zelcash
mkdir .zelcash-params
```
```
cd .zelcash-params
cp /root/params/sprout-proving.key .
cp /root/params/sprout-verifying.key .
```
```
cd
```
```
cd .zelcash
echo "addnode=node.zel.cash" >~/.zelcash/zelcash.conf
echo "rpcuser=username" >>~/.zelcash/zelcash.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >>~/.zelcash/zelcash.conf
```
```
cd
./zelcash/src/zelcashd
```
