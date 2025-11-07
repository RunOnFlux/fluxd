# Flux 9.0.5

## What is Flux?

[Flux](https://runonflux.io/) is a decentralized cloud infrastructure powered by an incentivized network of independently operated FluxNodes. Fluxd is the blockchain daemon that provides the consensus layer and coin functionality for the Flux ecosystem, including the [Flux decentralized cloud](https://cloud.runonflux.com/) and Arcane OS.

### Key Features

- **PoUW v2 (Proof of Useful Work)**: Also known as PON (Proof of Nodes), activated at block 2,020,000 - see the [whitepaper](https://jetpack2_38080.app.runonflux.io/ipfs/QmW3TNPx5Ru3u3UhXf8GqyVNS3avSsttqjamhF395qe17M)
- **FluxNode Network**: Incentivized node operators power the decentralized cloud infrastructure at [cloud.runonflux.com](https://cloud.runonflux.com/)
- **Arcane OS**: Distributed operating system built on Flux infrastructure
- **LWMA3 Difficulty Algorithm**: Provides smooth difficulty adjustments
- **Delegate System**: Supports P2SH-based FluxNode delegation

### Components

- **fluxd**: Full node daemon
- **flux-cli**: Command-line interface for RPC interaction
- **flux-tx**: Transaction utility for creating and manipulating transactions

## Getting Started

### Prerequisites

Supported platforms:
- Ubuntu 20.04, 22.04, and 24.04
- Other Linux distributions (see build dependencies)
- macOS
- Windows (via cross-compilation)

### Building from Source

#### Install Dependencies (Ubuntu)

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib \
    autoconf2.64 libtool ncurses-dev unzip git zlib1g-dev wget curl \
    bsdmainutils automake
```

#### Build Fluxd

```bash
./zcutil/build.sh -j$(nproc)
```

The built binaries will be located in `./src/`:
- `./src/fluxd` - daemon
- `./src/flux-cli` - CLI tool
- `./src/flux-tx` - transaction utility

### Configuration Options

Fluxd supports various build-time options:
- `--disable-wallet` - Build without wallet support
- `--disable-mining` - Build without mining support
- `--disable-zmq` - Build without ZeroMQ notifications
- `--disable-proton` - Build without AMQP messaging
- `--enable-debug` - Build with debug symbols

## Running a FluxNode

FluxNodes are incentivized network participants that provide computational resources to the Flux decentralized cloud at [cloud.runonflux.com](https://cloud.runonflux.com/).

For setup instructions, visit the [Flux documentation](https://docs.runonflux.com/).

## Documentation

- **Documentation**: [docs.runonflux.com](https://docs.runonflux.com/)
- **Website**: [runonflux.io](https://runonflux.io/)
- **Decentralized Cloud**: [cloud.runonflux.com](https://cloud.runonflux.com/)
- **Block Explorer**: [explorer.runonflux.io](https://explorer.runonflux.io/)
- **PoUW v2 Whitepaper**: [View whitepaper](https://jetpack2_38080.app.runonflux.io/ipfs/QmW3TNPx5Ru3u3UhXf8GqyVNS3avSsttqjamhF395qe17M)

## Community & Support

- **Discord**: [discord.gg/runonflux](https://discord.gg/runonflux)
- **GitHub Issues**: [github.com/RunOnFlux/fluxd/issues](https://github.com/RunOnFlux/fluxd/issues)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## Security

For security vulnerabilities, please email security@runonflux.com following our [bug bounty program](https://runonflux.com/bug-bounty/).

## License

Flux is released under the terms of the MIT license. See [COPYING](COPYING) for more information.

Copyright (c) 2018-2025 The Flux Developers
Copyright (c) 2016-2019 The Zcash developers
Copyright (c) 2009-2019 The Bitcoin Core developers
