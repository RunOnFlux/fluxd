// Copyright (c) 2012-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 170021;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 31800;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = 170002;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION_TESTNET = 170016;

//! nTime field added to CAddress, starting with this version;
//! if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "mempool" command, enhanced "getdata" behavior starts with this version
static const int MEMPOOL_GD_VERSION = 60002;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 170004;

//! protocol version that requires fluxnode payments
static const int MIN_PEER_PROTO_VERSION_FLUXNODE = 170009;

//! protocol version that means they support deterministic fluxnodes, not used as of now, usage of UPGRADE_KAMATA
static const int DETERMINISTIC_FLUXNODES = 170016;

static const int P2SH_NODES = 170019;

static const int PROOF_OF_NODE = 170020;

//! "sendheaders" command and announcing blocks with headers starts with this version
static const int SENDHEADERS_VERSION = 170021;

//! "sendcmpct" command for BIP 152 compact block relay (same version as sendheaders)
static const int SENDCMPCT_VERSION = 170021;

//! "cmpheaders" message for efficient header sync of checkpointed blocks
static const int CMPHEADERS_VERSION = 170021;

#endif // BITCOIN_VERSION_H
