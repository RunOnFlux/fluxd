// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "compat.h"
#include "serialize.h"

#include <stdint.h>
#include <string>
#include <vector>

extern int nConnectTimeout;
extern bool fNameLookup;

/** -timeout default */
static const int DEFAULT_CONNECT_TIMEOUT = 5000;

#ifdef WIN32
// In MSVC, this is defined as a macro, undefine it to prevent a compile and link error
#undef SetPort
#endif

enum Network
{
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_ONION,                   // v3 onion services (ed25519 / 32-byte pubkey)

    NET_MAX,
};

/** BIP155 network identifiers (used in the addrv2 wire format).
 *  Reference: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
 *  We only emit IPV4/IPV6/TORV3. TORV2/I2P/CJDNS are reserved as enum values
 *  so we can recognize and skip them on the wire. */
enum BIP155Network : uint8_t
{
    BIP155_NONE  = 0,
    BIP155_IPV4  = 1,
    BIP155_IPV6  = 2,
    BIP155_TORV2 = 3,    // deprecated; we never emit and silently drop on receive
    BIP155_TORV3 = 4,
    BIP155_I2P   = 5,    // not implemented; recognized to skip
    BIP155_CJDNS = 6,    // not implemented; recognized to skip
};

/** Size of a TORv3 ed25519 public key. See BIP155 + rend-spec-v3. */
static const size_t ADDR_TORV3_SIZE = 32;
/** BIP155 maximum encoded address length (defensive cap on the wire). */
static const size_t ADDRV2_MAX_ADDRESS_SIZE = 512;

/** RFC 4291 IPv4-mapped-IPv6 prefix.
 *  Promoted from a file-static in netbase.cpp so that header-defined templated
 *  serializers (e.g. CNetAddr::UnserializeV2) can reference the same named
 *  constant instead of inlining magic bytes. */
static const unsigned char pchIPv4[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };

/** IP address (IPv6, IPv4 mapped, TORv3 onion). */
class CNetAddr
{
    protected:
        /** Authoritative network type tag. Every accessor dispatches on this. */
        Network m_net;

        /** Raw address bytes. Length is determined by m_net:
         *    NET_IPV4       -> 4   bytes
         *    NET_IPV6       -> 16  bytes
         *    NET_ONION        -> 32  bytes (ed25519 ed25519 pubkey, BIP155 TORV3)
         *    NET_UNROUTABLE -> 0..16 bytes (treated as IPv6 for legacy validation) */
        std::vector<unsigned char> m_addr;

        /** Reconstruct the legacy 16-byte "IPv4-mapped-IPv6" representation
         *  that pre-Phase-2 code stored in `unsigned char ip[16]`. Used by
         *  GetByte / GetHash / GetGroup / V1 wire serialization / CSubNet so
         *  the byte-level outputs (and hence addrman bucketing) stay
         *  identical for IPv4/IPv6 across the refactor. NET_ONION and any
         *  unrecognized state produces all zeros. */
        void SerializeV1Array(uint8_t out[16]) const;

    public:
        CNetAddr();
        CNetAddr(const struct in_addr& ipv4Addr);
        explicit CNetAddr(const char *pszIp, bool fAllowLookup = false);
        explicit CNetAddr(const std::string &strIp, bool fAllowLookup = false);
        void Init();
        void SetIP(const CNetAddr& ip);

        /**
         * Set raw IPv4 or IPv6 address (in network byte order)
         * @note Only NET_IPV4 and NET_IPV6 are allowed for network.
         */
        void SetRaw(Network network, const uint8_t *data);

        /**
         * Parse a TORv3 ".onion" address (56-char base32 + ".onion" suffix),
         * validate its SHA3-256 checksum, and on success set m_net=NET_ONION
         * with m_addr holding the 32-byte ed25519 pubkey.
         */
        bool SetTor(const std::string &strName);

        bool SetSpecial(const std::string &strName); // dispatches to SetTor for .onion
        bool IsIPv4() const;    // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
        bool IsIPv6() const;    // IPv6 address (not mapped IPv4, not Tor)
        bool IsRFC1918() const; // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
        bool IsRFC2544() const; // IPv4 inter-network communications (192.18.0.0/15)
        bool IsRFC6598() const; // IPv4 ISP-level NAT (100.64.0.0/10)
        bool IsRFC5737() const; // IPv4 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        bool IsRFC3849() const; // IPv6 documentation address (2001:0DB8::/32)
        bool IsRFC3927() const; // IPv4 autoconfig (169.254.0.0/16)
        bool IsRFC3964() const; // IPv6 6to4 tunnelling (2002::/16)
        bool IsRFC4193() const; // IPv6 unique local (FC00::/7)
        bool IsRFC4380() const; // IPv6 Teredo tunnelling (2001::/32)
        bool IsRFC4843() const; // IPv6 ORCHID (2001:10::/28)
        bool IsRFC4862() const; // IPv6 autoconfig (FE80::/64)
        bool IsRFC6052() const; // IPv6 well-known prefix (64:FF9B::/96)
        bool IsRFC6145() const; // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
        bool IsTor() const;
        bool IsLocal() const;
        bool IsRoutable() const;
        bool IsValid() const;
        bool IsMulticast() const;
        enum Network GetNetwork() const;
        std::string ToString() const;
        std::string ToStringIP() const;
        unsigned int GetByte(int n) const;
        uint64_t GetHash() const;
        bool GetInAddr(struct in_addr* pipv4Addr) const;
        std::vector<unsigned char> GetGroup() const;
        int GetReachabilityFrom(const CNetAddr *paddrPartner = NULL) const;

        CNetAddr(const struct in6_addr& pipv6Addr);
        bool GetIn6Addr(struct in6_addr* pipv6Addr) const;

        friend bool operator==(const CNetAddr& a, const CNetAddr& b);
        friend bool operator!=(const CNetAddr& a, const CNetAddr& b);
        friend bool operator<(const CNetAddr& a, const CNetAddr& b);

        ADD_SERIALIZE_METHODS;

        // V1 wire format: always 16 bytes in IPv4-mapped-IPv6 layout. NET_ONION
        // and any other non-IP state writes 16 zero bytes (which the receiver
        // rejects via IsValid()), so legacy peers see no change in behavior.
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            uint8_t serialized[16];
            if (ser_action.ForRead()) {
                READWRITE(FLATDATA(serialized));
                SetLegacyIPv6(serialized);
            } else {
                SerializeV1Array(serialized);
                READWRITE(FLATDATA(serialized));
            }
        }

        /** Decode a 16-byte IPv4-mapped-IPv6 representation (the legacy V1
         *  wire format and on-disk format) and store the result. Sets m_net
         *  to NET_IPV4 if the bytes start with the pchIPv4 prefix; otherwise
         *  NET_IPV6. Never produces NET_ONION (the V1 format cannot carry it). */
        void SetLegacyIPv6(const uint8_t bytes[16]);

        // ----- BIP155 (addrv2) wire format -----
        // Explicit member functions, NOT part of the SerializationOp dispatch.
        // Callers reach the V2 path through the CAddrVecV2 wrapper. V1 wire
        // and on-disk formats are provably untouched by the V2 code path.
        template <typename Stream> void SerializeV2(Stream& s) const;
        template <typename Stream> void UnserializeV2(Stream& s);

        friend class CSubNet;
};

class CSubNet
{
    protected:
        /// Network (base) address
        CNetAddr network;
        /// Netmask, in network byte order
        uint8_t netmask[16];
        /// Is this value valid? (only used to signal parse errors)
        bool valid;

    public:
        CSubNet();
        explicit CSubNet(const std::string &strSubnet, bool fAllowLookup = false);

        bool Match(const CNetAddr &addr) const;

        std::string ToString() const;
        bool IsValid() const;

        friend bool operator==(const CSubNet& a, const CSubNet& b);
        friend bool operator!=(const CSubNet& a, const CSubNet& b);
        friend bool operator<(const CSubNet& a, const CSubNet& b);
};

/** A combination of a network address (CNetAddr) and a (TCP) port */
class CService : public CNetAddr
{
    protected:
        unsigned short port; // host order

    public:
        CService();
        CService(const CNetAddr& ip, unsigned short port);
        CService(const struct in_addr& ipv4Addr, unsigned short port);
        CService(const struct sockaddr_in& addr);
        explicit CService(const char *pszIpPort, int portDefault, bool fAllowLookup = false);
        explicit CService(const char *pszIpPort, bool fAllowLookup = false);
        explicit CService(const std::string& strIpPort, int portDefault, bool fAllowLookup = false);
        explicit CService(const std::string& strIpPort, bool fAllowLookup = false);
        void Init();
        void SetPort(unsigned short portIn);
        unsigned short GetPort() const;
        bool GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const;
        bool SetSockAddr(const struct sockaddr* paddr);
        friend bool operator==(const CService& a, const CService& b);
        friend bool operator!=(const CService& a, const CService& b);
        friend bool operator<(const CService& a, const CService& b);
        std::vector<unsigned char> GetKey() const;
        std::string ToString() const;
        std::string ToStringPort() const;
        std::string ToStringIPPort() const;

        CService(const struct in6_addr& ipv6Addr, unsigned short port);
        CService(const struct sockaddr_in6& addr);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            uint8_t serialized[16];
            unsigned short portN;
            if (ser_action.ForRead()) {
                READWRITE(FLATDATA(serialized));
                READWRITE(FLATDATA(portN));
                SetLegacyIPv6(serialized);
                port = ntohs(portN);
            } else {
                SerializeV1Array(serialized);
                portN = htons(port);
                READWRITE(FLATDATA(serialized));
                READWRITE(FLATDATA(portN));
            }
        }

        // ----- BIP155 (addrv2) wire format -----
        template <typename Stream> void SerializeV2(Stream& s) const;
        template <typename Stream> void UnserializeV2(Stream& s);
};

// =================================================================
// BIP155 (addrv2) wire-format member templates.
//
// These are explicit member functions, NOT routed through the
// CNetAddr/CService::SerializationOp dispatch. The intent is that
// callers reach the V2 path only by going through CAddrVecV2 (below)
// or by invoking SerializeV2/UnserializeV2 directly. The legacy V1
// SerializationOp is therefore provably untouched, and on-disk and
// V1 wire formats are unaffected by anything in this section.
//
// Why explicit methods instead of a stream-flag dispatch:
// fluxd's serializer (circa 2013) uses an int nType bit-bag and has
// no per-call parameter mechanism. Setting a SER_ADDRV2 bit on the
// shared per-connection ssSend stream would require flipping a flag
// mid-message and is fragile. Bypassing SerializationOp via dedicated
// methods is the cleanest port of Bitcoin's BIP155 work to this
// generation of the codebase.
// =================================================================

template <typename Stream>
inline void CNetAddr::SerializeV2(Stream& s) const
{
    switch (m_net) {
    case NET_IPV4:
        ser_writedata8(s, (uint8_t)BIP155_IPV4);
        WriteCompactSize(s, m_addr.size());
        if (!m_addr.empty()) s.write((const char*)m_addr.data(), m_addr.size());
        break;
    case NET_ONION:
        ser_writedata8(s, (uint8_t)BIP155_TORV3);
        WriteCompactSize(s, m_addr.size());
        if (!m_addr.empty()) s.write((const char*)m_addr.data(), m_addr.size());
        break;
    case NET_IPV6:
    case NET_UNROUTABLE:
    default: {
        // For NET_IPV6 (and any unrecognized state) emit a 16-byte IPv6 entry.
        // Unroutable entries are emitted as the legacy 16-byte representation
        // and dropped by the receiver via IsValid() / IsRoutable().
        ser_writedata8(s, (uint8_t)BIP155_IPV6);
        WriteCompactSize(s, 16);
        uint8_t v1bytes[16];
        SerializeV1Array(v1bytes);
        s.write((const char*)v1bytes, 16);
        break;
    }
    }
}

template <typename Stream>
inline void CNetAddr::UnserializeV2(Stream& s)
{
    uint8_t network_id = ser_readdata8(s);
    uint64_t addr_size = ReadCompactSize(s);
    if (addr_size > ADDRV2_MAX_ADDRESS_SIZE) {
        throw std::ios_base::failure("BIP155 address payload exceeds 512 bytes");
    }
    std::vector<unsigned char> raw(addr_size);
    if (addr_size > 0) {
        s.read((char*)raw.data(), addr_size);
    }
    switch (network_id) {
    case BIP155_IPV4:
        if (addr_size == 4) {
            m_net = NET_IPV4;
            m_addr = std::move(raw);
            return;
        }
        break;
    case BIP155_IPV6:
        if (addr_size == 16) {
            m_net = NET_IPV6;
            m_addr = std::move(raw);
            return;
        }
        break;
    case BIP155_TORV3:
        if (addr_size == ADDR_TORV3_SIZE) {
            m_net = NET_ONION;
            m_addr = std::move(raw);
            return;
        }
        break;
    case BIP155_TORV2:
    case BIP155_I2P:
    case BIP155_CJDNS:
    default:
        break;
    }
    // Unrecognized / size-mismatched / unsupported network: present as
    // unspecified IPv6 so IsValid() rejects it and the caller drops the entry.
    m_net = NET_IPV6;
    m_addr.assign(16, 0);
}

template <typename Stream>
inline void CService::SerializeV2(Stream& s) const
{
    CNetAddr::SerializeV2(s);
    // BIP155: port is 2 bytes in network byte order.
    uint8_t pbuf[2] = { (uint8_t)((port >> 8) & 0xff), (uint8_t)(port & 0xff) };
    s.write((const char*)pbuf, 2);
}

template <typename Stream>
inline void CService::UnserializeV2(Stream& s)
{
    CNetAddr::UnserializeV2(s);
    uint8_t pbuf[2];
    s.read((char*)pbuf, 2);
    port = ((unsigned short)pbuf[0] << 8) | (unsigned short)pbuf[1];
}

// Forward decl — full definition lives in protocol.h, but CAddrVecV2 below
// references it via SerializeV2/UnserializeV2 instances declared there.
class CAddress;

/** Wrapper that lets a std::vector<CAddress> ride fluxd's standard ssSend
 *  serializer pipeline (i.e. PushMessage("addrv2", CAddrVecV2(vAddr))) while
 *  still routing each element through the explicit BIP155 methods.
 *
 *  We hold a const reference for sends and a mutable pointer for receives.
 *  The latter requires constructing the wrapper around an empty vector and
 *  then calling Unserialize on it. */
class CAddrVecV2
{
public:
    explicit CAddrVecV2(const std::vector<CAddress>& v) : m_const(&v), m_mut(nullptr) {}
    explicit CAddrVecV2(std::vector<CAddress>& v)       : m_const(&v), m_mut(&v) {}

    template <typename Stream> void Serialize(Stream& s) const;
    template <typename Stream> void Unserialize(Stream& s);

private:
    const std::vector<CAddress>* m_const;
    std::vector<CAddress>*       m_mut;
};

class proxyType
{
public:
    proxyType(): randomize_credentials(false) {}
    proxyType(const CService &proxy, bool randomize_credentials=false): proxy(proxy), randomize_credentials(randomize_credentials) {}

    bool IsValid() const { return proxy.IsValid(); }

    CService proxy;
    bool randomize_credentials;
};

enum Network ParseNetwork(std::string net);
std::string GetNetworkName(enum Network net);
void SplitHostPort(std::string in, int &portOut, std::string &hostOut);
bool SetProxy(enum Network net, const proxyType &addrProxy);
bool GetProxy(enum Network net, proxyType &proxyInfoOut);
bool IsProxy(const CNetAddr &addr);
bool SetNameProxy(const proxyType &addrProxy);
bool HaveNameProxy();
bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, CService& addr, int portDefault = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault = 0, bool fAllowLookup = true, unsigned int nMaxSolutions = 0);
bool LookupNumeric(const char *pszName, CService& addr, int portDefault = 0);
bool ConnectSocket(const CService &addr, SOCKET& hSocketRet, int nTimeout, bool *outProxyConnectionFailed = 0);
bool ConnectSocketByName(CService &addr, SOCKET& hSocketRet, const char *pszDest, int portDefault, int nTimeout, bool *outProxyConnectionFailed = 0);
/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET& hSocket);
/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(SOCKET& hSocket, bool fNonBlocking);
/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);

#endif // BITCOIN_NETBASE_H
