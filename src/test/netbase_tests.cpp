// Copyright (c) 2012-2013 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "netbase.h"
#include "test/test_bitcoin.h"

#include <string>

#include <boost/assign/list_of.hpp>
#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(netbase_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(netbase_networks)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").GetNetwork()                              == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("::1").GetNetwork()                                    == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("8.8.8.8").GetNetwork()                                == NET_IPV4);
    BOOST_CHECK(CNetAddr("2001::8888").GetNetwork()                             == NET_IPV6);
    // The OnionCat v2 IPv6-prefix test was removed when TORv2 support was dropped.

    // TORv3 .onion address (BIP155 / rend-spec-v3). Test vector borrowed from
    // Bitcoin Core's net_tests.cpp; the 32-byte ed25519 pubkey is
    //   53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88
    {
        CNetAddr torv3;
        BOOST_CHECK(torv3.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
        BOOST_CHECK(torv3.IsTor());
        BOOST_CHECK(torv3.IsValid());
        BOOST_CHECK(torv3.IsRoutable());
        BOOST_CHECK_EQUAL(torv3.GetNetwork(), NET_ONION);
        BOOST_CHECK_EQUAL(torv3.ToStringIP(),
                          "kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion");
    }

    // A 16-character (TORv2) .onion string must be rejected — TORv2 is dropped.
    {
        CNetAddr v2;
        BOOST_CHECK(!v2.SetSpecial("5wyqrzbvrdsumnok.onion"));
        BOOST_CHECK(!v2.IsTor());
    }

    // A v3 string with a corrupted checksum must be rejected. Take the valid
    // address above and flip a single base32 character inside the checksum/version
    // tail (the last 8 chars cover bytes 32..34 — checksum + version).
    {
        CNetAddr bad;
        BOOST_CHECK(!bad.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaie.onion"));
        BOOST_CHECK(!bad.IsTor());
    }
}

BOOST_AUTO_TEST_CASE(netbase_properties)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::FFFF:192.168.1.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::1").IsIPv6());
    BOOST_CHECK(CNetAddr("10.0.0.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("192.168.1.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("172.31.255.255").IsRFC1918());
    BOOST_CHECK(CNetAddr("2001:0DB8::").IsRFC3849());
    BOOST_CHECK(CNetAddr("169.254.1.1").IsRFC3927());
    BOOST_CHECK(CNetAddr("2002::1").IsRFC3964());
    BOOST_CHECK(CNetAddr("FC00::").IsRFC4193());
    BOOST_CHECK(CNetAddr("2001::2").IsRFC4380());
    BOOST_CHECK(CNetAddr("2001:10::").IsRFC4843());
    BOOST_CHECK(CNetAddr("FE80::").IsRFC4862());
    BOOST_CHECK(CNetAddr("64:FF9B::").IsRFC6052());
    // OnionCat v2 .IsTor() check removed — TORv3 has its own tests in Phase 3.
    BOOST_CHECK(CNetAddr("127.0.0.1").IsLocal());
    BOOST_CHECK(CNetAddr("::1").IsLocal());
    BOOST_CHECK(CNetAddr("8.8.8.8").IsRoutable());
    BOOST_CHECK(CNetAddr("2001::1").IsRoutable());
    BOOST_CHECK(CNetAddr("127.0.0.1").IsValid());
}

bool static TestSplitHost(string test, string host, int port)
{
    string hostOut;
    int portOut = -1;
    SplitHostPort(test, portOut, hostOut);
    return hostOut == host && port == portOut;
}

BOOST_AUTO_TEST_CASE(netbase_splithost)
{
    BOOST_CHECK(TestSplitHost("www.bitcoin.org", "www.bitcoin.org", -1));
    BOOST_CHECK(TestSplitHost("[www.bitcoin.org]", "www.bitcoin.org", -1));
    BOOST_CHECK(TestSplitHost("www.bitcoin.org:80", "www.bitcoin.org", 80));
    BOOST_CHECK(TestSplitHost("[www.bitcoin.org]:80", "www.bitcoin.org", 80));
    BOOST_CHECK(TestSplitHost("127.0.0.1", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("127.0.0.1:8333", "127.0.0.1", 8333));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]:8333", "127.0.0.1", 8333));
    BOOST_CHECK(TestSplitHost("::ffff:127.0.0.1", "::ffff:127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[::ffff:127.0.0.1]:8333", "::ffff:127.0.0.1", 8333));
    BOOST_CHECK(TestSplitHost("[::]:8333", "::", 8333));
    BOOST_CHECK(TestSplitHost("::8333", "::8333", -1));
    BOOST_CHECK(TestSplitHost(":8333", "", 8333));
    BOOST_CHECK(TestSplitHost("[]:8333", "", 8333));
    BOOST_CHECK(TestSplitHost("", "", -1));
}

bool static TestParse(string src, string canon)
{
    CService addr;
    if (!LookupNumeric(src.c_str(), addr, 65535))
        return canon == "";
    return canon == addr.ToString();
}

BOOST_AUTO_TEST_CASE(netbase_lookupnumeric)
{
    BOOST_CHECK(TestParse("127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("127.0.0.1:8333", "127.0.0.1:8333"));
    BOOST_CHECK(TestParse("::ffff:127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("::", "[::]:65535"));
    BOOST_CHECK(TestParse("[::]:8333", "[::]:8333"));
    BOOST_CHECK(TestParse("[127.0.0.1]", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse(":::", ""));
}

BOOST_AUTO_TEST_CASE(subnet_test)
{
    BOOST_CHECK(CSubNet("1.2.3.0/24") == CSubNet("1.2.3.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24") != CSubNet("1.2.4.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.2.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4/32").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.3.4").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(!CSubNet("1.2.3.4/32").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(CSubNet("::ffff:127.0.0.1").Match(CNetAddr("127.0.0.1")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:8")));
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:9")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:0/112").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    BOOST_CHECK(CSubNet("192.168.0.1/24").Match(CNetAddr("192.168.0.2")));
    BOOST_CHECK(CSubNet("192.168.0.20/29").Match(CNetAddr("192.168.0.18")));
    BOOST_CHECK(CSubNet("1.2.2.1/24").Match(CNetAddr("1.2.2.4")));
    BOOST_CHECK(CSubNet("1.2.2.110/31").Match(CNetAddr("1.2.2.111")));
    BOOST_CHECK(CSubNet("1.2.2.20/26").Match(CNetAddr("1.2.2.63")));
    // All-Matching IPv6 Matches arbitrary IPv4 and IPv6
    BOOST_CHECK(CSubNet("::/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    BOOST_CHECK(CSubNet("::/0").Match(CNetAddr("1.2.3.4")));
    // All-Matching IPv4 does not Match IPv6
    BOOST_CHECK(!CSubNet("0.0.0.0/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    // Invalid subnets Match nothing (not even invalid addresses)
    BOOST_CHECK(!CSubNet().Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("").Match(CNetAddr("4.5.6.7")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("0.0.0.0")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("hab")));
    // Check valid/invalid
    BOOST_CHECK(CSubNet("1.2.3.0/0").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/-1").IsValid());
    BOOST_CHECK(CSubNet("1.2.3.0/32").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/33").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/0").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/33").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/-1").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/128").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/129").IsValid());
    BOOST_CHECK(!CSubNet("fuzzy").IsValid());
}

BOOST_AUTO_TEST_CASE(netbase_getgroup)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").GetGroup() == boost::assign::list_of(0)); // Local -> !Routable()
    BOOST_CHECK(CNetAddr("257.0.0.1").GetGroup() == boost::assign::list_of(0)); // !Valid -> !Routable()
    BOOST_CHECK(CNetAddr("10.0.0.1").GetGroup() == boost::assign::list_of(0)); // RFC1918 -> !Routable()
    BOOST_CHECK(CNetAddr("169.254.1.1").GetGroup() == boost::assign::list_of(0)); // RFC3927 -> !Routable()
    BOOST_CHECK(CNetAddr("1.2.3.4").GetGroup() == boost::assign::list_of((unsigned char)NET_IPV4)(1)(2)); // IPv4
    BOOST_CHECK(CNetAddr("::FFFF:0:102:304").GetGroup() == boost::assign::list_of((unsigned char)NET_IPV4)(1)(2)); // RFC6145
    BOOST_CHECK(CNetAddr("64:FF9B::102:304").GetGroup() == boost::assign::list_of((unsigned char)NET_IPV4)(1)(2)); // RFC6052
    BOOST_CHECK(CNetAddr("2002:102:304:9999:9999:9999:9999:9999").GetGroup() == boost::assign::list_of((unsigned char)NET_IPV4)(1)(2)); // RFC3964
    BOOST_CHECK(CNetAddr("2001:0:9999:9999:9999:9999:FEFD:FCFB").GetGroup() == boost::assign::list_of((unsigned char)NET_IPV4)(1)(2)); // RFC4380
    // OnionCat v2 GetGroup test removed — TORv3 group is single-element {NET_ONION};
    // see netbase.cpp CNetAddr::GetGroup() and Phase 3 tests for verification.
    BOOST_CHECK(CNetAddr("2001:470:abcd:9999:9999:9999:9999:9999").GetGroup() == boost::assign::list_of((unsigned char)NET_IPV6)(32)(1)(4)(112)(175)); //he.net
    BOOST_CHECK(CNetAddr("2001:2001:9999:9999:9999:9999:9999:9999").GetGroup() == boost::assign::list_of((unsigned char)NET_IPV6)(32)(1)(32)(1)); //IPv6
}

BOOST_AUTO_TEST_SUITE_END()
