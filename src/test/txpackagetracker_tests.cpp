// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txorphanage.h>
#include <txpackagerelay.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(txpackagetracker_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(pkginfo)
{
    TxOrphanage orphanage;
    TxPackageTracker tracker(orphanage);
    BOOST_CHECK_EQUAL(tracker.GetVersions().size(), 1);

    // Peer 0: successful handshake
    NodeId peer = 0;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedTxRelayInfo(peer, true);
    tracker.ReceivedWtxidRelay(peer);
    tracker.ReceivedSendpackages(peer, RECEIVER_INIT_ANCESTOR_PACKAGES);
    tracker.SentSendpackages(peer);
    BOOST_CHECK(tracker.ReceivedVerack(peer));

    // Peer 1: unsupported version(s)
    const uint32_t unsupported_package_type{3};
    peer = 1;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedTxRelayInfo(peer, true);
    tracker.ReceivedWtxidRelay(peer);
    tracker.ReceivedSendpackages(peer, unsupported_package_type);
    tracker.SentSendpackages(peer);
    BOOST_CHECK(tracker.ReceivedVerack(peer));

    // Peer 2: no wtxidrelay
    peer = 2;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedTxRelayInfo(peer, true);
    tracker.ReceivedSendpackages(peer, RECEIVER_INIT_ANCESTOR_PACKAGES);
    tracker.SentSendpackages(peer);
    BOOST_CHECK(!tracker.ReceivedVerack(peer));

    // Peer 3: fRelay=false
    peer = 3;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedTxRelayInfo(peer, false);
    tracker.ReceivedWtxidRelay(peer);
    tracker.ReceivedSendpackages(peer, RECEIVER_INIT_ANCESTOR_PACKAGES);
    tracker.SentSendpackages(peer);
    BOOST_CHECK(!tracker.ReceivedVerack(peer));

    // Peer 4: we didn't send sendpackages
    peer = 4;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedTxRelayInfo(peer, true);
    tracker.ReceivedWtxidRelay(peer);
    tracker.ReceivedSendpackages(peer, RECEIVER_INIT_ANCESTOR_PACKAGES);
    BOOST_CHECK(!tracker.ReceivedVerack(peer));
}

BOOST_AUTO_TEST_SUITE_END()
