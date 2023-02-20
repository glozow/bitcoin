// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackagetracker.h>
#include <txorphanage.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(txpackagetracker_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(pkginfo)
{
    TxOrphanage orphanage;
    node::TxPackageTracker tracker(orphanage);
    BOOST_CHECK_EQUAL(tracker.GetVersions().size(), 1);

    // Peer 0: successful handshake
    NodeId peer = 0;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedSendpackages(peer, node::RECEIVER_INIT_ANCESTOR_PACKAGES);
    BOOST_CHECK(tracker.ReceivedVerack(peer, /*txrelay=*/true, /*wtxidrelay=*/true));

    // Peer 1: unsupported version(s)
    const uint32_t unsupported_package_type{3};
    peer = 1;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedSendpackages(peer, unsupported_package_type);
    BOOST_CHECK(tracker.ReceivedVerack(peer, /*txrelay=*/true, /*wtxidrelay=*/true));

    // Peer 2: no wtxidrelay
    peer = 2;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedSendpackages(peer, node::RECEIVER_INIT_ANCESTOR_PACKAGES);
    BOOST_CHECK(!tracker.ReceivedVerack(peer, /*txrelay=*/true, /*wtxidrelay=*/false));

    // Peer 3: fRelay=false
    peer = 3;
    tracker.ReceivedVersion(peer);
    tracker.ReceivedSendpackages(peer, node::RECEIVER_INIT_ANCESTOR_PACKAGES);
    BOOST_CHECK(!tracker.ReceivedVerack(peer, /*txrelay=*/false, /*wtxidrelay=*/true));

    for (NodeId i{0}; i < peer + 1; ++i) {
        BOOST_CHECK_EQUAL(tracker.Count(i), 0);
        BOOST_CHECK_EQUAL(tracker.CountInFlight(i), 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
