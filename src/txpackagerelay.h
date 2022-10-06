// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TX_PKG_RELAY_H
#define BITCOIN_TX_PKG_RELAY_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

class TxOrphanage;

static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};
static constexpr uint32_t RECEIVER_INIT_ANCESTOR_PACKAGES{0};
static std::vector<uint32_t> PACKAGE_RELAY_SUPPORTED_VERSIONS = {
    RECEIVER_INIT_ANCESTOR_PACKAGES,
};

class TxPackageTracker {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxPackageTracker(TxOrphanage& orphanage);
    ~TxPackageTracker();
    std::vector<uint32_t> GetVersions() { return PACKAGE_RELAY_SUPPORTED_VERSIONS; }

    // We expect this to be called only once
    void ReceivedVersion(NodeId nodeid);
    // Can call this for fRelay
    void ReceivedTxRelayInfo(NodeId nodeid, bool txrelay);
    void ReceivedWtxidRelay(NodeId nodeid);
    void ReceivedSendpackages(NodeId nodeid, uint32_t version);
    // Sent sendpackages messages for each version in PACKAGE_RELAY_SUPPORTED_VERSIONS
    void SentSendpackages(NodeId nodeid);

    // Finalize the registration state.
    bool ReceivedVerack(NodeId nodeid);

    // Tear down all state
    void DisconnectedPeer(NodeId nodeid);
};

#endif // BITCOIN_TX_PKG_RELAY_H
