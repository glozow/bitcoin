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

    // Received an orphan. Should request ancpkginfo. Call this for any peer, even if not registered.
    void AddOrphanTx(NodeId nodeid, const uint256& wtxid, bool is_preferred, std::chrono::microseconds expiry);

    // Number of orphans we are considering for this peer.
    size_t CountOrphans(NodeId nodeid) const;

    // Get list of requests that should be sent to resolve orphans. These may be wtxids to send
    // getdata(ANCPKGINFO) or txids corresponding to parents. Automatically marks the orphans as
    // having outgoing requests.
    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid) const;

    /** Update transactions for which we have made "final" decisions: transactions that have
     * confirmed in a block, conflicted due to a block, or added to the mempool already.
     * Should be called on new block: valid=block transactions, invalid=conflicts.
     * Should be called when tx is added to mempool.
     * */
    void FinalizeTransactions(const std::set<uint256>& valid, const std::set<uint256>& invalid);

    enum class TxDataStatus : uint8_t {
        /** We still need the tx data and may or may not have requested it. */
        MISSING,
        /** We have the tx data in our orphanage. */
        ORPHANAGE,
        /** We already have the tx data in mempool or confirmed. */
        ACCEPTED,
    };
    /** Whether a package info message is allowed:
     * - We agreed to relay packages of this version with this peer.
     * - We solicited this package info.
     * Returns false if the peer should be disconnected. */
    bool PkgInfoAllowed(NodeId nodeid, const uint256& wtxid, uint32_t version);
    /** Record receipt of an ancpkginfo, which transactions are missing (and requested),
     * and when to expire it. */
    bool ReceivedAncPkgInfo(NodeId nodeid, const uint256& rep_wtxid, const std::map<uint256,
                            TxDataStatus>& txdata_status, int64_t total_orphan_size,
                            std::chrono::microseconds expiry);
};

#endif // BITCOIN_TX_PKG_RELAY_H
