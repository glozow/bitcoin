// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXPACKAGETRACKER_H
#define BITCOIN_NODE_TXPACKAGETRACKER_H

#include <net.h>
#include <policy/packages.h>

#include <cstdint>
#include <map>
#include <vector>

class CBlock;
namespace node {
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};
static constexpr uint32_t RECEIVER_INIT_ANCESTOR_PACKAGES{0};
static std::vector<uint32_t> PACKAGE_RELAY_SUPPORTED_VERSIONS = {
    RECEIVER_INIT_ANCESTOR_PACKAGES,
};
/** If working on this many packages with a peer, drop any new orphan resolutions with this peer and
 * try a different peer (assuming another peer announced the tx as well) instead.
 * Includes package info requests, tx data download, and packages in validation queue.
 * This is meant to bound the memory reserved for protected orphans; a single peer should not be
 * able to cause us to store lots of orphans by announcing packages and stalling download.
 * Individual packages are also bounded in size. */
static constexpr size_t MAX_IN_FLIGHT_PACKAGES{1};

class TxPackageTracker {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    struct Options {
        bool enable_package_relay{DEFAULT_ENABLE_PACKAGE_RELAY};
        /** Maximum number of transactions in orphanage. Configured using -maxorphantx.*/
        unsigned int max_orphan_count{DEFAULT_MAX_ORPHAN_TRANSACTIONS};
    };
    TxPackageTracker(const Options& opts);
    ~TxPackageTracker();
    /** New block. */
    void BlockConnected(const CBlock& block);
    /** Get list of supported package relay versions. */
    std::vector<uint32_t> GetVersions() { return PACKAGE_RELAY_SUPPORTED_VERSIONS; }
    void ReceivedVersion(NodeId nodeid);
    void ReceivedSendpackages(NodeId nodeid, uint32_t version);
    // Finalize the registration state.
    bool ReceivedVerack(NodeId nodeid, bool txrelay, bool wtxidrelay);

    /** Peer has disconnected, tear down state. */
    void DisconnectedPeer(NodeId nodeid);
    /** Returns whether a tx is present in the orphanage. */
    bool OrphanageHaveTx(const GenTxid& gtxid) const;
    /** Transaction accepted to mempool. */
    void TransactionAccepted(const CTransactionRef& tx);
    /** Transaction rejected for non-missing-inputs reason. */
    void TransactionRejected(const uint256& wtxid);
    /** Get tx from orphan that can be reconsidered. */
    CTransactionRef GetTxToReconsider(NodeId nodeid);
    /** Whether there are more orphans from this peer to consider. */
    bool HaveTxToReconsider(NodeId nodeid) const;
    /** Returns the number of transactions in the orphanage. */
    size_t OrphanageSize() const;

    /** Received an announcement from this peer for a tx we already know is an orphan; should be
     * called for every peer that announces the tx, even if they are not a package relay peer.
     * The orphan request tracker will decide when to request what from which peer - use
     * GetOrphanRequests().
     * returns whether this transaction has been newly added to the orphanage.
     */
    void AddOrphanTx(NodeId nodeid, const std::pair<uint256, CTransactionRef>& tx, bool is_preferred, std::chrono::microseconds reqtime);

    /** Number of packages we are working on with this peer. Includes any entries in the orphan
     * tracker, in-flight orphan parent requests (1 per orphan regardless of how many missing
     * parents were requested), package info requests, tx data download, and packages in the
     * validation queue. */
    size_t Count(NodeId nodeid) const;

    /** Number of packages we are currently working on with this peer (i.e. reserving memory for
     * storing orphan(s)). Includes in-flight package info requests, tx data download, and packages
     * in the validation queue. Excludes entries in the orphan tracker that are just candidates. */
    size_t CountInFlight(NodeId nodeid) const;

    /** Get list of requests that should be sent to resolve orphans. These may be wtxids to send
     * getdata(ANCPKGINFO) or txids corresponding to parents. Automatically marks the orphans as
     * having outgoing requests. */
    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time);

    /** Whether a package info message is allowed:
     * - We agreed to relay packages of this version with this peer.
     * - We solicited this package info.
     * Returns false if the peer should be disconnected. */
    bool PkgInfoAllowed(NodeId nodeid, const uint256& wtxid, uint32_t version);

    /** Record receipt of a notfound message for pkginfo. */
    void ForgetPkgInfo(NodeId nodeid, const uint256& rep_wtxid, uint32_t pkginfo_version);

    /** Record receipt of an ancpkginfo, which transactions are missing (and requested),
     * and when to expire it. */
    bool ReceivedAncPkgInfo(NodeId nodeid, const uint256& rep_wtxid, const std::map<uint256, bool>& txdata_status,
                            const std::vector<uint256>& missing_wtxids, int64_t total_orphan_size,
                            std::chrono::microseconds expiry);
};
} // namespace node
#endif // BITCOIN_NODE_TXPACKAGETRACKER_H
