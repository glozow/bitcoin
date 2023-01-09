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
class TxOrphanage;
namespace node {
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
    explicit TxPackageTracker();
    ~TxPackageTracker();

    // Orphanage wrapper functions
    /** Add new tx to orphanage if it isn't already there. Returns whether the tx was added. */
    bool OrphanageAddTx(const CTransactionRef& tx, NodeId peer);

    /** Check if we already have an orphan transaction (by txid or wtxid) */
    bool OrphanageHaveTx(const GenTxid& gtxid);

    /** Get virtual size of an orphan transaction if it exists. */
    int64_t OrphanageGetTxSize(const uint256& wtxid);

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef GetTxToReconsider(NodeId peer);

    /** Erase an orphan by txid */
    int EraseOrphanTx(const uint256& txid);

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void EraseOrphanForPeer(NodeId peer);

    /** Erase all orphans included in or invalidated by a new block */
    void BlockConnected(const CBlock& block);

    /** Limit the orphanage to the given maximum */
    void LimitOrphans(unsigned int max_orphans);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx);

    /** Does this peer have any orphans to validate? */
    bool HaveTxToReconsider(NodeId peer);

    /** Return how many entries exist in the orphange */
    size_t OrphanageSize();

    std::vector<uint32_t> GetVersions() { return PACKAGE_RELAY_SUPPORTED_VERSIONS; }

    // We expect this to be called only once
    void ReceivedVersion(NodeId nodeid);
    void ReceivedSendpackages(NodeId nodeid, uint32_t version);
    // Finalize the registration state.
    bool ReceivedVerack(NodeId nodeid, bool txrelay, bool wtxidrelay);

    // Tear down all state
    void DisconnectedPeer(NodeId nodeid);

    /** Received an announcement from this peer for a tx we already know is an orphan; should be
     * called for every peer that announces the tx, even if they are not a package relay peer.
     * The orphan request tracker will decide when to request what from which peer - use
     * GetOrphanRequests().
     */
    void AddOrphanTx(NodeId nodeid, const uint256& wtxid, bool is_preferred, std::chrono::microseconds reqtime);

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

    /** Update transactions for which we have made "final" decisions: transactions that have
     * confirmed in a block, conflicted due to a block, or added to the mempool already.
     * Should be called on new block: valid=block transactions, invalid=conflicts.
     * Should be called when tx is added to mempool.
     * Should not be called when a tx fails validation.
     * */
    void FinalizeTransactions(const std::set<uint256>& valid, const std::set<uint256>& invalid);

    /** Handle new block: Stop trying to resolve orphans that have been confirmed in or conflicted
     * by a block. */
    void HandleNewBlock(const CBlock& block);

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

    /** Record receipt of notfound message for pkgtxns. */
    void ReceivedNotFound(NodeId nodeid, const uint256& hash);

    struct PackageToValidate {
        /** Who provided the package info. */
        const NodeId m_info_provider;
        /** Representative transaction, i.e. orphan in an ancestor package. */
        const uint256 m_rep_wtxid;
        /** Combined hash of all transactions in package info. Used to cache failure. */
        const uint256 m_pkginfo_hash;
        /** Transactions to submit for mempool validation. */
        const Package m_unvalidated_txns;

        PackageToValidate() = delete;
        PackageToValidate(NodeId info_provider,
                          const uint256& rep_wtxid,
                          const uint256& pkginfo_hash,
                          const Package& txns) :
            m_info_provider{info_provider},
            m_rep_wtxid{rep_wtxid},
            m_pkginfo_hash{pkginfo_hash},
            m_unvalidated_txns{txns}
        {}
    };

    /** If there is a package that is missing this tx data, updates the PendingPackage and
     * returns a PackageToValidate including the other txdata stored in the orphanage.
     */
    std::optional<PackageToValidate> ReceivedPkgTxns(NodeId nodeid, const std::vector<CTransactionRef>& package_txns);
};
} // namespace node
#endif // BITCOIN_NODE_TXPACKAGETRACKER_H
