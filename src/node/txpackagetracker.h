// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXPACKAGETRACKER_H
#define BITCOIN_NODE_TXPACKAGETRACKER_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

class CBlock;
class TxOrphanage;
namespace node {
static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};

class TxPackageTracker {
    class Impl;
    const std::unique_ptr<Impl> m_impl;
public:
    struct Options {
        unsigned int m_max_orphanage_count;
    };

    explicit TxPackageTracker(const Options& options);
    ~TxPackageTracker();

    /** Check if we already have an orphan transaction (by txid or wtxid) */
    bool OrphanageHaveTx(const GenTxid& gtxid);

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef GetTxToReconsider(NodeId peer);

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void DisconnectedPeer(NodeId peer);

    /** Erase all orphans included in or invalidated by a new block */
    void BlockConnected(const CBlock& block);

    /** Does this peer have any orphans to validate? */
    bool HaveTxToReconsider(NodeId peer);

    /** Return how many entries exist in the orphange */
    size_t OrphanageSize();

    /** Should be called when a transaction is accepted to the mempool. If it was an orphan we were
     * trying to resolve, remove its entries from the orphanage and other data structures. If it is
     * the ancestor of an orphan, add the orphan to its associated peer's workset. */
    void MempoolAcceptedTx(const CTransactionRef& ptx);

    /** Should be called when a transaction is rejected from the mempool and is not an orphan we
     * still want to try to resolve. Remove its entries from the orphanage and other data
     * structures. */
    void MempoolRejectedTx(const uint256& wtxid);

    /** Add a new orphan or an announcement for a known orphan. This should be called for every
     * peer that announces the orphan.  The orphan request tracker will decide when to request what
     * from which peer - use GetOrphanRequests().
     * @param[in]   tx      CTransactionRef if this is a new orphan, or nullptr if an announcement
     *                      for a known orphan.
     * @param[in]   reqtime Some time in the future when the orphan resolution information should be
     *                      requested. This may be further extended internally.
     */
    void AddOrphanTx(NodeId nodeid, const uint256& wtxid, const CTransactionRef& tx, bool is_preferred, std::chrono::microseconds reqtime);

    /** Number of orphans this peer has told us about, including ones for which we don't have
     * in-flight requests. */
    size_t Count(NodeId nodeid) const;

    /** Number of packages we are working on with this peer that have in-flight requests. For
     * example, orphans for which we have requested parents and are waiting for a response (1 per
     * orphan regardless of how many missing parents were requested). */
    size_t CountInFlight(NodeId nodeid) const;

    /** Get list of requests that should be sent to resolve orphans. These may be wtxids to send
     * getdata(ANCPKGINFO) or txids corresponding to parents. Automatically marks the orphans as
     * having outgoing requests. */
    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time);
};
} // namespace node
#endif // BITCOIN_NODE_TXPACKAGETRACKER_H
