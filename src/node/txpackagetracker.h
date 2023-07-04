// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXPACKAGETRACKER_H
#define BITCOIN_NODE_TXPACKAGETRACKER_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

class TxOrphanage;
namespace node {
static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};

class TxPackageTracker {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxPackageTracker();
    ~TxPackageTracker();

    bool OrphanageAddTx(const CTransactionRef& tx, NodeId peer);

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

    void LimitOrphans(unsigned int max_orphans);

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
};
} // namespace node
#endif // BITCOIN_NODE_TXPACKAGETRACKER_H
