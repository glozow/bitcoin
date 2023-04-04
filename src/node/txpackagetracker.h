// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXPACKAGETRACKER_H
#define BITCOIN_NODE_TXPACKAGETRACKER_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

namespace node {
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};

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
    /** Peer has disconnected, tear down state. */
    void DisconnectedPeer(NodeId nodeid);
    /** Returns whether a tx is present in the orphanage. */
    bool OrphanageHaveTx(const GenTxid& gtxid) const;
    bool AddOrphanTx(const CTransactionRef& tx, NodeId peer);
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
};
} // namespace node
#endif // BITCOIN_NODE_TXPACKAGETRACKER_H
