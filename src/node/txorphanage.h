// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXORPHANAGE_H
#define BITCOIN_TXORPHANAGE_H

#include <consensus/validation.h>
#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <util/time.h>

#include <map>
#include <set>

namespace node{
class TxOrphanageImpl;

/** Default maximum number of orphan transactions kept in memory */
static const uint32_t DEFAULT_MAX_ORPHAN_TRANSACTIONS{100};

/** A class to track orphan transactions (failed on TX_MISSING_INPUTS)
 * Since we cannot distinguish orphans from bad transactions with
 * non-existent inputs, we heavily limit the number of orphans
 * we keep and the duration we keep them for.
 * Not thread-safe. Requires external synchronization.
 */
class TxOrphanage {
    const std::unique_ptr<TxOrphanageImpl> m_impl;
public:
    explicit TxOrphanage();
    ~TxOrphanage();

    /** Add a new orphan transaction */
    bool AddTx(const CTransactionRef& tx, NodeId peer);

    /** Add an additional announcer to an orphan if it exists. Otherwise, do nothing. */
    bool AddAnnouncer(const Wtxid& wtxid, NodeId peer);

    CTransactionRef GetTx(const Wtxid& wtxid) const;

    /** Check if we already have an orphan transaction (by wtxid only) */
    bool HaveTx(const Wtxid& wtxid) const;

    /** Check if a {tx, peer} exists in the orphanage.*/
    bool HaveTxFromPeer(const Wtxid& wtxid, NodeId peer) const;

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef GetTxToReconsider(NodeId peer);

    /** Erase an orphan by wtxid */
    int EraseTx(const Wtxid& wtxid);

    /** Maybe erase all orphans announced by a peer (eg, after that peer disconnects). If an orphan
     * has been announced by another peer, don't erase, just remove this peer from the list of announcers. */
    void EraseForPeer(NodeId peer);

    /** Erase all orphans included in or invalidated by a new block */
    void EraseForBlock(const CBlock& block);

    /** Limit the orphanage to the given maximum */
    void LimitOrphans();

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx, FastRandomContext& rng);

    /** Does this peer have any work to do? */
    bool HaveTxToReconsider(NodeId peer);

    /** Get all children that spend from this tx and were received from nodeid. Sorted from most
     * recent to least recent. */
    std::vector<CTransactionRef> GetChildrenFromSamePeer(const CTransactionRef& parent, NodeId nodeid) const;

    /** Return how many entries exist in the orphange */
    size_t Size() const;

    /** Allows providing orphan information externally */
    struct OrphanTxBase {
        CTransactionRef tx;
        /** Peers added with AddTx or AddAnnouncer. */
        std::set<NodeId> announcers;
    };

    std::vector<OrphanTxBase> GetOrphanTransactions() const;

    /** Get the total usage (weight) of all orphans. If an orphan has multiple announcers, its usage is
     * only counted once within this total. */
    int64_t TotalOrphanUsage() const;

    /** Total usage (weight) of orphans for which this peer is an announcer. If an orphan has multiple
     * announcers, its weight will be accounted for in each PeerOrphanInfo, so the total of all
     * peers' UsageByPeer() may be larger than TotalOrphanBytes(). */
    int64_t UsageByPeer(NodeId peer) const;

    /** Check consistency between PeerOrphanInfo and m_orphans. Recalculate counters and ensure they
     * match what is cached. */
    void SanityCheck() const;
};
} // namespace node
#endif // BITCOIN_TXORPHANAGE_H
