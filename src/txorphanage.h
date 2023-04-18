// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXORPHANAGE_H
#define BITCOIN_TXORPHANAGE_H

#include <net.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <map>
#include <set>

/** Maximum total size of orphan transactions stored, in bytes. */
static constexpr size_t MAX_ORPHAN_TOTAL_SIZE{100 * MAX_STANDARD_TX_WEIGHT};

/** A class to track orphan transactions (failed on TX_MISSING_INPUTS)
 * Since we cannot distinguish orphans from bad transactions with
 * non-existent inputs, we heavily limit the number of orphans
 * we keep and the duration we keep them for.
 */
class TxOrphanage {
public:
    /** Add a new orphan transaction */
    bool AddTx(const CTransactionRef& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Get orphan transaction by wtxid. Returns nullptr if we don't have it anymore. */
    CTransactionRef GetTx(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Check if we already have an orphan transaction (by txid or wtxid) */
    bool HaveTx(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef GetTxToReconsider(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase an orphan by wtxid */
    int EraseTx(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void EraseForPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans included in or invalidated by a new block. Returns wtxids of erased txns. */
    std::vector<uint256> EraseForBlock(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Limit the orphanage to the given maximum */
    void LimitOrphans(unsigned int max_orphans) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);;

    /** Does this peer have any work to do? */
    bool HaveTxToReconsider(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);;

    /** Return how many entries exist in the orphange */
    size_t Size() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_orphans.size();
    }

    /** Return total memory usage of the transactions stored. Does not include overhead of
     * m_orphans, m_peer_work_set, etc. */
    size_t TotalOrphanBytes() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_total_orphan_bytes;
    }
    size_t BytesFromPeer(NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        auto peer_bytes_it = m_peer_bytes_used.find(peer);
        return peer_bytes_it == m_peer_bytes_used.end() ? 0 : peer_bytes_it->second;
    }

protected:
    size_t m_total_orphan_bytes{0};

    /** Guards orphan transactions */
    mutable Mutex m_mutex;

    struct OrphanTx {
        CTransactionRef tx;
        NodeId fromPeer;
        int64_t nTimeExpire;
        size_t list_pos;
    };

    /** Map from txid to orphan transaction record. Limited by
     *  -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    std::map<uint256, OrphanTx> m_orphans GUARDED_BY(m_mutex);

    /** Which peer provided the orphans that need to be reconsidered */
    std::map<NodeId, std::set<uint256>> m_peer_work_set GUARDED_BY(m_mutex);

    using OrphanMap = decltype(m_orphans);

    struct IteratorComparator
    {
        template<typename I>
        bool operator()(const I& a, const I& b) const
        {
            return &(*a) < &(*b);
        }
    };

    /** Index from the parents' COutPoint into the m_orphans. Used
     *  to remove orphan transactions from the m_orphans */
    std::map<COutPoint, std::set<OrphanMap::iterator, IteratorComparator>> m_outpoint_to_orphan_it GUARDED_BY(m_mutex);

    /** Orphan transactions in vector for quick random eviction */
    std::vector<OrphanMap::iterator> m_orphan_list GUARDED_BY(m_mutex);

    /** Index from wtxid into the m_orphans to lookup orphan
     *  transactions using their witness ids. */
    std::map<uint256, OrphanMap::iterator> m_wtxid_to_orphan_it GUARDED_BY(m_mutex);

    /** Map from nodeid to the amount of orphans provided by this peer, in bytes. */
    std::map<NodeId, size_t> m_peer_bytes_used GUARDED_BY(m_mutex);

    /** Erase an orphan by txid */
    int _EraseTx(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
};

#endif // BITCOIN_TXORPHANAGE_H
