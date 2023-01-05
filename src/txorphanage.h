// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXORPHANAGE_H
#define BITCOIN_TXORPHANAGE_H

#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <map>
#include <set>

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
     *  Returns nullptr and sets more to false if there are no transactions
     *  to work on. Otherwise returns the transaction reference, removes
     *  the transaction from the work set, and populates its arguments with
     *  the originating peer, and whether there are more orphans for this peer
     *  to work on after this tx.
     */
    CTransactionRef GetTxToReconsider(NodeId peer, NodeId& originator, bool& more) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase an orphan by txid */
    int EraseTx(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void EraseForPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans included in or invalidated by a new block */
    void EraseForBlock(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Limit the orphanage to the given maximum. Delete orphans whose expiry has been reached.
     * The maximum does not apply to protected transactions, i.e., LimitOrphans(100) ensures
     * that the number of non-protected orphan entries does not exceed 100. Afterward, Size() may
     * return a number greater than 100.  It is the caller's responsibility to ensure that not too
     * many orphans are protected.
     */
    void LimitOrphans(unsigned int max_orphans) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Add any orphans that list a particular tx as a parent into a peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Return how many entries exist in the orphange */
    size_t Size() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_orphans.size();
    }
    /** Protect an orphan from eviction from the orphanage getting full. The orphan may still be
     * removed due to expiry. If the orphan is already protected (by any peer), nothing happens.
     * TODO: allow protection to expire or be removed? */
    void ProtectOrphan(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

protected:
    /** Guards orphan transactions */
    mutable Mutex m_mutex;

    struct OrphanTx {
        CTransactionRef tx;
        NodeId fromPeer;
        int64_t nTimeExpire;
        // Position in m_orphan_list, or std::nullopt if protected from eviction.
        std::optional<size_t> list_pos;
    };

    /** Map from txid to orphan transaction record. Limited by
     *  -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    std::map<uint256, OrphanTx> m_orphans GUARDED_BY(m_mutex);

    /** Which peer provided a parent tx of orphans that need to be reconsidered */
    std::map<NodeId, std::set<uint256>> m_peer_work_set GUARDED_BY(m_mutex);

    /** Number of orphans protected by this peer, used to check that a single peer does not
     * protect too many orphans from eviction (should be managed by the caller). */
    std::map<NodeId, size_t> m_peer_protected GUARDED_BY(m_mutex);

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

    /** Erase an orphan by txid */
    int _EraseTx(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
};

#endif // BITCOIN_TXORPHANAGE_H
