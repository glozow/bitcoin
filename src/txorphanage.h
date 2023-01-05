// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXORPHANAGE_H
#define BITCOIN_TXORPHANAGE_H

#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <util/time.h>

#include <map>
#include <set>

/** Expiration time for orphan transactions */
static constexpr auto ORPHAN_TX_EXPIRE_TIME{20min};
/** Minimum time between orphan transactions expire time checks */
static constexpr auto ORPHAN_TX_EXPIRE_INTERVAL{5min};

/** A class to track orphan transactions (failed on TX_MISSING_INPUTS)
 * Since we cannot distinguish orphans from bad transactions with
 * non-existent inputs, we heavily limit the number of orphans
 * we keep and the duration we keep them for.
 * Not thread-safe. Requires external synchronization.
 */
class TxOrphanage {
public:
    /** Add a new orphan transaction.
     * parent_txids should contain a (de-duplicated) list of txids of this transaction's missing parents.
      @returns true if the transaction was added as a new orphan. */
    bool AddTx(const CTransactionRef& tx, NodeId peer, const std::vector<Txid>& parent_txids);

    /** Add an additional announcer to an orphan if it exists. Otherwise, do nothing. */
    bool AddAnnouncer(const Wtxid& wtxid, NodeId peer);

    /** Get the size of an orphan if it exists, 0 otherwise. */
    unsigned int GetOrphanSize(const Wtxid& wtxid) const;

    /** Check if we already have an orphan transaction (by wtxid only) */
    bool HaveTx(const Wtxid& wtxid) const;

    /** Check if a {tx, peer} exists in the orphanage.*/
    bool HaveTxAndPeer(const Wtxid& wtxid, NodeId peer) const;

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
    std::vector<Wtxid> EraseForBlock(const CBlock& block);

    /** Limit the orphanage to the given maximum. Delete orphans whose expiry has been reached.
     * The maximum does not apply to protected transactions, i.e., LimitOrphans(100) ensures
     * that Size() <= 100. However, the total number of transactions including protected ones may
     * exceed 100. It is the caller's responsibility to ensure that not too many orphans are protected.
     */
    std::vector<Wtxid> LimitOrphans(unsigned int max_orphans, FastRandomContext& rng);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx);

    /** Does this peer have any work to do? */
    bool HaveTxToReconsider(NodeId peer);

    /** Get all children that spend from this tx and were received from nodeid. Sorted from most
     * recent to least recent. */
    std::vector<CTransactionRef> GetChildrenFromSamePeer(const CTransactionRef& parent, NodeId nodeid) const;

    /** Erase this peer as an announcer of this orphan. If there are no more announcers, delete the orphan. */
    void EraseOrphanOfPeer(const Wtxid& wtxid, NodeId peer);

    /** Return how many unprotected entries exist in the orphange. */
    size_t Size() const
    {
        return m_orphan_list.size();
    }

    /** Protect an orphan from eviction from the orphanage getting full. The orphan may still be
     * removed for other reasons - expiry, EraseTx, EraseForBlock, EraseForPeer will still remove
     * an orphan even if it is protected.
     */
    std::optional<unsigned int> ProtectOrphan(const Wtxid& wtxid, NodeId peer, unsigned int max_size);

    /** Remove protection by this peer for this orphan, if it exists. The orphan may still be
     * protected afterward if a different peer has also protected it. */
    void UndoProtectOrphan(const Wtxid& wtxid, NodeId peer);

    /** If this orphan exists and is protected, return the orphan size and a vector of its
     * protectors. Otherwise, returns std::nullopt. */
    std::optional<std::pair<unsigned int, std::vector<NodeId>>> GetProtectors(const Wtxid& wtxid) const;

    /** Get an orphan's parent_txids, or std::nullopt if the orphan is not present. */
    std::optional<std::vector<Txid>> GetParentTxids(const Wtxid& wtxid);

    /** Return total memory usage of the transactions stored. Does not include overhead of
     * m_orphans, m_peer_work_set, etc. */
    unsigned int TotalOrphanBytes() const
    {
        return m_total_orphan_bytes;
    }
    /** Return total amount of orphans stored by this peer, in bytes. */
    unsigned int BytesFromPeer(NodeId peer) const
    {
        auto peer_bytes_it = m_peer_bytes_used.find(peer);
        return peer_bytes_it == m_peer_bytes_used.end() ? 0 : peer_bytes_it->second;
    }

protected:
    struct OrphanTx {
        CTransactionRef tx;
        /** Peers added with AddTx or AddAnnouncer. */
        std::set<NodeId> announcers;
        /** Peers that have protected this orphan */
        std::set<NodeId> protectors;
        NodeSeconds nTimeExpire;
        /** If >= 0: position in m_orphan_list.
         *  If < 0: not in m_orphan_list because this orphan is protected. */
        int32_t list_pos;
        /** Txids of the missing parents to request. Determined by peerman. */
        std::vector<Txid> parent_txids;

        /** Whether this orphan is protected. */
        bool IsProtected() const {
            Assume(protectors.size() <= announcers.size());
            Assume((list_pos >= 0) == protectors.empty());
            return !protectors.empty();
        }
    };

    /** Map from wtxid to orphan transaction record. Limited by
     *  -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    std::map<Wtxid, OrphanTx> m_orphans;

    /** Which peer provided the orphans that need to be reconsidered */
    std::map<NodeId, std::set<Wtxid>> m_peer_work_set;

    using OrphanMap = decltype(m_orphans);

    struct IteratorComparator
    {
        template<typename I>
        bool operator()(const I& a, const I& b) const
        {
            return a->first < b->first;
        }
    };

    /** Index from the parents' COutPoint into the m_orphans. Used
     *  to remove orphan transactions from the m_orphans */
    std::map<COutPoint, std::set<OrphanMap::iterator, IteratorComparator>> m_outpoint_to_orphan_it;

    /** Orphan transactions in vector for quick random eviction */
    std::vector<OrphanMap::iterator> m_orphan_list;

    /** Timestamp for the next scheduled sweep of expired orphans */
    NodeSeconds m_next_sweep{0s};

    /** Total bytes of all transactions. */
    unsigned int m_total_orphan_bytes{0};

    /** Total bytes of all protected orphans. */
    size_t m_total_protected_orphan_bytes{0};

    /** Map from nodeid to the amount of orphans provided by this peer, in bytes.
     * The sum of all values in this map may exceed m_total_orphan_bytes, since multiple peers may
     * provide the same orphan and its bytes are included in all peers' entries. */
    std::map<NodeId, unsigned int> m_peer_bytes_used;

    /** Add bytes to this peer's entry in m_peer_bytes_used, adding a new entry if it doesn't
     * already exist. */
    void AddOrphanBytes(unsigned int size, NodeId peer);

    /** Subtract bytes from this peer's entry in m_peer_bytes_used, removing the peer's entry from
     * the map if its value becomes 0. */
    void SubtractOrphanBytes(unsigned int size, NodeId peer);
};

#endif // BITCOIN_TXORPHANAGE_H
