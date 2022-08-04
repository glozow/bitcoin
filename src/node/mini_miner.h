// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINI_MINER_H
#define BITCOIN_NODE_MINI_MINER_H

#include <txmempool.h>

#include <memory>
#include <optional>
#include <stdint.h>

namespace node {

// Container for tracking updates to ancestor feerate as we include ancestors in the "block"
class MiniMinerMempoolEntry
{
    const CAmount fee_individual;
    const CTransaction tx;
    const int32_t vsize_individual;

// This class must be constructed while holding mempool.cs. After construction, the object's
// methods can be called without holding that lock.
public:
    CAmount fee_with_ancestors;
    int32_t vsize_with_ancestors;
    explicit MiniMinerMempoolEntry(CTxMemPool::txiter entry) :
        fee_individual{entry->GetModifiedFee()},
        tx{entry->GetTx()},
        vsize_individual(entry->GetTxSize()),
        fee_with_ancestors{entry->GetModFeesWithAncestors()},
        vsize_with_ancestors(entry->GetSizeWithAncestors())
    { }

    CAmount GetModifiedFee() const { return fee_individual; }
    CAmount GetModFeesWithAncestors() const { return fee_with_ancestors; }
    int32_t GetTxSize() const { return vsize_individual; }
    int32_t GetSizeWithAncestors() const { return vsize_with_ancestors; }
    const CTransaction& GetTx() const LIFETIMEBOUND { return tx; }
};

void UpdateForMinedAncestor(const MiniMinerMempoolEntry& ancestor, const MiniMinerMempoolEntry& descendant);

// Comparator needed for std::set<MockEntryMap::iterator>
struct IteratorComparator
{
    template<typename I>
    bool operator()(const I& a, const I& b) const
    {
        return &(*a) < &(*b);
    }
};

/** A minimal version of BlockAssembler. Allows us to run the mining algorithm on a subset of
 * mempool transactions, ignoring consensus rules, to calculate mining scores. */
class MiniMiner
{
    // Original outpoints requested
    std::vector<COutPoint> m_requested_outpoints;

    // Set once per lifetime, fill in during initialization.
    // txids of to-be-replaced transactions
    std::set<uint256> m_to_be_replaced;

    // If multiple argument outpoints correspond to the same transaction, cache them together in
    // a single entry indexed by txid. Then we can just work with txids since all outpoints from
    // the same tx will have the same bumpfee. Excludes non-mempool transactions.
    std::map<uint256, std::vector<COutPoint>> m_requested_outpoints_by_txid;

    // What we're trying to calculate.
    std::map<COutPoint, CAmount> m_bump_fees;

    // The constructed block template
    std::set<uint256> m_in_block;

    // Information on the current status of the block
    CAmount m_total_fees{0};
    int32_t m_total_vsize{0};

    /** Main data structure holding the entries, can be indexed by txid */
    std::map<uint256, MiniMinerMempoolEntry> m_entries_by_txid;
    using MockEntryMap = decltype(m_entries_by_txid);

    /** Vector of entries, can be sorted by ancestor feerate. */
    std::vector<MockEntryMap::iterator> m_entries;

    /** Map of txid to its descendants. Should be inclusive. */
    std::map<uint256, std::vector<MockEntryMap::iterator>> m_descendant_set_by_txid;

    /** Consider this ancestor package "mined" so remove all these entries from our data structures. */
    void DeleteAncestorPackage(const std::set<MockEntryMap::iterator, IteratorComparator>& ancestors);

    /** Build a block template until the target feerate is hit. */
    void BuildMockTemplate(const CFeeRate& target_feerate);

public:
    MiniMiner(const CTxMemPool& mempool, const std::vector<COutPoint>& outpoints);

    /** Construct a new block template and, for each outpoint corresponding to a transaction that
     * did not make it into the block, calculate the cost of bumping those transactions (and their
     * ancestors) to the minimum feerate. */
    std::map<COutPoint, CAmount> CalculateBumpFees(const CFeeRate& target_feerate);
};
} // namespace node

#endif // BITCOIN_NODE_MINI_MINER_H
