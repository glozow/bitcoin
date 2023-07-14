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
    const CTransactionRef tx;
    const int64_t vsize_individual;

// This class must be constructed while holding mempool.cs. After construction, the object's
// methods can be called without holding that lock.
public:
    CAmount fee_with_ancestors;
    int64_t vsize_with_ancestors;
    explicit MiniMinerMempoolEntry(CTxMemPool::txiter entry) :
        fee_individual{entry->GetModifiedFee()},
        tx{entry->GetSharedTx()},
        vsize_individual(entry->GetTxSize()),
        fee_with_ancestors{entry->GetModFeesWithAncestors()},
        vsize_with_ancestors(entry->GetSizeWithAncestors())
    { }
    explicit MiniMinerMempoolEntry(CAmount fee_individual_in, CAmount fee_with_ancestors_in,
                                   int64_t vsize_individual_in, int64_t vsize_with_ancestors_in,
                                   const CTransactionRef& tx_in) :
        fee_individual{fee_individual_in},
        tx{tx_in},
        vsize_individual{vsize_individual_in},
        fee_with_ancestors{fee_with_ancestors_in},
        vsize_with_ancestors{vsize_with_ancestors_in}
    {}

    CAmount GetModifiedFee() const { return fee_individual; }
    CAmount GetModFeesWithAncestors() const { return fee_with_ancestors; }
    int64_t GetTxSize() const { return vsize_individual; }
    int64_t GetSizeWithAncestors() const { return vsize_with_ancestors; }
    const CTransaction& GetTx() const LIFETIMEBOUND { return *tx; }
};

// Comparator needed for std::set<MockEntryMap::iterator>
struct IteratorComparator
{
    template<typename I>
    bool operator()(const I& a, const I& b) const
    {
        return &(*a) < &(*b);
    }
};

/** A minimal version of BlockAssembler. Allows us to run the mining algorithm on a limited set of
 * transactions (e.g. subset of mempool or transactions that are not yet in mempool) instead of the entire
 * mempool, ignoring consensus rules. Callers may use this to calculate mining scores, bump fees, or
 * linearization order of a list of transactions.
 */
class MiniMiner
{
    // When true, a caller may use CalculateBumpFees(). Becomes false if we failed to retrieve
    // mempool entries (i.e. cluster size too large) or bump fees have already been calculated.
    bool m_ready_to_calculate{true};

    // Set once per lifetime, fill in during initialization.
    // txids of to-be-replaced transactions
    std::set<uint256> m_to_be_replaced;

    // If multiple argument outpoints correspond to the same transaction, cache them together in
    // a single entry indexed by txid. Then we can just work with txids since all outpoints from
    // the same tx will have the same bumpfee. Excludes non-mempool transactions.
    std::map<uint256, std::vector<COutPoint>> m_requested_outpoints_by_txid;

    // Txid to a sequence number representing the order in which this transaction was included.
    // Transactions included in an ancestor set together have the same sequence number.
    std::map<uint256, uint32_t> m_mining_sequence;
    // What we're trying to calculate. Outpoint to the fee needed to bring the transaction to the target feerate.
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

    /** Perform some checks. */
    void SanityCheck() const;

public:
    /** Returns true if CalculateBumpFees may be called, false if not. */
    bool IsReadyToCalculate() const { return m_ready_to_calculate; }

    /** Build a block template until the target feerate is hit. */
    void BuildMockTemplate(std::optional<CFeeRate> target_feerate);

    /** Returns set of txids in the block template if one has been constructed. */
    std::set<uint256> GetMockTemplateTxids() const { return m_in_block; }

    /** Constructor that takes a list of outpoints that may or may not belong to transactions in
     * mempool. */
    MiniMiner(const CTxMemPool& mempool, const std::vector<COutPoint>& outpoints);

    /** Constructor in which MiniMinerMempoolEntry entries have been constructed manually,
     * presumably because these transactions are not in the mempool (yet).
     * @param[in] descendant_caches A map from each transaction to the set of txids of this
     *                              transaction's descendant set, including itself. All of the
     *                              txids must correspond to a transaction in manual_entries.
     */
    MiniMiner(const std::vector<MiniMinerMempoolEntry>& manual_entries,
              const std::map<uint256, std::set<uint256>>& descendant_caches);

    /** Construct a new block template and, for each outpoint corresponding to a transaction that
     * did not make it into the block, calculate the cost of bumping those transactions (and their
     * ancestors) to the minimum feerate. Returns a map from outpoint to bump fee, or an empty map
     * if they cannot be calculated. */
    std::map<COutPoint, CAmount> CalculateBumpFees(const CFeeRate& target_feerate);

    /** Construct a new block template and, calculate the cost of bumping all transactions that did
     * not make it into the block to the target feerate. Returns the total bump fee, or std::nullopt
     * if it cannot be calculated. */
    std::optional<CAmount> CalculateTotalBumpFees(const CFeeRate& target_feerate);

    /** Construct a new block template with all of the transactions and calculate the order in which
     * they are selected. Returns the sequence number (lower = selected earlier) with which each
     * transaction was selected, indexed by txid, or an empty map if it cannot be calculated.
     */
    std::map<uint256, uint32_t> Linearize();

};
} // namespace node

#endif // BITCOIN_NODE_MINI_MINER_H
