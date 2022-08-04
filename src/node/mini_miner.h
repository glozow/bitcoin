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
struct MockMempoolEntry {
    CAmount fee_individual;
    CAmount fee_with_ancestors;
    int64_t vsize_individual;
    int64_t vsize_with_ancestors;
    const CTransaction& tx;

public:
    explicit MockMempoolEntry(CTxMemPool::txiter entry) :
        fee_individual{entry->GetModifiedFee()},
        fee_with_ancestors{entry->GetModFeesWithAncestors()},
        vsize_individual(entry->GetTxSize()),
        vsize_with_ancestors(entry->GetSizeWithAncestors()),
        tx{entry->GetTx()}
    { }

    const CTransaction& GetTx() const { return tx; }
    CAmount GetModifiedFee() const { return fee_individual; }
    CAmount GetModFeesWithAncestors() const { return fee_with_ancestors; }
    int64_t GetTxSize() const { return vsize_individual; }
    int64_t GetSizeWithAncestors() const { return vsize_with_ancestors; }
};

void UpdateForMinedAncestor(const MockMempoolEntry& ancestor, const MockMempoolEntry& descendant);

/** A minimal version of BlockAssembler. Allows us to run the mining algorithm on a subset of
 * mempool transactions, ignoring consensus rules, to calculate mining scores. */
class MiniMiner
{
    // Set once per lifetime, fill in during initialization.
    // txids of to-be-replaced transactions
    std::set<uint256> to_be_replaced;

    // After using the outpoints to figure out which transactions are to be replaced, we can just
    // work with txids (each outpoint from a single tx should have the same bumpfee independently).
    // Cache which outpoint are needed for each tx so we don't have to look up all the outputs.
    // Excludes to-be-replaced and unavailable transactions (set to 0).
    std::map<uint256, std::vector<COutPoint>> outpoints_needed_by_txid;

    // What we're trying to calculate.
    std::map<COutPoint, CAmount> bump_fees;

    // The constructed block template
    std::set<uint256> in_block;

    // Information on the current status of the block
    CAmount total_fees{0};
    int64_t total_vsize{0};

    /** Main data structure holding the entries, can be indexed by txid */
    std::map<uint256, MockMempoolEntry> entries_by_txid;
    using MockEntryMap = decltype(entries_by_txid);

    /** Vector of entries, can be sorted by ancestor feerate. */
    std::vector<MockEntryMap::iterator> entries;

    /** Map of txid to its descendants. Should be inclusive. */
    std::map<uint256, std::vector<MockEntryMap::iterator>> descendant_set_by_txid;

    /** Consider this ancestor package "mined" so remove all these entries from our data structures. */
    void DeleteAncestorPackage(const std::vector<MockEntryMap::iterator>& ancestors);

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
