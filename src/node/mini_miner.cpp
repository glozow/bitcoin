// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mini_miner.h>

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/check.h>
#include <util/moneystr.h>

#include <algorithm>
#include <utility>

namespace node {

MiniMiner::MiniMiner(const CTxMemPool& mempool, const std::vector<COutPoint>& outpoints)
{
    LOCK(mempool.cs);
    // Find which outpoints to calculate bump fees for.
    // Anything that's spent by the mempool is to-be-replaced
    // Anything otherwise unavailable just has a bump fee of 0
    for (const auto& outpoint : outpoints) {
        if (const auto ptx{mempool.GetConflictTx(outpoint)}) {
            // The conflicting transaction is to-be-replaced
            to_be_replaced.insert(ptx->GetHash());
        } else if (mempool.isSpent(outpoint)) {
            // This UTXO is either confirmed or not yet submitted to mempool.
            // In the former case, no bump fee is required.
            // In the latter case, we have no information, so just return 0.
            bump_fees.emplace(std::make_pair(outpoint, 0));
        } else {
            // This UTXO is unconfirmed and available to spend.
            auto it = outpoints_needed_by_txid.find(outpoint.hash);
            if (it != outpoints_needed_by_txid.end()) {
                it->second.push_back(outpoint);
            } else {
                std::vector<COutPoint> outpoints_of_tx({outpoint});
                outpoints_needed_by_txid.emplace(std::make_pair(outpoint.hash, outpoints_of_tx));
                // Instead of operating on the entire mempool, just run the mining algorithm on the
                // cluster of relevant transactions, which we'll store in mapModifiedTx.
            }
        }
    }
    // Calculate the cluster and construct the entry map.
    std::vector<uint256> txids_needed;
    std::transform(outpoints_needed_by_txid.cbegin(),
                   outpoints_needed_by_txid.cend(),
                   std::back_inserter(txids_needed),
                   [](const auto& pair) { return pair.first; });
    const auto& cluster = mempool.CalculateCluster(txids_needed);
    for (const auto& txiter : cluster) {
        if (to_be_replaced.find(txiter->GetTx().GetHash()) == to_be_replaced.end()) {
            entries_by_txid.emplace(std::make_pair(txiter->GetTx().GetHash(), MockMempoolEntry(txiter)));
        }
    }

    // Remove the to-be-replaced transactions and build the descendant_set_by_txid cache.
    for (const auto& txiter : cluster) {
        const auto& txid = txiter->GetTx().GetHash();
        // Cache descendants for future use. Unlike the real mempool, a descendant MockMempoolEntry
        // will not exist wihout its ancestor MockMempoolEntry, so these sets won't be invalidated.
        std::vector<MockEntryMap::iterator> cached_descendants;
        cached_descendants.emplace_back(entries_by_txid.find(txid));
        // If a tx is to-be-replaced, remove any of its descendants so they can't fee-bump anything.
        // this case should be rare as the wallet won't normally attempt to replace transactions
        // with descendants.
        const bool remove = to_be_replaced.find(txid) != to_be_replaced.end();
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(txiter, descendants);

        for (const auto& desc_txiter : descendants) {
            auto desc_it{entries_by_txid.find(desc_txiter->GetTx().GetHash())};
            if (desc_it != entries_by_txid.end()) {
                if (remove) {
                    entries_by_txid.erase(desc_it); 
                } else {
                    cached_descendants.push_back(desc_it); 
                }
            }
        }
        if (!remove) descendant_set_by_txid.emplace(std::make_pair(txid, cached_descendants));
    }
    // Release the mempool lock; we now have all the information we need for a subset of the entries
    // we care about. We will solely operate on the MockMempoolEntry map from now on.
    Assume(entries.size() == entries_by_txid.size());
    Assume(entries.size() == descendant_set_by_txid.size());
    Assume(in_block.empty());
}

// Compare by ancestor feerate, then iterator
struct AncestorFeerateComparator
{
    template<typename I>
    bool operator()(const I& a, const I& b) const {
        const CFeeRate a_feerate(a->second.GetModFeesWithAncestors(), a->second.GetSizeWithAncestors());
        const CFeeRate b_feerate(b->second.GetModFeesWithAncestors(), b->second.GetSizeWithAncestors());
        if (a_feerate != b_feerate) {
            return a_feerate < b_feerate;
        }
        return &(*a) < &(*b);
    }
};

void MiniMiner::DeleteAncestorPackage(const std::vector<MockEntryMap::iterator>& ancestors)
{
    for (const auto& anc : ancestors) {
        // TODO: Delete everything
        auto vec_it = std::find(entries.begin(), entries.end(), anc);
        Assume(vec_it != entries.end());
        entries.erase(vec_it);
        entries_by_txid.erase(anc);
    }
}

void MiniMiner::BuildMockTemplate(const CFeeRate& target_feerate)
{
    while (!entries_by_txid.empty()) {
        // Sort again, since transaction removal may change some entries' ancestor feerates.
        std::sort(entries.begin(), entries.end(), AncestorFeerateComparator());

        // Pick highest ancestor feerate entry.
        auto best_iter = entries.begin();
        Assume(best_iter != entries.end());
        // Stop here. Everything that didn't "make it into the block" has bumpfee.
        if (best_iter == entries.end() ||
            (*best_iter)->second.GetModFeesWithAncestors() < target_feerate.GetFee((*best_iter)->second.GetSizeWithAncestors())) {
            break;
        }

        std::vector<MockEntryMap::iterator> ancestors;
        // TODO: FIXME
        /* auto ancestors = GetAncestors(*best_iter); */
        for (const auto& anc : ancestors) {
            in_block.insert(anc->second.GetTx().GetHash());
            total_fees += anc->second.GetModifiedFee();
            total_vsize += anc->second.GetTxSize();
            auto it = descendant_set_by_txid.find(anc->second.GetTx().GetHash());
            Assume(it != descendant_set_by_txid.end());
            for (const auto& descendant : it->second) {
                descendant->second.vsize_with_ancestors -= anc->second.GetTxSize();
                descendant->second.fee_with_ancestors -= anc->second.GetModifiedFee();
            }
        }
        DeleteAncestorPackage(ancestors);
    }
}

std::map<COutPoint, CAmount> MiniMiner::CalculateBumpFees(const CFeeRate& target_feerate)
{
    // Build a block template until the target feerate is hit.
    BuildMockTemplate(target_feerate);
    Assume(in_block.empty() || CFeeRate(total_fees, total_vsize) >= target_feerate);

    // Each transaction that "made it into the block" has a bumpfee of 0, i.e. they are part of an
    // ancestor package that exceeds the target feerate and don't need to be bumped.
    for (const auto& txid : in_block) {
        // Not all of the block transactions were necessarily requested.
        auto it = outpoints_needed_by_txid.find(txid);
        if (it != outpoints_needed_by_txid.end()) {
            for (const auto& outpoint : it->second) {
                bump_fees.emplace(std::make_pair(outpoint, 0));
            }
            outpoints_needed_by_txid.erase(it);
        }
    }
    // For each transaction that remains, the bumpfee is the cost to raise it and its ancestors
    // to the target feerate, target_feerate * ancestor_size - ancestor_fees
    for (const auto& [txid, outpoints] : outpoints_needed_by_txid) {
        auto it = entries_by_txid.find(txid);
        Assume(it != entries_by_txid.end());
        if (it != entries_by_txid.end()) {
            const CAmount bump_fee{target_feerate.GetFee(it->second.GetSizeWithAncestors())
                                   - it->second.GetModFeesWithAncestors()};
            for (const auto& outpoint : outpoints) {
                bump_fees.emplace(std::make_pair(outpoint, bump_fee));
            }
        }
    }
    return bump_fees;
}
} // namespace node
