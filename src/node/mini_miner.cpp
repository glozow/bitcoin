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
#include <numeric>
#include <utility>

namespace node {

MiniMiner::MiniMiner(const CTxMemPool& mempool, const std::vector<COutPoint>& outpoints)
{
    LOCK(mempool.cs);
    m_requested_outpoints = outpoints;
    // Find which outpoints to calculate bump fees for.
    // Anything that's spent by the mempool is to-be-replaced
    // Anything otherwise unavailable just has a bump fee of 0
    for (const auto& outpoint : outpoints) {
        if (const auto ptx{mempool.GetConflictTx(outpoint)}) {
            // This outpoint is already being spent by another transaction in the mempool.
            // We assume that the caller wants to replace this transaction (and its descendants).
            // This means we still need to calculate its ancestors bump fees, but after removing the
            // to-be-replaced entries. Note that this is only calculating bump fees and RBF fee
            // rules are not factored in here; those should be handled separately.
            m_to_be_replaced.insert(ptx->GetHash());
        }

        if (!mempool.exists(GenTxid::Txid(outpoint.hash))) {
            // This UTXO is either confirmed or not yet submitted to mempool.
            // In the former case, no bump fee is required.
            // In the latter case, we have no information, so just return 0.
            m_bump_fees.emplace(outpoint, 0);
        } else {
            // This UTXO is unconfirmed, in the mempool, and available to spend.
            auto it = m_requested_outpoints_by_txid.find(outpoint.hash);
            if (it != m_requested_outpoints_by_txid.end()) {
                it->second.push_back(outpoint);
            } else {
                std::vector<COutPoint> outpoints_of_tx({outpoint});
                m_requested_outpoints_by_txid.emplace(outpoint.hash, outpoints_of_tx);
            }
        }
    }

    // No unconfirmed UTXOs, so nothing mempool-related needs to be calculated.
    if (m_requested_outpoints_by_txid.empty()) return;

    // Calculate the cluster and construct the entry map.
    std::vector<uint256> txids_needed;
    for (const auto& [txid, outpoints]: m_requested_outpoints_by_txid) {
        txids_needed.push_back(txid);
    }
    const auto& cluster = mempool.CalculateCluster(txids_needed);
    // An empty cluster means that at least one of the transactions is missing from the mempool.
    // Since we only included things that exist in mempool, have not released the mutex, and would
    // have quit early if requested_outpoints_by_txid was empty, this should not be possible.
    Assume(!cluster.empty());
    for (const auto& txiter : cluster) {
        if (m_to_be_replaced.find(txiter->GetTx().GetHash()) == m_to_be_replaced.end()) {
            // Exclude entries that are going to be replaced.
            auto [mapiter, success] = m_entries_by_txid.emplace(txiter->GetTx().GetHash(), MiniMinerMempoolEntry(txiter));
            Assume(success);
            m_entries.push_back(mapiter);
        } else {
            auto outpoints_it = m_requested_outpoints_by_txid.find(txiter->GetTx().GetHash());
            if (outpoints_it != m_requested_outpoints_by_txid.end()) {
                // This UTXO is the output of a to-be-replaced transaction. Bump fee is 0; spending
                // this UTXO is impossible as it will no longer exist after the replacement.
                for (const auto& outpoint : outpoints_it->second) {
                    m_bump_fees.emplace(outpoint, 0);
                }
                m_requested_outpoints_by_txid.erase(outpoints_it);
            }
        }
    }

    // Remove the to-be-replaced transactions and build the m_descendant_set_by_txid cache.
    for (const auto& txiter : cluster) {
        const auto& txid = txiter->GetTx().GetHash();
        // Cache descendants for future use. Unlike the real mempool, a descendant MiniMinerMempoolEntry
        // will not exist without its ancestor MiniMinerMempoolEntry, so these sets won't be invalidated.
        std::vector<MockEntryMap::iterator> cached_descendants;
        cached_descendants.emplace_back(m_entries_by_txid.find(txid));
        // If a tx is to-be-replaced, remove any of its descendants so they can't fee-bump anything.
        // this case should be rare as the wallet won't normally attempt to replace transactions
        // with descendants.
        const bool remove = m_to_be_replaced.find(txid) != m_to_be_replaced.end();
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(txiter, descendants);

        for (const auto& desc_txiter : descendants) {
            auto desc_it{m_entries_by_txid.find(desc_txiter->GetTx().GetHash())};
            // It's possible the descendant has already been excluded, see cluster loop above.
            if (desc_it != m_entries_by_txid.end()) {
                if (remove) {
                    m_entries_by_txid.erase(desc_it);
                } else {
                    cached_descendants.push_back(desc_it);
                }
            }
        }
        if (!remove) m_descendant_set_by_txid.emplace(txid, std::move(cached_descendants));
    }
    // Release the mempool lock; we now have all the information we need for a subset of the entries
    // we care about. We will solely operate on the MiniMinerMempoolEntry map from now on.
    Assume(m_entries.size() == m_entries_by_txid.size());
    Assume(m_entries.size() == m_descendant_set_by_txid.size());
    Assume(m_in_block.empty());
    Assume(m_requested_outpoints_by_txid.size() <= outpoints.size());
}

// Compare by ancestor feerate, then iterator
struct AncestorFeerateComparator
{
    template<typename I>
    bool operator()(const I& a, const I& b) const {
        const CFeeRate a_feerate(a->second.GetModFeesWithAncestors(), a->second.GetSizeWithAncestors());
        const CFeeRate b_feerate(b->second.GetModFeesWithAncestors(), b->second.GetSizeWithAncestors());
        if (a_feerate != b_feerate) {
            return a_feerate > b_feerate;
        }
        // Make sorting order stable without introducing a gameable tie-breaker
        return &(*a) > &(*b);
    }
};

void MiniMiner::DeleteAncestorPackage(const std::set<MockEntryMap::iterator, IteratorComparator>& ancestors)
{
    for (const auto& anc : ancestors) {
        auto vec_it = std::find(m_entries.begin(), m_entries.end(), anc);
        Assume(vec_it != m_entries.end());
        m_entries.erase(vec_it);
        m_entries_by_txid.erase(anc);
    }
}

void MiniMiner::BuildMockTemplate(const CFeeRate& target_feerate)
{
    while (!m_entries_by_txid.empty()) {
        // Sort again, since transaction removal may change some m_entries' ancestor feerates.
        std::sort(m_entries.begin(), m_entries.end(), AncestorFeerateComparator());

        // Pick highest ancestor feerate entry.
        auto best_iter = m_entries.begin();
        Assume(best_iter != m_entries.end());
        const auto ancestor_package_size = (*best_iter)->second.GetSizeWithAncestors();
        const auto ancestor_package_fee = (*best_iter)->second.GetModFeesWithAncestors();
        // Stop here. Everything that didn't "make it into the block" has bumpfee.
        if (ancestor_package_fee < target_feerate.GetFee(ancestor_package_size)) {
            break;
        }

        // Calculate ancestors on the fly. This lookup should be fairly cheap, and ancestor sets
        // change at every iteration, so this is more efficient than maintaining a cache.
        std::set<MockEntryMap::iterator, IteratorComparator> ancestors;
        std::set<MockEntryMap::iterator, IteratorComparator> to_process;
        ancestors.insert(*best_iter);
        to_process.insert(*best_iter);
        while (!to_process.empty()) {
            auto iter = to_process.begin();
            Assume(iter != to_process.end());
            const CTransaction& tx = (*iter)->second.GetTx();
            for (const auto& input : tx.vin) {
                if (auto parent_it{m_entries_by_txid.find(input.prevout.hash)}; parent_it != m_entries_by_txid.end()) {
                    if (!ancestors.count(parent_it)) { // Skip if it has been processed before
                        to_process.insert(parent_it);
                        ancestors.insert(parent_it);
                    }
                }
            }
            to_process.erase(iter);
        }
        Assume(ancestor_package_size == std::accumulate(ancestors.cbegin(), ancestors.cend(), 0,
            [](int64_t sum, const auto it) {return sum + it->second.GetTxSize();}));
        Assume(ancestor_package_fee == std::accumulate(ancestors.cbegin(), ancestors.cend(), 0,
            [](CAmount sum, const auto it) {return sum + it->second.GetModifiedFee();}));

        // "Mine" all transactions in this ancestor set.
        for (const auto& anc : ancestors) {
            m_in_block.insert(anc->second.GetTx().GetHash());
            m_total_fees += anc->second.GetModifiedFee();
            m_total_vsize += anc->second.GetTxSize();
            auto it = m_descendant_set_by_txid.find(anc->second.GetTx().GetHash());
            // Each entry’s descendant set includes itself
            Assume(it != m_descendant_set_by_txid.end());
            for (const auto& descendant : it->second) {
                descendant->second.vsize_with_ancestors -= anc->second.GetTxSize();
                descendant->second.fee_with_ancestors -= anc->second.GetModifiedFee();
            }
        }
        DeleteAncestorPackage(ancestors);
        Assume(m_entries.size() == m_entries_by_txid.size());
    }
}

std::map<COutPoint, CAmount> MiniMiner::CalculateBumpFees(const CFeeRate& target_feerate)
{
    // Build a block template until the target feerate is hit.
    BuildMockTemplate(target_feerate);
    Assume(m_in_block.empty() || CFeeRate(m_total_fees, m_total_vsize) >= target_feerate);

    // Each transaction that "made it into the block" has a bumpfee of 0, i.e. they are part of an
    // ancestor package with at least the target feerate and don't need to be bumped.
    for (const auto& txid : m_in_block) {
        // Not all of the block transactions were necessarily requested.
        auto it = m_requested_outpoints_by_txid.find(txid);
        if (it != m_requested_outpoints_by_txid.end()) {
            for (const auto& outpoint : it->second) {
                m_bump_fees.emplace(outpoint, 0);
            }
            m_requested_outpoints_by_txid.erase(it);
        }
    }
    // For each transaction that remains, the bumpfee is the cost to raise it and its ancestors
    // to the target feerate, target_feerate * ancestor_size - ancestor_fees
    for (const auto& [txid, outpoints] : m_requested_outpoints_by_txid) {
        auto it = m_entries_by_txid.find(txid);
        Assume(it != m_entries_by_txid.end());
        if (it != m_entries_by_txid.end()) {
            Assume(target_feerate.GetFee(it->second.GetSizeWithAncestors()) > it->second.GetModFeesWithAncestors());
            const CAmount bump_fee{target_feerate.GetFee(it->second.GetSizeWithAncestors())
                                   - it->second.GetModFeesWithAncestors()};
            Assume(bump_fee >= 0);
            for (const auto& outpoint : outpoints) {
                m_bump_fees.emplace(outpoint, bump_fee);
            }
        }
    }
    return m_bump_fees;
}
} // namespace node
