// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <policy/ancestor_packages.h>

#include <node/mini_miner.h>
#include <util/check.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <numeric>


/**Comparator for sorting m_txns which contains reference wrappers.*/
struct CompareEntry {
    template<typename T>
    bool operator()(const std::reference_wrapper<T> a, const std::reference_wrapper<T> b) const
    {
        return a.get() < b.get();
    }
};
// Calculates curr_tx's in-package ancestor set. If the tx spends another tx in the package, calls
// visit() for that transaction first, since any transaction's ancestor set includes its parents'
// ancestor sets. Transaction dependency cycles are not possible without breaking sha256 and
// duplicate transactions were checked in the AncestorPackage() ctor, so this won't recurse infinitely.
// After this function returns, entry is guaranteed to contain a non-empty ancestor_subset.
void AncestorPackage::visit(const CTransactionRef& curr_tx)
{
    const uint256& curr_txid = curr_tx->GetHash();
    auto& entry = m_txid_to_entry.at(curr_txid);
    if (!entry.ancestor_subset.empty()) return;
    std::set<uint256> my_ancestors;
    my_ancestors.insert(curr_txid);
    for (const auto& input : curr_tx->vin) {
        const auto& parent_txid = input.prevout.hash;
        if (m_txid_to_entry.count(parent_txid) == 0) continue;
        auto parent_tx = m_txid_to_entry.at(parent_txid).tx;
        if (m_txid_to_entry.at(parent_txid).ancestor_subset.empty()) {
            visit(parent_tx);
        }
        auto parent_ancestor_set = m_txid_to_entry.at(parent_txid).ancestor_subset;
        Assume(!parent_ancestor_set.empty());
        my_ancestors.insert(parent_ancestor_set.cbegin(), parent_ancestor_set.cend());
    }
    entry.ancestor_subset = std::move(my_ancestors);
}

AncestorPackage::AncestorPackage(const Package& txns_in)
{
    // Duplicate transactions are not allowed, as they will result in infinite visit() recursion.
    Assume(IsConsistent(txns_in));
    if (txns_in.empty() || !IsConsistent(txns_in)) return;
    // Populate m_txid_to_entry for quick lookup
    for (const auto& tx : txns_in) {
        m_txid_to_entry.emplace(tx->GetHash(), PackageEntry{tx});
        m_txns.push_back(std::ref(m_txid_to_entry.at(tx->GetHash())));
    }
    // DFS-based algorithm to sort transactions by ancestor count and populate ancestor_subset.
    // Best case runtime is if the package is already sorted and no recursive calls happen.
    // An empty PackageEntry::ancestor_subset is equivalent to not yet being processed.
    size_t i{0};
    while (i < txns_in.size()) {
        const auto& tx = txns_in[i];
        if (m_txid_to_entry.at(tx->GetHash()).ancestor_subset.empty()) visit(tx);
        Assume(!m_txid_to_entry.at(tx->GetHash()).ancestor_subset.empty());
        ++i;
    }
    // Sort by the number of in-package ancestors.
    std::sort(m_txns.begin(), m_txns.end(), CompareEntry());
    Assume(m_txns.size() == txns_in.size() && IsSorted(Txns()));
    // This package is ancestor package-shaped if every transaction is an ancestor of the last tx.
    m_ancestor_package_shaped = m_txns.back().get().ancestor_subset.size() == m_txns.size();
    // Now populate the descendant caches
    for (const auto& [txid, entry] : m_txid_to_entry) {
        for (const auto& anc_txid : entry.ancestor_subset) {
            m_txid_to_entry.at(anc_txid).descendant_subset.insert(txid);
        }
    }
}

Package AncestorPackage::Txns() const
{
    Package result;
    std::transform(m_txns.cbegin(), m_txns.cend(), std::back_inserter(result),
                   [](const auto refentry){ return refentry.get().tx; });
    return result;
}

Package AncestorPackage::FilteredTxns() const
{
    Package result;
    for (const auto entryref : m_txns) {
        if (!entryref.get().skip && !entryref.get().dangles) result.push_back(entryref.get().tx);
    }
    return result;
}

std::optional<std::vector<CTransactionRef>> AncestorPackage::GetAncestorSet(const CTransactionRef& tx) const
{
    if (m_txid_to_entry.count(tx->GetHash()) == 0) return std::nullopt;
    const auto& entry = m_txid_to_entry.find(tx->GetHash())->second;
    if (entry.dangles) return std::nullopt;
    std::vector<CTransactionRef> result;
    result.reserve(entry.ancestor_subset.size());
    for (const auto entryref : m_txns) {
        if (!entryref.get().skip && entry.ancestor_subset.count(entryref.get().tx->GetHash()) > 0) {
            Assume(!entryref.get().dangles);
            result.push_back(entryref.get().tx);
        }
    }
    return result;
}

std::optional<std::pair<CAmount, int64_t>> AncestorPackage::GetFeeAndVsize(const CTransactionRef& tx) const
{
    if (m_txid_to_entry.count(tx->GetHash()) == 0) return std::nullopt;
    const auto& entry = m_txid_to_entry.find(tx->GetHash())->second;
    if (!entry.fee.has_value() || !entry.vsize.has_value()) return std::nullopt;
    return std::make_pair(entry.fee.value(), entry.vsize.value());
}

std::optional<std::pair<CAmount, int64_t>> AncestorPackage::GetAncestorFeeAndVsize(const CTransactionRef& tx) const
{
    if (m_txid_to_entry.count(tx->GetHash()) == 0) return std::nullopt;
    const auto& entry = m_txid_to_entry.find(tx->GetHash())->second;
    if (entry.dangles || !entry.fee.has_value() || !entry.vsize.has_value()) return std::nullopt;
    CAmount total_fee{0};
    int64_t total_vsize{0};
    for (const auto& txid : entry.ancestor_subset) {
        const auto& anc_entry = m_txid_to_entry.at(txid);
        Assume(!anc_entry.dangles);
        if (!anc_entry.skip && !anc_entry.dangles) {
            // If tx has fee and vsize, then any of its non-skipped ancestors should too.
            if (anc_entry.fee.has_value() && anc_entry.vsize.has_value()) {
                total_fee += anc_entry.fee.value();
                total_vsize += anc_entry.vsize.value();
            } else {
                // If any fee or vsize information is missing, we can't return an accurate result.
                return std::nullopt;
            }
        }
    }
    return std::make_pair(total_fee, total_vsize);
}

void AncestorPackage::Skip(const CTransactionRef& transaction)
{
    if (m_txid_to_entry.count(transaction->GetHash()) == 0) return;
    m_txid_to_entry.at(transaction->GetHash()).skip = true;
}
void AncestorPackage::SkipWithDescendants(const CTransactionRef& transaction)
{
    if (m_txid_to_entry.count(transaction->GetHash()) == 0) return;
    m_txid_to_entry.at(transaction->GetHash()).skip = true;
    for (const auto& descendant_txid : m_txid_to_entry.at(transaction->GetHash()).descendant_subset) {
        m_txid_to_entry.at(descendant_txid).skip = true;
        m_txid_to_entry.at(descendant_txid).dangles = true;
    }
}

void AncestorPackage::AddFeeAndVsize(const uint256& txid, CAmount fee, int64_t vsize)
{
    if (m_txid_to_entry.count(txid) == 0) return;
    m_txid_to_entry.at(txid).fee = fee;
    m_txid_to_entry.at(txid).vsize = vsize;
}

bool AncestorPackage::LinearizeWithFees()
{
    if (!m_ancestor_package_shaped) return false;
    // All fee and vsize information for non-skipped transactions must be available, otherwise linearization cannot be done.
    if (!std::all_of(m_txid_to_entry.cbegin(), m_txid_to_entry.cend(),
        [](const auto& entry) { return entry.second.skip || entry.second.dangles ||
                                 (entry.second.fee.has_value() && entry.second.vsize.has_value()); })) {
        return false;
    }
    // Clear any previously-calculated mining sequences for all transactions.
    for (auto& [_, entry] : m_txid_to_entry) entry.mining_sequence = std::nullopt;
    std::vector<node::MiniMinerMempoolEntry> miniminer_info;
    std::map<uint256, std::set<uint256>> descendant_caches;
    // For each non-skipped transaction, calculate their ancestor fee and vsize.
    for (const auto& [txid, entry] : m_txid_to_entry) {
        if (entry.skip) continue;
        // GetAncestorSet() is different from ancestor_subset because it filters out skipped transactions
        // and will return std::nullopt if this transaction should be skipped.
        const auto filtered_ancestor_subset = GetAncestorSet(entry.tx);
        if (filtered_ancestor_subset == std::nullopt) continue;
        CAmount ancestor_subset_fees = std::accumulate(filtered_ancestor_subset->cbegin(), filtered_ancestor_subset->cend(),
            CAmount{0}, [&](CAmount sum, const auto& anc) { return sum + *m_txid_to_entry.at(anc->GetHash()).fee; });
        int64_t ancestor_subset_vsize = std::accumulate(filtered_ancestor_subset->cbegin(), filtered_ancestor_subset->cend(),
            int64_t{0}, [&](int64_t sum, const auto& anc) { return sum + *m_txid_to_entry.at(anc->GetHash()).vsize; });
        miniminer_info.push_back(node::MiniMinerMempoolEntry{*entry.fee, ancestor_subset_fees, *entry.vsize, ancestor_subset_vsize, entry.tx});
        descendant_caches.emplace(txid, entry.descendant_subset);
    }

    // Use MiniMiner to calculate the order in which these transactions would be selected for mining.
    node::MiniMiner miniminer(miniminer_info, descendant_caches);
    if (!miniminer.IsReadyToCalculate()) return false;
    for (const auto& [txid, mining_sequence] : miniminer.Linearize()) {
        m_txid_to_entry.at(txid).mining_sequence = mining_sequence;
    }
    // Sort again, this time using mining score.
    std::sort(m_txns.begin(), m_txns.end(), CompareEntry());
    Assume(std::all_of(m_txid_to_entry.cbegin(), m_txid_to_entry.cend(), [](const auto& entry) {
        bool should_have_sequence = !entry.second.skip && !entry.second.dangles;
        return entry.second.mining_sequence.has_value() == should_have_sequence;
    }));
    return true;
}
