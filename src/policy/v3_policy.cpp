// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/v3_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/check.h>

#include <algorithm>
#include <numeric>
#include <vector>

std::optional<std::tuple<Wtxid, Wtxid, bool>> CheckV3Inheritance(const Package& package)
{
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    // If all transactions are V3, we can stop here.
    if (std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx->nVersion == 3;})) {
        return std::nullopt;
    }
    // If all transactions are non-V3, we can stop here.
    if (std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx->nVersion != 3;})) {
        return std::nullopt;
    }
    // Look for a V3 transaction spending a non-V3 or vice versa.
    std::unordered_map<Txid, Wtxid, SaltedTxidHasher> v3_txid_to_wtxid;
    std::unordered_map<Txid, Wtxid, SaltedTxidHasher> non_v3_txid_to_wtxid;
    for (const auto& tx : package) {
        if (tx->nVersion == 3) {
            // If duplicate txids exist, this function will still detect violations, but it
            // will return the earlier transaction's wtxid.
            Assume(v3_txid_to_wtxid.emplace(tx->GetHash(), tx->GetWitnessHash()).second);
        } else {
            Assume(non_v3_txid_to_wtxid.emplace(tx->GetHash(), tx->GetWitnessHash()).second);
        }
    }
    for (const auto& tx : package) {
        if (tx->nVersion == 3) {
            for (const auto& input : tx->vin) {
                if (auto it = non_v3_txid_to_wtxid.find(input.prevout.hash); it != non_v3_txid_to_wtxid.end()) {
                    return std::make_tuple(it->second, tx->GetWitnessHash(), true);
                }
            }
        } else {
            for (const auto& input : tx->vin) {
                if (auto it = v3_txid_to_wtxid.find(input.prevout.hash); it != v3_txid_to_wtxid.end()) {
                    return std::make_tuple(it->second, tx->GetWitnessHash(), false);
                }
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string> CheckV3Inheritance(const CTransactionRef& ptx,
                                              const CTxMemPool::setEntries& ancestors)
{
    for (const auto& entry : ancestors) {
        if (ptx->nVersion != 3 && entry->GetTx().nVersion == 3) {
            return strprintf("tx that spends from %s must be nVersion=3",
                             entry->GetTx().GetWitnessHash().ToString());
        } else if (ptx->nVersion == 3 && entry->GetTx().nVersion != 3) {
            return strprintf("v3 tx cannot spend from %s which is not nVersion=3",
                             entry->GetTx().GetWitnessHash().ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> PackageV3SanityChecks(const Package& package)
{
    // Check inheritance rules within package.
    if (const auto inheritance_error{CheckV3Inheritance(package)}) {
        const auto [parent_wtxid, child_wtxid, child_v3] = inheritance_error.value();
        if (child_v3) {
            return strprintf("v3 tx %s cannot spend from non-v3 %s", child_wtxid.ToString(), parent_wtxid.ToString());
        } else {
            return strprintf("non-v3 tx %s cannot spend from v3 %s", child_wtxid.ToString(), parent_wtxid.ToString());
        }
    }

    // Sanity check that package itself obeys ancestor/descendant limits. This is not a complete
    // check, but we can exit early if it fails.
    if (!package.empty() && package.size() > V3_CHILD_MAX_VSIZE && package.back()->nVersion == 3) {
        const auto& child_wtxid = package.back()->GetWitnessHash();
        return strprintf("tx %s would have too many ancestors", child_wtxid.ToString());
    }

    return std::nullopt;
}

std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& ancestors,
                                        const std::set<Txid>& direct_conflicts,
                                        int64_t vsize)
{
    // This function is specialized for these limits, and must be reimplemented if they ever change.
    static_assert(V3_ANCESTOR_LIMIT == 2);
    static_assert(V3_DESCENDANT_LIMIT == 2);

    // These rules only apply to transactions with nVersion=3.
    if (ptx->nVersion != 3) return std::nullopt;

    if (ancestors.size() + 1 > V3_ANCESTOR_LIMIT) {
        return strprintf("tx %s would have too many ancestors", ptx->GetWitnessHash().ToString());
    }
    if (ancestors.empty()) {
        return std::nullopt;
    }
    // If this transaction spends V3 parents, it cannot be too large.
    if (vsize > V3_CHILD_MAX_VSIZE) {
        return strprintf("v3 child tx is too big: %u > %u virtual bytes", vsize, V3_CHILD_MAX_VSIZE);
    }
    // Any ancestor of a V3 transaction must also be V3.
    const auto& parent_entry = *ancestors.begin();
    if (parent_entry->GetTx().nVersion != 3) {
        return strprintf("v3 tx cannot spend from %s which is not nVersion=3",
                         parent_entry->GetTx().GetWitnessHash().ToString());
    }
    // If there are any ancestors, this is the only child allowed. The parent cannot have any
    // other descendants.
    const auto& children = parent_entry->GetMemPoolChildrenConst();
    // Don't double-count a transaction that is going to be replaced. This logic assumes that
    // any descendant of the V3 transaction is a direct child, which makes sense because a V3
    // transaction can only have 1 descendant.
    const bool child_will_be_replaced = !children.empty() &&
        std::any_of(children.cbegin(), children.cend(),
            [&direct_conflicts](const CTxMemPoolEntry& child){return direct_conflicts.count(child.GetTx().GetHash()) > 0;});
    if (parent_entry->GetCountWithDescendants() + 1 > V3_DESCENDANT_LIMIT && !child_will_be_replaced) {
        return strprintf("tx %u would exceed descendant count limit", parent_entry->GetTx().GetHash().ToString());
    }
    return std::nullopt;
}
