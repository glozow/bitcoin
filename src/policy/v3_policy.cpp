// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/v3_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <tinyformat.h>

#include <numeric>
#include <vector>

std::optional<std::tuple<uint256, uint256, bool>> CheckV3Inheritance(const Package& package)
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
    std::unordered_map<uint256, uint256, SaltedTxidHasher> v3_txid_to_wtxid;
    std::unordered_map<uint256, uint256, SaltedTxidHasher> non_v3_txid_to_wtxid;
    for (const auto& tx : package) {
        if (tx->nVersion == 3) {
            v3_txid_to_wtxid.emplace(tx->GetHash(), tx->GetWitnessHash());
        } else {
            non_v3_txid_to_wtxid.emplace(tx->GetHash(), tx->GetWitnessHash());
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

std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& ancestors,
                                        const std::set<uint256>& direct_conflicts)
{
    // These rules only apply to transactions with nVersion=3.
    if (ptx->nVersion != 3) return std::nullopt;

    const auto tx_vsize{GetVirtualTransactionSize(*ptx)};
    if (ancestors.size() + 1 > V3_ANCESTOR_LIMIT) {
        return strprintf("tx would have too many ancestors");
    }
    const auto ancestor_vsize {std::accumulate(ancestors.cbegin(), ancestors.cend(), 0,
        [](int64_t sum, CTxMemPool::txiter it) { return sum + it->GetTxSize(); })};
    if (ancestor_vsize + tx_vsize > V3_ANCESTOR_SIZE_LIMIT_KVB * 1000) {
        return strprintf("total vsize of tx with ancestors would be too big: %u virtual bytes", tx_vsize + ancestor_vsize);
    }

    // Any two unconfirmed transactions with a dependency relationship must either both be V3 or both non-V3.
    if (auto err_string{CheckV3Inheritance(ptx, ancestors)}) {
        return err_string;
    }

    // This tx is a child of a V3 tx. To avoid RBF pinning, it can't be too large. Note that this
    // code is optimized for only allowing 1 child (enforced below). If that rule is loosened, we
    // must check the *accumulated* size of each of the ancestor's descendants.
    if (ancestors.size() > 0 && tx_vsize > V3_CHILD_MAX_SIZE) {
        return strprintf("v3 child tx is too big: %u virtual bytes", tx_vsize);
    }

    // If there are any ancestors, this is the only child allowed. None of the ancestors (which are
    // all V3, otherwise CheckV3Inheritance wouldn't have passed) can have any other descendants.
    for (const auto& entry : ancestors) {
        const auto& children = entry->GetMemPoolChildrenConst();
        // Don't double-count a transaction that is going to be replaced. This logic assumes that
        // any descendant of the V3 transaction is a direct child, which makes sense because a V3
        // transaction can only have 1 descendant.
        const bool child_will_be_replaced = !children.empty() &&
            std::any_of(children.cbegin(), children.cend(),
                [&direct_conflicts](const CTxMemPoolEntry& child){return direct_conflicts.count(child.GetTx().GetHash()) > 0;});
        if (entry->GetCountWithDescendants() + 1 > V3_DESCENDANT_LIMIT && !child_will_be_replaced) {
            return strprintf("tx %u would exceed descendant count limit", entry->GetTx().GetHash().ToString());
        }
    }
    return std::nullopt;
}
