// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/contract_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <tinyformat.h>

#include <numeric>
#include <vector>

std::optional<std::string> CheckV3Inheritance(const CTransactionRef& ptx,
                                              const CTxMemPool::setEntries& ancestors)
{
    const auto version{ptx->nVersion};
    if (version == 3) return std::nullopt;
    for (const auto& entry : ancestors) {
        if (entry->GetTx().nVersion == 3) {
            return strprintf("tx is nVersion=%u. tx that spends from %s must be nVersion=3",
                             version, entry->GetTx().GetHash().ToString()); 
        } 
    }
    return std::nullopt;
}

CTxMemPool::setEntries GetV3Ancestors(const CTxMemPool::setEntries& ancestors)
{
    CTxMemPool::setEntries v3_ancestors;
    // todo use std filter
    for (const auto& entry : ancestors) {
        if (entry->GetTx().nVersion == 3) {
            v3_ancestors.insert(entry);
        } 
    }
    return v3_ancestors;
}

std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& ancestors)
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

    CTxMemPool::setEntries v3_ancestors{GetV3Ancestors(ancestors)};

    if (v3_ancestors.size() > 0) {
        // this tx is a child of a V3 tx. To avoid RBF pinning, it can't be too large.
        if (tx_vsize > V3_CHILD_MAX_SIZE) {
            return strprintf("tx is too big: %u virtual bytes", tx_vsize);
        }
    }
    for (const auto& entry : v3_ancestors) {
        if (entry->GetCountWithDescendants() + 1 > V3_DESCENDANT_LIMIT) {
            return strprintf("tx %u would exceed descendant count limit", entry->GetTx().GetHash().ToString());
        }
    }
    return std::nullopt;
}
