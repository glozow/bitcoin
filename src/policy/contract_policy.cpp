// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <policy/contract_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <policy/settings.h>
#include <tinyformat.h>
#include <util/moneystr.h>

#include <numeric>
#include <vector>

std::optional<std::pair<uint256, uint256>> CheckV3Inheritance(const Package& package)
{
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    std::unordered_map<uint256, uint256, SaltedTxidHasher> v3_txid_to_wtxid;
    for (const auto& tx : package) {
        if (tx->nVersion == 3) {
            v3_txid_to_wtxid.emplace(tx->GetHash(), tx->GetWitnessHash());
        } else {
            for (const auto& input : tx->vin) {
                if (auto it = v3_txid_to_wtxid.find(input.prevout.hash); it != v3_txid_to_wtxid.end()) {
                    return std::make_pair(it->second, tx->GetWitnessHash());
                }
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string> CheckV3Inheritance(const CTransactionRef& ptx,
                                              const CTxMemPool::setEntries& ancestors)
{
    const auto version{ptx->nVersion};
    if (version == 3) return std::nullopt;
    for (const auto& entry : ancestors) {
        if (entry->GetTx().nVersion == 3) {
            return strprintf("tx that spends from %s must be nVersion=3",
                             entry->GetTx().GetWitnessHash().ToString());
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

bool CanReplaceV3(const CTransaction& mempool_tx, const CTransaction& replacement_tx)
{
    return mempool_tx.nVersion == 3 && replacement_tx.nVersion == 3;
}

std::optional<std::string> CanReplaceV3(const CTxMemPool::setEntries& direct_conflicts,
                                        const std::vector<CTransactionRef>& replacement_transactions)
{
    for (const auto& entry : direct_conflicts) {
        if (entry->GetTx().nVersion != 3) {
            return strprintf("mempool tx %u is not V3", entry->GetTx().GetWitnessHash().ToString());
        }
    }
    for (const auto& tx : replacement_transactions) {
        if (tx->nVersion != 3) {
            return strprintf("replacement tx %u is not V3", tx->GetWitnessHash().ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> CheckEphemeralDust(const CTransactionRef& parent,
                                              const CTransactionRef& child,
                                              const CAmount& parent_fee)
{
    if (parent->nVersion != 3) {
        return strprintf("parent %s must be V3", parent->GetWitnessHash().ToString());
    }
    if (child->nVersion != 3) {
        return strprintf("child %s must be V3", child->GetWitnessHash().ToString());
    }
    if (parent_fee != 0) {
        return strprintf("parent fee is %s, must be 0", FormatMoney(parent_fee));
    }
    for (const auto& output : child->vout) {
        if (output.nValue < GetDustThreshold(output, ::dustRelayFee)) {
            return strprintf("child output %s is dust", output.ToString());
        }
    }
    std::optional<COutPoint> ephemeral_output;
    std::unordered_set<COutPoint, SaltedOutpointHasher> child_inputs;
    std::transform(child->vin.cbegin(), child->vin.cend(), std::inserter(child_inputs, child_inputs.end()),
                   [](const auto& input) { return input.prevout; });
    for (uint32_t i{0}; i < parent->vout.size(); ++i) {
        const auto& output = parent->vout[i];
        if (output.nValue < GetDustThreshold(output, ::dustRelayFee)) {
            if (ephemeral_output.has_value()) {
                return strprintf("tx %s has more than one dust output: %s and %s",
                                 parent->GetWitnessHash().ToString(), ephemeral_output->ToString(), output.ToString());
            } 
            if (output.nValue != 0) {
                return strprintf("ephemeral output %s amount is %d, must be exactly 0", output.ToString(), output.nValue);
            }
            const COutPoint prevout{parent->GetHash(), i};
            if (child_inputs.find(prevout) == child_inputs.end()) {
                return strprintf("ephemeral output %s is not spent immediately", output.ToString());
            }
            ephemeral_output = prevout;
        } 
    }
    return std::nullopt;
}
