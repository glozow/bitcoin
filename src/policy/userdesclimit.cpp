// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/userdesclimit.h>

#include <policy/rbf.h>

bool SignalsUserDescendantLimit(const CTransaction& tx)
{
    for (const CTxIn &txin : tx.vin) {
        if (txin.nSequence & SEQUENCE_USER_DESCENDANT_LIMIT_FLAG) {
            return true;
        }
    }
    return false;
}

uint64_t CalculateUserDescendantLimit(const CTransaction& tx)
{
    const uint64_t vsize_multiplied = USER_DESCENDANT_LIMIT_MULTIPLIER * GetVirtualTransactionSize(tx);
    return std::max(vsize_multiplied, USER_DESCENDANT_LIMIT_FLOOR);
}

std::optional<std::string> CheckUserDescendantLimits(const CTxMemPool::setEntries& entries,
                                                     uint64_t additional_vsize)
{
    for (const auto& it : entries) {
        if (SignalsUserDescendantLimit(it->GetTx())) {
            const auto limit{CalculateUserDescendantLimit(it->GetTx())};
            if (it->GetSizeWithDescendants() + additional_vsize > limit) {
                return strprintf("tx %s exceeds user descendant limit %u",
                                 it->GetTx().GetHash().ToString(), limit);
            }
        }
    }
    return std::nullopt;
}

