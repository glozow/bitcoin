// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_USERDESCLIMIT_H
#define BITCOIN_POLICY_USERDESCLIMIT_H

#include <primitives/transaction.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/rbf.h>

#include <optional>
#include <string>

/** Whether or not we enforce BIPX user-elected descendant limits by default. */
static constexpr bool DEFAULT_ENFORCE_USER_DESCENDANT_LIMIT{false};
/** Default floor for user-elected descendant limit, in virtual bytes. */
static constexpr uint64_t USER_DESCENDANT_LIMIT_FLOOR{5000};
static constexpr uint64_t USER_DESCENDANT_LIMIT_MULTIPLIER{2};
static constexpr uint32_t SEQUENCE_USER_DESCENDANT_LIMIT_FLAG{1U << 30};

/** Check whether this transaction signals user-elected descendant limits according to BIPX. */
bool SignalsUserDescendantLimit(const CTransaction& tx);

/** Calculate this transaction's user-elected descendant limits according to BIPX:
 * twice this transaction's virtual size, with a floor of USER_DESCENDANT_LIMIT_FLOOR. */
uint64_t CalculateUserDescendantLimit(const CTransaction& tx);

/** For each entry, if the transaction signals user-elected descendant limits,
 * check that total size with descendants <= descendant_vsize_limit.
 * @returns std::nullopt if all checks passed, error string if any entry failed.
 */
std::optional<std::string> CheckUserDescendantLimits(const CTxMemPool::setEntries& entries,
                                                     uint64_t additional_vsize);
#endif // BITCOIN_POLICY_USERDESCLIMIT_H
