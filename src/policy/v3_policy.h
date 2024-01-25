// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_V3_POLICY_H
#define BITCOIN_POLICY_V3_POLICY_H

#include <consensus/amount.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <txmempool.h>
#include <util/result.h>

#include <set>
#include <string>

// This module enforces rules for transactions with nVersion=3 ("v3 transactions") which help make
// RBF abilities more robust.

// v3 only allows 1 parent and 1 child.
/** Maximum number of transactions including an unconfirmed tx and its descendants. */
static constexpr unsigned int V3_DESCENDANT_LIMIT{2};
/** Maximum number of transactions including a V3 tx and all its mempool ancestors. */
static constexpr unsigned int V3_ANCESTOR_LIMIT{2};

/** Maximum sigop-adjusted virtual size of a tx which spends from an unconfirmed v3 transaction. */
static constexpr int64_t V3_CHILD_MAX_VSIZE{1000};
// Since these limits are within the default ancestor/descendant limits, there is no need to
// additionally check ancestor/descendant limits for V3 transactions.
static_assert(V3_CHILD_MAX_VSIZE + MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR <= DEFAULT_ANCESTOR_SIZE_LIMIT_KVB * 1000);
static_assert(V3_CHILD_MAX_VSIZE + MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR <= DEFAULT_DESCENDANT_SIZE_LIMIT_KVB * 1000);

/** Must be called for every transaction, even if not v3.
 *
 * Checks the following rules:
 * 1. A v3 tx must only have v3 unconfirmed ancestors.
 * 2. A non-v3 tx must only have non-v3 unconfirmed ancestors.
 * 3. A v3's ancestor set, including itself, must be within V3_ANCESTOR_LIMIT.
 * 4. A v3's descendant set, including itself, must be within V3_DESCENDANT_LIMIT.
 * 5. If a v3 tx has any unconfirmed ancestors, the tx's sigop-adjusted vsize must be within
 * V3_CHILD_MAX_VSIZE.
 *
 *
 * @param[in]   mempool_ancestors       The in-mempool ancestors of ptx, including any that are only
 *                                      direct ancestors of its in-package ancestors.
 * @param[in]   direct_conflicts        In-mempool transactions this tx conflicts with. These conflicts
 *                                      are used to more accurately calculate the resulting descendant
 *                                      count of in-mempool ancestors.  While V3_ANCESTOR_LIMIT is 2, it
 *                                      is unnecessary to include the conflicts of in-package ancestors
 *                                      because the presence of both in-mempool and in-package ancestors
 *                                      would already be a violation of V3_ANCESTOR_LIMIT.
 * @param[in]   vsize                   The sigop-adjusted virtual size of ptx.
 * @returns an error string if any v3 rule was violated, otherwise std::nullopt.
 */
std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& mempool_ancestors,
                                        const std::set<Txid>& direct_conflicts,
                                        int64_t vsize);

/** Must be called for every package containing any v3 transaction. Should not be called for non-v3 packages.
 *
 * Check the following rules for transactions within the package:
 * 1. A v3 tx must only have v3 unconfirmed ancestors.
 * 2. A non-v3 tx must only have non-v3 unconfirmed ancestors.
 * 3. A v3's ancestor set, including itself, must be within V3_ANCESTOR_LIMIT.
 * 4. A v3's descendant set, including itself, must be within V3_DESCENDANT_LIMIT.
 * 5. If a v3 tx has any unconfirmed ancestors, its vsize must be within V3_CHILD_MAX_VSIZE.
 *
 * Important: this function is necessary but insufficient to enforce these rules. ApplyV3Rules must
 * be called for each individual transaction, after in-mempool ancestors, virtual sizes, and
 * in-package ancestors have been calculated. This function serves as a way to quit early on
 * packages in which those calculations may be expensive.
 *
 * @returns If all checks pass, a map from each v3 transaction, by txid, to the txids of its
 * in-package ancestor set. Every ancestor set includes the tx itself. If this passed, we know that
 * each connected component does not violate v3 inheritance or topology constraints within the
 * package itself. If any checks fail, an error string detailing what failed.
 * */
//util::Result<std::map<Txid, std::set<Txid>>> PackageV3Checks(const Package& package);

struct PackageWithAncestorCounts {
    Package package;
    std::vector<size_t> ancestor_counts; // number of in-mempool ancestors for each package transaction.
};

std::optional<std::string> PackageV3Checks(const CTransactionRef& ptx, int64_t vsize,
                                            const PackageWithAncestorCounts& package_with_ancestors,
                                            const CTxMemPool::setEntries& mempool_ancestors, CTxMemPool& pool);

#endif // BITCOIN_POLICY_V3_POLICY_H
