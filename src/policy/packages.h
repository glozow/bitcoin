// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_PACKAGES_H
#define BITCOIN_POLICY_PACKAGES_H

#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <util/hasher.h>

#include <cstdint>
#include <unordered_set>
#include <vector>

/** Default maximum number of transactions in a package. */
static constexpr uint32_t MAX_PACKAGE_COUNT{25};
/** Default maximum total weight of transactions in a package in KWu and (non-virtual) KB
    to allow for context-less checks. */
static constexpr uint32_t MAX_PACKAGE_KWEIGHT = 404;
static constexpr uint32_t MAX_PACKAGE_SIZE{MAX_PACKAGE_KWEIGHT / WITNESS_SCALE_FACTOR};
static_assert(MAX_PACKAGE_SIZE == 101);
static_assert(MAX_PACKAGE_SIZE * WITNESS_SCALE_FACTOR * 1000 >= MAX_STANDARD_TX_WEIGHT);

// If a package is submitted, it must be within the mempool's ancestor/descendant limits. Since a
// submitted package must be child-with-unconfirmed-parents (all of the transactions are an ancestor
// of the child), package limits are ultimately bounded by mempool package limits. Ensure that the
// defaults reflect this constraint.
static_assert(DEFAULT_DESCENDANT_LIMIT >= MAX_PACKAGE_COUNT);
static_assert(DEFAULT_ANCESTOR_LIMIT >= MAX_PACKAGE_COUNT);
static_assert(DEFAULT_ANCESTOR_SIZE_LIMIT_KVB >= MAX_PACKAGE_SIZE);
static_assert(DEFAULT_DESCENDANT_SIZE_LIMIT_KVB >= MAX_PACKAGE_SIZE);

/** A "reason" why a package was invalid. It may be that one or more of the included
 * transactions is invalid or the package itself violates our rules.
 * We don't distinguish between consensus and policy violations right now.
 */
enum class PackageValidationResult {
    PCKG_RESULT_UNSET = 0,        //!< Initial value. The package has not yet been rejected.
    PCKG_POLICY,                  //!< The package itself is invalid (e.g. too many transactions).
    PCKG_TX,                      //!< At least one tx is invalid.
    PCKG_MEMPOOL_ERROR,           //!< Mempool logic error.
};

/** A package is an ordered list of transactions. The transactions cannot conflict with (spend the
 * same inputs as) one another. */
using Package = std::vector<CTransactionRef>;

class PackageValidationState : public ValidationState<PackageValidationResult> {};

/** If any direct dependencies exist between transactions (i.e. a child spending the output of a
 * parent), checks that all parents appear somewhere in the list before their respective children.
 * This function cannot detect indirect dependencies (e.g. a transaction's grandparent if its parent
 * is not present).
 * @returns true if sorted. False if any tx spends the output of a tx that appears later in txns.
 */
bool IsSorted(const Package& txns);

/** IsSorted where a set of txids has been pre-populated. The set is assumed to be correct and
 * is mutated within this function. */
bool IsSorted(const Package& txns, std::unordered_set<uint256, SaltedTxidHasher>& all_txids);

/** Checks that none of the transactions conflict, i.e., spend the same prevout. Consequently also
 * checks that there are no duplicate transactions. Since these checks require looking at the inputs
 * of a transaction, returns false immediately if any transactions have empty vin (which is not
 * allowed in unconfirmed transactions).
 * @returns true if there are no conflicts. False if any two transactions spend the same prevout.
 * */
bool IsConsistent(const Package& txns);

/** Context-free package policy checks:
 * 1. The number of transactions cannot exceed MAX_PACKAGE_COUNT.
 * 2. The total (non-virtual) size cannot exceed MAX_PACKAGE_SIZE.
 * 3. If any dependencies exist between transactions, parents must appear before children.
 * 4. Transactions cannot conflict, i.e., spend the same inputs.
 */
bool IsPackageWellFormed(const Package& txns, PackageValidationState& state, bool require_sorted);

#endif // BITCOIN_POLICY_PACKAGES_H
