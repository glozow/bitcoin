// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_PACKAGES_H
#define BITCOIN_POLICY_PACKAGES_H

#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/hasher.h>

#include <cstdint>
#include <unordered_set>
#include <vector>

/** Default maximum number of transactions in a package. */
static constexpr uint32_t MAX_PACKAGE_COUNT{25};
/** Default maximum total virtual size of transactions in a package in KvB. */
static constexpr uint32_t MAX_PACKAGE_SIZE{101};
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

bool IsSorted(const Package& txns);
bool HasNoConflicts(const Package& txns);

/** Context-free package policy checks:
 * 1. The number of transactions cannot exceed MAX_PACKAGE_COUNT.
 * 2. The total virtual size cannot exceed MAX_PACKAGE_SIZE.
 * 3. If any dependencies exist between transactions, parents must appear before children.
 * 4. Transactions cannot conflict, i.e., spend the same inputs.
 */
bool IsPackageWellFormed(const Package& txns, PackageValidationState& state);

/** Context-free check that a package is exactly one child and its parents; not all parents need to
 * be present, but the package must not contain any transactions that are not the child's parents.
 * It is expected to be sorted, which means the last transaction must be the child.
 */
bool IsChildWithParents(const Package& package);

class Packageifier
{
    /** Transactions sorted topologically. */
    Package txns;
    /** Caches the transactions by txid for quick lookup. */
    std::map<uint256, CTransactionRef> txid_to_tx;
    /** Caches the in-package ancestors for each transaction. */
    std::map<uint256, std::set<uint256>> ancestor_subsets;
    /** Transactions to exclude when returning ancestor subsets.*/
    std::unordered_set<uint256, SaltedTxidHasher> excluded_txns;
    /** Transactions that are banned. Return empty vector if any ancestor subset contains these transactions.*/
    std::unordered_set<uint256, SaltedTxidHasher> banned_txns;

    /** Helper function for recursively constructing ancestor caches in ctor. */
    void visit(const CTransactionRef&);
public:
    /** Constructs ancestor package, sorting the transactions topologically and constructing the
     * txid_to_tx and ancestor_subsets maps. It is ok if the input txns is not sorted.
     * Expects:
     * - No conflicts between transactions.
     * - txns is of reasonable size (e.g. below MAX_PACKAGE_COUNT) to limit recursion depth
     */
    Packageifier(const Package& txns);
    /** Returns the transactions, in ascending order of number of in-package ancestors. */
    Package Txns() const { return txns; }
    /** Get the ancestor subpackage for a tx, sorted so that ancestors appear before descendants.
     * The list includes the tx. If this transaction depends on a Banned tx, returns std::nullopt.
     * If one or more ancestors have been Excluded, they will not appear in the result. */
    std::optional<std::vector<CTransactionRef>> GetAncestorSet(const CTransactionRef& tx);
    /** From now on, exclude this tx from any result in GetAncestorSet(). Does not affect Txns(). */
    void Exclude(const CTransactionRef& transaction);
    /** Mark a transaction as "banned." From now on, if this transaction is present in the ancestor
     * set, GetAncestorSet() should return std::nullopt for that tx. Does not affect Txns(). */
    void Ban(const CTransactionRef& transaction);
};
#endif // BITCOIN_POLICY_PACKAGES_H
