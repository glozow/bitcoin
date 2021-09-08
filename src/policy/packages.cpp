// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <policy/packages.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/hasher.h>

#include <numeric>
#include <unordered_set>

static inline bool IsSorted(const Package& txns)
{
    std::unordered_set<uint256, SaltedTxidHasher> later_txids;
    std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });
    for (const auto& tx : txns) {
        for (const auto& input : tx->vin) {
            // The parent is a subsequent transaction in the package.
            if (later_txids.find(input.prevout.hash) != later_txids.end()) return false;
        }
        later_txids.erase(tx->GetHash());
    }
    return true;
}

static inline bool NoConflicts(const Package& txns)
{
    std::unordered_set<COutPoint, SaltedOutpointHasher> inputs_seen;
    for (const auto& tx : txns) {
        for (const auto& input : tx->vin) {
            // This input is also present in another tx in the package.
            if (inputs_seen.find(input.prevout) != inputs_seen.end()) return false;
        }
        // Batch-add all the inputs for a tx at a time. If we added them 1 at a time, we could
        // catch duplicate inputs within a single tx.  This is a more severe, consensus error,
        // and we want to report that from CheckTransaction instead.
        std::transform(tx->vin.cbegin(), tx->vin.cend(), std::inserter(inputs_seen, inputs_seen.end()),
                       [](const auto& input) { return input.prevout; });
    }
    return true;
}

bool CheckPackage(const Package& txns, PackageValidationState& state)
{
    const unsigned int package_count = txns.size();

    if (package_count > MAX_PACKAGE_COUNT) {
        return state.Invalid(PackageValidationResult::PCKG_BAD, "package-too-many-transactions");
    }

    const int64_t total_size = std::accumulate(txns.cbegin(), txns.cend(), 0,
                               [](int64_t sum, const auto& tx) { return sum + GetVirtualTransactionSize(*tx); });
    // If the package only contains 1 tx, it's better to report the policy violation on individual tx size.
    if (package_count > 1 && total_size > MAX_PACKAGE_SIZE * 1000) {
        return state.Invalid(PackageValidationResult::PCKG_BAD, "package-too-large");
    }

    // Require the package to be sorted in order of dependency, i.e. parents appear before children.
    // An unsorted package will fail anyway on missing-inputs, but it's better to quit earlier and
    // fail on something less ambiguous (missing-inputs could also be an orphan or trying to
    // spend nonexistent coins).
    if (!IsSorted(txns)) return state.Invalid(PackageValidationResult::PCKG_BAD, "package-not-sorted");

    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    if (!NoConflicts(txns)) return state.Invalid(PackageValidationResult::PCKG_BAD, "conflict-in-package");
    return true;
}

bool IsChildWithParents(const Package& package, bool exact)
{
    assert(!package.empty());
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    assert(IsSorted(package));

    if (package.size() < 2) return false;

    const auto& child = package[package.size() - 1];

    std::unordered_set<uint256, SaltedTxidHasher> input_txids;
    std::transform(child->vin.cbegin(), child->vin.cend(),
                   std::inserter(input_txids, input_txids.end()),
                   [](const auto& input) { return input.prevout.hash; });
    assert(!input_txids.empty());

    std::unordered_set<uint256, SaltedTxidHasher> parent_txids;
    std::transform(package.cbegin(), package.cbegin() + (package.size() - 1),
                   std::inserter(parent_txids, parent_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });
    assert(!parent_txids.empty());

    if (exact) {
        return parent_txids == input_txids;
    } else {
        // parent_txids is subset of input_txids
        return parent_txids.size() <= input_txids.size() &&
            std::all_of(parent_txids.cbegin(), parent_txids.cend(),
                        [&input_txids](const auto& txid) { return input_txids.count(txid) > 0; });
    }

}
