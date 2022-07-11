// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/check.h>
#include <util/hasher.h>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <memory>
#include <numeric>
#include <unordered_set>

bool CheckPackage(const Package& txns, PackageValidationState& state)
{
    const unsigned int package_count = txns.size();

    if (package_count > MAX_PACKAGE_COUNT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-many-transactions");
    }

    const int64_t total_size = std::accumulate(txns.cbegin(), txns.cend(), 0,
                               [](int64_t sum, const auto& tx) { return sum + GetVirtualTransactionSize(*tx); });
    // If the package only contains 1 tx, it's better to report the policy violation on individual tx size.
    if (package_count > 1 && total_size > MAX_PACKAGE_SIZE * 1000) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-large");
    }

    // Require the package to be sorted in order of dependency, i.e. parents appear before children.
    // An unsorted package will fail anyway on missing-inputs, but it's better to quit earlier and
    // fail on something less ambiguous (missing-inputs could also be an orphan or trying to
    // spend nonexistent coins).
    std::unordered_set<uint256, SaltedTxidHasher> later_txids;
    std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });
    for (const auto& tx : txns) {
        for (const auto& input : tx->vin) {
            if (later_txids.find(input.prevout.hash) != later_txids.end()) {
                // The parent is a subsequent transaction in the package.
                return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-sorted");
            }
        }
        later_txids.erase(tx->GetHash());
    }

    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    std::unordered_set<COutPoint, SaltedOutpointHasher> inputs_seen;
    for (const auto& tx : txns) {
        for (const auto& input : tx->vin) {
            if (inputs_seen.find(input.prevout) != inputs_seen.end()) {
                // This input is also present in another tx in the package.
                return state.Invalid(PackageValidationResult::PCKG_POLICY, "conflict-in-package");
            }
        }
        // Batch-add all the inputs for a tx at a time. If we added them 1 at a time, we could
        // catch duplicate inputs within a single tx.  This is a more severe, consensus error,
        // and we want to report that from CheckTransaction instead.
        std::transform(tx->vin.cbegin(), tx->vin.cend(), std::inserter(inputs_seen, inputs_seen.end()),
                       [](const auto& input) { return input.prevout; });
    }
    return true;
}

bool IsChildWithParents(const Package& package)
{
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    if (package.size() < 2) return false;

    // The package is expected to be sorted, so the last transaction is the child.
    const auto& child = package.back();
    std::unordered_set<uint256, SaltedTxidHasher> input_txids;
    std::transform(child->vin.cbegin(), child->vin.cend(),
                   std::inserter(input_txids, input_txids.end()),
                   [](const auto& input) { return input.prevout.hash; });

    // Every transaction must be a parent of the last transaction in the package.
    return std::all_of(package.cbegin(), package.cend() - 1,
                       [&input_txids](const auto& ptx) { return input_txids.count(ptx->GetHash()) > 0; });
}

bool IsAncestorPackage(const Package& package)
{
    const auto& dependent = package.back();
    std::unordered_set<uint256, SaltedTxidHasher> dependency_txids;
    for (auto it = package.rbegin(); it != package.rend(); ++it) {
        const auto& tx = *it;
        // Each transaction must be a dependency of the last transaction.
        if (tx->GetWitnessHash() != dependent->GetWitnessHash() &&
            dependency_txids.count(tx->GetHash()) == 0) {
            return false;
        }
        // Add each transaction's dependencies to allow transactions which are ancestors but not
        // necessarily direct parents of the last transaction.
        std::transform(tx->vin.cbegin(), tx->vin.cend(),
                       std::inserter(dependency_txids, dependency_txids.end()),
                       [](const auto& input) { return input.prevout.hash; });
    }
    return true;
}

std::map<uint256, Package> CalculateAncestorPackages(const std::vector<CTransactionRef>& transactions)
{
    // wtxid to ancestor package for return result
    std::map<uint256, Package> ancestor_packages;
    // txid to transaction for quick lookup when looking at prevouts
    std::unordered_map<uint256, CTransactionRef, SaltedTxidHasher> txid_to_tx;
    auto iteration{0};
    // txid to the iteration in which we last added this transaction to an ancestor set. Allows us
    // to deduplicate ancestors without using a set (which will not preserve order).
    std::unordered_map<uint256, decltype(iteration), SaltedTxidHasher> last_added;
    for (const auto& tx : transactions) {
        last_added.emplace(tx->GetHash(), iteration);
    }
    for (const auto& tx : transactions) {
        ++iteration;
        txid_to_tx.emplace(tx->GetHash(), tx);
        Package ancestors;
        for (const auto& input : tx->vin) {
            // If this is an in-package parent, it must already have entries in txid_to_tx and
            // ancestor_packages.
            if (auto parent_tx_it{txid_to_tx.find(input.prevout.hash)}; parent_tx_it != txid_to_tx.end()) {
                auto parent_package_it{ancestor_packages.find(parent_tx_it->second->GetWitnessHash())};
                Assume(parent_package_it != ancestor_packages.end());
                // Each ancestor of the parent is also an ancestor of the child.
                for (const auto& parent_ancestor : parent_package_it->second) {
                    if (last_added.at(parent_ancestor->GetHash()) != iteration) {
                        ancestors.push_back(parent_ancestor);
                        last_added.at(parent_ancestor->GetHash()) = iteration;
                    }
                }
            }
        }
        ancestors.push_back(tx);
        ancestor_packages.emplace(tx->GetWitnessHash(), ancestors);
    }
    Assume(txid_to_tx.size() == transactions.size());
    Assume(ancestor_packages.size() == transactions.size());
    for (const auto& tx : transactions) {
        auto it = ancestor_packages.find(tx->GetWitnessHash());
        Assume(IsAncestorPackage(it->second));
    }
    return ancestor_packages;
}
