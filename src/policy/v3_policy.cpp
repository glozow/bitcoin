// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/v3_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/check.h>

#include <algorithm>
#include <numeric>
#include <vector>

/** Helper for PackageV3Checks: Returns a vector containing the indices of transactions (within
 * package) that are direct parents of ptx. Also populates
 * PackageWithAncestorCounts::has_in_package_ancestor. */
std::vector<int> FindInPackageParents(PackageWithAncestorCounts& package_with_ancestors, const CTransactionRef& ptx)
{
    std::vector<int> in_package_parents;

    std::set<Txid> possible_parents;
    for (auto &input : ptx->vin) {
        possible_parents.insert(input.prevout.hash);
    }

    size_t my_index{0};

    for (size_t i = 0; i < package_with_ancestors.package.size(); ++i) {
        const auto& tx = package_with_ancestors.package[i];
        // We assume the package is sorted, so that we don't need to continue
        // looking past the transaction itself.
        if (&(*tx) == &(*ptx)) {
            my_index = i;
            break;
        }
        if (possible_parents.count(tx->GetHash())) {
            in_package_parents.push_back(i);
        }
    }

    if (!in_package_parents.empty()) {
        package_with_ancestors.has_in_package_ancestor.at(my_index) = true;
    }
    return in_package_parents;
}

std::optional<std::string> PackageV3Checks(const CTransactionRef& ptx, int64_t vsize,
                                           PackageWithAncestorCounts& package_with_ancestors,
                                           const CTxMemPool::setEntries& mempool_ancestors)
{
    const auto in_package_parents{FindInPackageParents(package_with_ancestors, ptx)};

    // Now we have all ancestors, so we can start checking v3 rules.
    if (ptx->nVersion == 3) {
        // v3 transactions can have at most 1 unconfirmed parent
        if (mempool_ancestors.size() + in_package_parents.size() > 1) {
            return strprintf("tx %s would have too many ancestors", ptx->GetWitnessHash().ToString());
        }

        const bool has_parent{mempool_ancestors.size() + in_package_parents.size() > 0};
        if (has_parent) {
            // A v3 child cannot be too large.
            if (vsize > V3_CHILD_MAX_VSIZE) {
                return strprintf("v3 child tx %s is too big: %u > %u virtual bytes",
                                 ptx->GetWitnessHash().ToString(), vsize, V3_CHILD_MAX_VSIZE);
            }

            // Find the parent and extract the information we need for v3 checks.
            int parent_version = 0;
            // fixme: parent hash is txid, should return err strings with wtxid?
            Txid parent_hash = Txid::FromUint256(uint256(0));
            Wtxid parent_wtxid = Wtxid::FromUint256(uint256(0));
            int other_mempool_descendants = 0;

            if (mempool_ancestors.size() > 0) {
                // There's a parent in the mempool.
                auto& parent = *mempool_ancestors.begin();
                parent_version = parent->GetTx().nVersion;
                // Subtract 1 because descendant count is inclusive of the tx itself.
                other_mempool_descendants = parent->GetCountWithDescendants() - 1;
                parent_hash = parent->GetTx().GetHash();
                parent_wtxid = parent->GetTx().GetWitnessHash();
            } else {
                // Ancestor must be in the package. Find it.
                auto &parent_index = in_package_parents[0];
                // If the in-package parent has mempool or in-package ancestors, then this is a v3 violation.
                if (package_with_ancestors.ancestor_counts[parent_index] > 0 ||
                    package_with_ancestors.has_in_package_ancestor.at(parent_index)) {
                    return strprintf("tx %s would have too many ancestors", ptx->GetWitnessHash().ToString());
                }

                auto &parent = package_with_ancestors.package[parent_index];
                parent_version = parent->nVersion;
                // There may be in-package descendants, which we will look for below.
                other_mempool_descendants = 0;
                parent_hash = parent->GetHash();
                parent_wtxid = parent->GetWitnessHash();
            }

            // If there is a parent, it must have the right version.
            if (parent_version != 3) {
                return strprintf("v3 tx %s cannot spend from non-v3 tx %s",
                                 ptx->GetWitnessHash().ToString(), parent_wtxid.ToString());
            }

            // The mempool or in-package parent cannot have any other in-mempool children.
            if (other_mempool_descendants > 0) {
                return strprintf("tx %u would exceed descendant count limit", parent_wtxid.ToString());
            }

            for (const auto& package_tx : package_with_ancestors.package) {
                // Skip same tx.
                if (&(*package_tx) == &(*ptx)) continue;

                for (auto& input : package_tx->vin) {
                    // Fail if we find another tx with the same parent.
                    if (input.prevout.hash == parent_hash) {
                        return strprintf("tx %u would exceed descendant count limit", parent_wtxid.ToString());
                    }

                    // This tx can't have both a parent and an in-package child. Can be redundant
                    // with the multiple in-package ancestors check above.
                    /* if (input.prevout.hash == ptx->GetHash()) { */
                    /*     return strprintf("tx %u would have too many ancestors", package_tx->GetWitnessHash().ToString()); */
                    /* } */
                }
            }

        }
    } else {
        // Non-v3 transactions cannot have v3 parents.
        for (auto it : mempool_ancestors) {
            if (it->GetTx().nVersion == 3) {
                return strprintf("non-v3 tx %s cannot spend from v3 tx %s",
                                 ptx->GetWitnessHash().ToString(), it->GetSharedTx()->GetWitnessHash().ToString());
            }
        }
        for (const auto& index: in_package_parents) {
            if (package_with_ancestors.package[index]->nVersion == 3) {
                return strprintf("non-v3 tx %s cannot spend from v3 tx %s",
                                 ptx->GetWitnessHash().ToString(),
                                 package_with_ancestors.package.at(index)->GetWitnessHash().ToString());
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& mempool_ancestors,
                                        const std::set<Txid>& direct_conflicts,
                                        int64_t vsize)
{
    // Check v3 and non-v3 inheritance.
    for (const auto& entry : mempool_ancestors) {
        if (ptx->nVersion != 3 && entry->GetTx().nVersion == 3) {
            return strprintf("non-v3 tx %s cannot spend from v3 tx %s",
                             ptx->GetWitnessHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString());
        } else if (ptx->nVersion == 3 && entry->GetTx().nVersion != 3) {
            return strprintf("v3 tx %s cannot spend from non-v3 tx %s",
                             ptx->GetWitnessHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString());
        }
    }

    // This function is specialized for these limits, and must be reimplemented if they ever change.
    static_assert(V3_ANCESTOR_LIMIT == 2);
    static_assert(V3_DESCENDANT_LIMIT == 2);

    // The rest of the rules only apply to transactions with nVersion=3.
    if (ptx->nVersion != 3) return std::nullopt;

    // Check that V3_ANCESTOR_LIMIT would not be violated, including both in-package and in-mempool.
    if (mempool_ancestors.size() + 1 > V3_ANCESTOR_LIMIT) {
        return strprintf("tx %s would have too many ancestors", ptx->GetWitnessHash().ToString());
    }

    // Remaining checks only pertain to transactions with unconfirmed ancestors.
    if (mempool_ancestors.size() > 0) {
        // If this transaction spends V3 parents, it cannot be too large.
        if (vsize > V3_CHILD_MAX_VSIZE) {
            return strprintf("v3 child tx %s is too big: %u > %u virtual bytes", ptx->GetWitnessHash().ToString(), vsize, V3_CHILD_MAX_VSIZE);
        }

        // Check the descendant counts of in-mempool ancestors.
        if (!mempool_ancestors.empty()) {
            const auto& parent_entry = *mempool_ancestors.begin();
            // If there are any ancestors, this is the only child allowed. The parent cannot have any
            // other descendants.
            const auto& children = parent_entry->GetMemPoolChildrenConst();
            // Don't double-count a transaction that is going to be replaced. This logic assumes that
            // any descendant of the V3 transaction is a direct child, which makes sense because a V3
            // transaction can only have 1 descendant.
            const bool child_will_be_replaced = !children.empty() &&
                std::any_of(children.cbegin(), children.cend(),
                    [&direct_conflicts](const CTxMemPoolEntry& child){return direct_conflicts.count(child.GetTx().GetHash()) > 0;});
            if (parent_entry->GetCountWithDescendants() + 1 > V3_DESCENDANT_LIMIT && !child_will_be_replaced) {
                return strprintf("tx %u would exceed descendant count limit", parent_entry->GetSharedTx()->GetWitnessHash().ToString());
            }
        }
    }
    return std::nullopt;
}
