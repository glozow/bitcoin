// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <memory>
#include <numeric>

/** IsTopoSortedPackage where a set of txids has been pre-populated. The set is assumed to be correct and
 * is mutated within this function (even if return value is false). */
bool IsTopoSortedPackage(const Package& txns, std::unordered_set<Txid, SaltedTxidHasher>& later_txids)
{
    // Avoid misusing this function: later_txids should contain the txids of txns.
    Assume(txns.size() == later_txids.size());

    // later_txids always contains the txids of this transaction and the ones that come later in
    // txns. If any transaction's input spends a tx in that set, we've found a parent placed later
    // than its child.
    for (const auto& tx : txns) {
        for (const auto& input : tx->vin) {
            if (later_txids.find(input.prevout.hash) != later_txids.end()) {
                // The parent is a subsequent transaction in the package.
                return false;
            }
        }
        // Avoid misusing this function: later_txids must contain every tx.
        Assume(later_txids.erase(tx->GetHash()) == 1);
    }

    // Avoid misusing this function: later_txids should have contained the txids of txns.
    Assume(later_txids.empty());
    return true;
}

bool IsTopoSortedPackage(const Package& txns)
{
    std::unordered_set<Txid, SaltedTxidHasher> later_txids;
    std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });

    return IsTopoSortedPackage(txns, later_txids);
}

bool IsConsistentPackage(const Package& txns)
{
    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    std::unordered_set<COutPoint, SaltedOutpointHasher> inputs_seen;
    for (const auto& tx : txns) {
        if (tx->vin.empty()) {
            // This function checks consistency based on inputs, and we can't do that if there are
            // no inputs. Duplicate empty transactions are also not consistent with one another.
            // This doesn't create false negatives, as unconfirmed transactions are not allowed to
            // have no inputs.
            return false;
        }
        for (const auto& input : tx->vin) {
            if (inputs_seen.find(input.prevout) != inputs_seen.end()) {
                // This input is also present in another tx in the package.
                return false;
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

bool IsWellFormedPackage(const Package& txns, PackageValidationState& state, bool require_sorted)
{
    const unsigned int package_count = txns.size();

    if (package_count > MAX_PACKAGE_COUNT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-many-transactions");
    }

    const int64_t total_weight = std::accumulate(txns.cbegin(), txns.cend(), 0,
                               [](int64_t sum, const auto& tx) { return sum + GetTransactionWeight(*tx); });
    // If the package only contains 1 tx, it's better to report the policy violation on individual tx weight.
    if (package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-large");
    }

    std::unordered_set<Txid, SaltedTxidHasher> later_txids;
    std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });

    // Package must not contain any duplicate transactions, which is checked by txid. This also
    // includes transactions with duplicate wtxids and same-txid-different-witness transactions.
    if (later_txids.size() != txns.size()) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-contains-duplicates");
    }

    // Require the package to be sorted in order of dependency, i.e. parents appear before children.
    // An unsorted package will fail anyway on missing-inputs, but it's better to quit earlier and
    // fail on something less ambiguous (missing-inputs could also be an orphan or trying to
    // spend nonexistent coins).
    if (require_sorted && !IsTopoSortedPackage(txns, later_txids)) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-sorted");
    }

    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    if (!IsConsistentPackage(txns)) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "conflict-in-package");
    }
    return true;
}

bool IsChildWithParents(const Package& package)
{
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    if (package.size() < 2) return false;

    // The package is expected to be sorted, so the last transaction is the child.
    const auto& child = package.back();
    std::unordered_set<Txid, SaltedTxidHasher> input_txids;
    std::transform(child->vin.cbegin(), child->vin.cend(),
                   std::inserter(input_txids, input_txids.end()),
                   [](const auto& input) { return input.prevout.hash; });

    // Every transaction must be a parent of the last transaction in the package.
    return std::all_of(package.cbegin(), package.cend() - 1,
                       [&input_txids](const auto& ptx) { return input_txids.count(ptx->GetHash()) > 0; });
}

uint256 GetPackageHash(const std::vector<CTransactionRef>& transactions)
{
    // Create a vector of the wtxids.
    std::vector<Wtxid> wtxids_copy;
    std::transform(transactions.cbegin(), transactions.cend(), std::back_inserter(wtxids_copy),
        [](const auto& tx){ return tx->GetWitnessHash(); });

    // Sort in ascending order
    std::sort(wtxids_copy.begin(), wtxids_copy.end(), [](const auto& lhs, const auto& rhs) {
        return std::lexicographical_compare(std::make_reverse_iterator(lhs.end()), std::make_reverse_iterator(lhs.begin()),
                                            std::make_reverse_iterator(rhs.end()), std::make_reverse_iterator(rhs.begin()));
    });

    // Get sha256 hash of the wtxids concatenated in this order
    HashWriter hashwriter;
    for (const auto& wtxid : wtxids_copy) {
        hashwriter << wtxid;
    }
    return hashwriter.GetSHA256();
}

MiniGraph::MiniGraph(const std::vector<CTransactionRef>& txns_in) : m_txns{txns_in} {
    for (unsigned int i{0}; i < txns_in.size(); ++i) {
        m_info.emplace(txns_in.at(i)->GetWitnessHash(), Tx(txns_in.at(i), i));
    }
    m_graph = MakeTxGraph(txns_in.size(), MAX_PACKAGE_WEIGHT, 1000000);
}

/** Register feerate information for a transaction. Overwrites previous data if called
 * multiple times for the same transaction. */
void MiniGraph::RegisterInfo(const CTransactionRef& tx, CAmount fee, int64_t size) {
    // If builder exists, that means we already linearized the transactions. Changing any
    // transaction's feerate would change the linearization, so we don't permit this action
    // after Linearize() has been called.
    if (!Assume(m_builder == nullptr)) return;

    auto it = m_info.find(tx->GetWitnessHash());
    if (it != m_info.end()) {
        it->second.m_fee = fee;
        it->second.m_size = size;
        it->second.m_status = TxStatus::REGISTERED;
    }
}

/** Schedule validation of transactions. Each transaction must either be valid, rejected, or
 * registered. */
// FIXME: add a CFeeRate for minimum feerate so we can split subpackages into individual transactions.
void MiniGraph::ScheduleValidation() {
    if (!Assume(m_builder == nullptr)) return;
    // Temporary map to easily look up refs of parents by prevout, discarded at the end of this
    // function. This is populated as transactions are processed, which works because the
    // package is required to be topological.
    std::map<Txid, TxGraph::Ref*> ref_index;

    // Populate TxGraph
    for (const auto& tx : m_txns) {
        auto& info = m_info.at(tx->GetWitnessHash());
        switch (info.m_status) {
            case TxStatus::REGISTERED:
            {
                // Caller should have registered feerate
                Assume(info.m_size != 0);
                info.m_ref = m_graph->AddTransaction(FeePerWeight{info.m_fee, info.m_size});

                // Add dependencies with previous transactions.
                for (const auto& input : info.m_tx->vin) {
                    if (auto it_parent = ref_index.find(input.prevout.hash); it_parent != ref_index.end()) {
                        m_graph->AddDependency(*it_parent->second, info.m_ref);
                    }
                }

                // Add ref to index so subsequent dependencies can be added
                ref_index.emplace(info.m_tx->GetHash(), &info.m_ref);
                break;
            }
            case TxStatus::REJECTED:
            case TxStatus::VALID:
            {
                break;
            }
            case TxStatus::UNKNOWN:
            {
                // Bug! We forgot to RegisterInfo for this transaction, or somehow
                // set a tranasction to VALID before ever running ScheduleValidation.
                Assume(false);
                break;
            }
        }
    }

    // Determine the validation schedule building a "block" out of its transactions.
    m_builder = m_graph->GetBlockBuilder();
    m_graph->SanityCheck();
}

/** Get the next subpackage to validate. ScheduleValidation must have already been called.
 * Returns nullopt if there is nothing left to validate. Call MarkValid or MarkRejected before
 * next call to GetCurrentSubpackage.
 */
std::optional<std::pair<std::vector<CTransactionRef>, FeePerWeight>> MiniGraph::GetCurrentSubpackage() {
    auto curr_chunk{m_builder->GetCurrentChunk()};
    if (curr_chunk) {
        // If there is a next chunk, translate it to a vector of transactions and return.
        std::pair<std::vector<CTransactionRef>, FeePerWeight> result;
        result.first.reserve(curr_chunk->first.size());
        for (const auto& ref : curr_chunk->first) {
            auto it = std::find_if(m_info.begin(), m_info.end(), [&ref](const auto& pair) { return &pair.second.m_ref == ref; });
            if (Assume(it != m_info.end())) result.first.emplace_back(it->second.m_tx);
        }
        result.second = curr_chunk->second;
        return result;
    }
    // Otherwise, there are no more transactions left to validate.
    return std::nullopt;
}

/** Call for transactions accepted to mempool or already found there. */
void MiniGraph::MarkValid(const std::vector<CTransactionRef>& subpackage) {
    for (const auto& tx : subpackage) {
        auto it = m_info.find(tx->GetWitnessHash());
        if (Assume(it != m_info.end())) {
            it->second.m_status = TxStatus::VALID;
        }
    }
    if (m_builder) m_builder->Include();
}

/** Call for transactions rejected from mempool. These transactions will not be included in the
 * validation schedule (descendants are not tracked, so it is assumed the caller will call
 * MarkRejected for any that exist). If validation schedule has already been created, these
 * transactions' cluster will be excluded from further calls to GetCurrentSubpackage. */
void MiniGraph::MarkRejected(const std::vector<CTransactionRef>& subpackage) {
    for (const auto& tx : subpackage) {
        auto it = m_info.find(tx->GetWitnessHash());
        if (Assume(it != m_info.end())) {
            it->second.m_status = TxStatus::REJECTED;
        }
    }
    if (m_builder) m_builder->Skip();
}
