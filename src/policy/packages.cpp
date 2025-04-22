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
#include <span>
#include <utility>

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

bool IsChildWithParentsTree(const Package& package)
{
    if (!IsChildWithParents(package)) return false;
    std::unordered_set<Txid, SaltedTxidHasher> parent_txids;
    std::transform(package.cbegin(), package.cend() - 1, std::inserter(parent_txids, parent_txids.end()),
                   [](const auto& ptx) { return ptx->GetHash(); });
    // Each parent must not have an input who is one of the other parents.
    return std::all_of(package.cbegin(), package.cend() - 1, [&](const auto& ptx) {
        for (const auto& input : ptx->vin) {
            if (parent_txids.count(input.prevout.hash) > 0) return false;
        }
        return true;
    });
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

MiniGraph::MiniGraph(const std::vector<CTransactionRef>& txns_in, CFeeRate min_feerate) :
    m_txns{txns_in},
    m_min_feerate{min_feerate.GetFee(MAX_PACKAGE_WEIGHT), MAX_PACKAGE_WEIGHT}
{
    m_graph = MakeTxGraph(txns_in.size(), MAX_PACKAGE_WEIGHT, 100000);
}

void MiniGraph::RegisterInfo(const CTransactionRef& tx, CAmount fee, int64_t size, bool needs_package_rbf) {
    // Changing any transaction's feerate would change the linearization, so we don't permit this action after
    // Linearize() has been called.
    if (m_status != Status::REGISTRATION) return;

    TxGraph::Ref ref = m_graph->AddTransaction(FeePerWeight{fee, static_cast<int32_t>(size)});
    m_info.emplace(tx->GetHash(), Tx(std::move(ref), tx, needs_package_rbf));
}

void MiniGraph::ScheduleValidation() {
    if (m_status != Status::REGISTRATION) return;

    // Client-side bug if we forgot to RegisterInfo for some transactions
    Assume(m_info.size() + m_num_skip_linearization == m_txns.size());

    // Populate TxGraph
    for (const auto& tx : m_txns) {
        auto it = m_info.find(tx->GetHash());
        if (it != m_info.end()) {
            auto& child = it->second;
            // Add dependencies with previous transactions. This works because the package is required to be topological.
            for (const auto& input : child.m_tx->vin) {
                if (auto it_parent = m_info.find(input.prevout.hash); it_parent != m_info.end()) {
                    m_graph->AddDependency(it_parent->second, child);
                }
            }
        }
    }

    // Determine the validation schedule building a "block" out of its transactions.
    m_builder = m_graph->GetBlockBuilder();
    m_status = Status::LINEARIZED;

    // Initialize current chunk.
    UpdateCurrentChunk();
}

void MiniGraph::UpdateCurrentChunk() {
    // Shouldn't be called in LINEARIZED_AGAIN because we only allow 1 bonus chunk.
    if (m_status != Status::LINEARIZED && m_status != Status::LINEARIZED_RECONSIDERABLE) return;

    // If needed, ask the builder for another chunk. If it is nullopt, there is nothing left to validate.
    if (!m_current_chunk || m_current_chunk->EndOfChunk()) {
        if (auto builder_chunk{m_builder->GetCurrentChunk()}) {
            m_current_chunk = ChunkCache(std::move(*builder_chunk));
        } else {
            m_current_chunk = std::nullopt;
            return;
        }
    }

    // Now, decide what subset of the chunk to serve. Create a new subchunk starting from the beginning or after the
    // last subchunk, adding transactions in linearization order until the aggregate feerate meets m_min_feerate or we
    // reach the end of the chunk.
    // start_index = 0 + 0 = 0 if just initialized.
    m_current_chunk->start_index = m_current_chunk->start_index + m_current_chunk->subchunk_len;
    m_current_chunk->subchunk_len = 0;
    m_current_chunk->feerate = FeePerWeight{0, 0};

    // Only allow subchunking in the first linearization.
    bool allow_subchunking{m_status == Status::LINEARIZED || m_status == Status::LINEARIZED_RECONSIDERABLE};
    while (!m_current_chunk->EndOfChunk()) {
        auto next = static_cast<const Tx*>(m_current_chunk->chunk.first[m_current_chunk->start_index + m_current_chunk->subchunk_len++]);
        m_current_chunk->feerate += m_graph->GetIndividualFeerate(*next);

        // Subchunking can prevent package RBF from being applied, so disable it if package RBF is needed.
        allow_subchunking &= !next->m_needs_package_rbf;

        // Subchunking: use the smallest possible subset of the chunk that meets the minimum feerate.
        if (allow_subchunking && m_current_chunk->subchunk_len == 1 && m_current_chunk->feerate >= m_min_feerate) {
            break;
        }
    }
    // If we reach the end of the chunk, serve it even if the feerate is too low. The caller may decide to throw it away.
}

std::optional<std::pair<std::vector<CTransactionRef>, FeePerWeight>> MiniGraph::GetCurrentSubpackage() const {
    if (!m_current_chunk) return std::nullopt;

    // We are not doing any calculations here, just translating the cached chunk to a vector of transactions.
    std::pair<std::vector<CTransactionRef>, FeePerWeight> result;
    result.first.reserve(m_current_chunk->subchunk_len);
    for (size_t i = m_current_chunk->start_index; i < m_current_chunk->start_index + m_current_chunk->subchunk_len; ++i) {
        auto next = static_cast<const Tx*>(m_current_chunk->chunk.first[i]);
        result.first.emplace_back(next->m_tx);
    }
    result.second = m_current_chunk->feerate;
    return result;
}

void MiniGraph::MarkValid(const std::vector<CTransactionRef>& subpackage) {
    switch (m_status) {
        case Status::REGISTRATION:
        {
            m_num_skip_linearization += 1;
            break;
        }
        case Status::LINEARIZED:
        case Status::LINEARIZED_RECONSIDERABLE:
        {
            // First collect all transactions to remove
            std::vector<std::pair<Txid, TxGraph::Ref*>> to_remove;
            to_remove.reserve(m_current_chunk->chunk.first.size());
            for (auto ref : m_current_chunk->chunk.first) {
                auto tx = static_cast<const Tx*>(ref);
                to_remove.emplace_back(tx->m_tx->GetHash(), ref);
            }

            // Stage removal of these transactions
            if (!m_graph->HaveStaging()) m_graph->StartStaging();

            // Remove transactions and update tracking
            for (const auto& [txid, ref] : to_remove) {
                m_to_remove.push_back(txid);
                m_graph->RemoveTransaction(*ref);
            }

            m_builder->Include();
            UpdateCurrentChunk();
            break;
        }
        case Status::LINEARIZED_AGAIN:
        {
            m_current_chunk = std::nullopt;
            // We only allow 1 bonus chunk.
            m_status = Status::FINAL;
            break;
        }
        case Status::FINAL:
        {
            break;
        }
    }
}

void MiniGraph::MarkRejected(const std::vector<CTransactionRef>& subpackage, bool reconsiderable) {
    switch (m_status) {
        case Status::REGISTRATION:
        {
            m_num_skip_linearization += 1;
            break;
        }
        case Status::LINEARIZED:
        case Status::LINEARIZED_RECONSIDERABLE:
        {
            // Stage removal of these transactions and their descendants.
            // Reconsiderable transactions are not removed from the graph, as we may want to try them again later.
            if (reconsiderable) {
                m_status = Status::LINEARIZED_RECONSIDERABLE;
            } else {
                if (!m_graph->HaveStaging()) m_graph->StartStaging();

                const auto& refs_subset = std::span(m_current_chunk->chunk.first).subspan(m_current_chunk->start_index, m_current_chunk->subchunk_len);
                const auto descendants_union = m_graph->GetDescendantsUnion(refs_subset, TxGraph::Level::TOP);
                for (auto ref : descendants_union) {
                    m_to_remove.emplace_back(static_cast<const Tx*>(ref)->m_tx->GetHash());
                    m_graph->RemoveTransaction(*ref);
                }
            }

            // Don't continue with the rest of the chunk (no effect if we aren't subchunking).
            // Any of the skipped transactions will be reconsidered later.
            m_current_chunk = std::nullopt;

            // The builder will automatically not serve transactions in the same cluster.
            m_builder->Skip();
            UpdateCurrentChunk();
            break;
        }
        case Status::LINEARIZED_AGAIN:
        {
            m_current_chunk = std::nullopt;
            // We only allow 1 bonus chunk.
            m_status = Status::FINAL;
            break;
        }
        case Status::FINAL:
        {
            break;
        }
    }
}

void MiniGraph::ApplyRemovals() {
    m_builder.reset();
    if (m_graph->HaveStaging()) m_graph->CommitStaging();
    m_current_chunk = std::nullopt;
    Assume(m_graph->GetTransactionCount(TxGraph::Level::MAIN) + m_to_remove.size() == m_info.size());
    for (const auto& txid : m_to_remove) {
        Assume(m_info.find(txid) != m_info.end());
        m_info.erase(txid);
    }
    m_to_remove.clear();
    Assume(m_graph->GetTransactionCount(TxGraph::Level::MAIN) == m_info.size());
    Assume(!m_graph->HaveStaging());
}


std::optional<std::vector<CTransactionRef>> MiniGraph::MaybeReconsiderBestChunk() {
    // Most packages (e.g. ones that all succeed) probably don't need a bonus chunk.
    // Quit now if that's the case; we don't actually need to apply the removals and relinearize.
    if (m_status != Status::LINEARIZED_RECONSIDERABLE) return std::nullopt;

    // Apply removal of transactions that succeeded in the first round or can't be reconsidered.
    ApplyRemovals();

    // Using the first linearization, prune transactions from the back whose chunk feerates are below minimum feerate.
    // We are going to alter the feerates of some transactions, so we need to do this now. If we dip below 2
    // transactions at any point, we don't need to continue.
    while (m_graph->GetTransactionCount(TxGraph::Level::MAIN) >= 2) {
        auto worst_chunk = m_graph->GetWorstMainChunk();
        if (worst_chunk.second >= m_min_feerate) {
            break;
        }
        for (auto ref : worst_chunk.first) {
            m_to_remove.emplace_back(static_cast<const Tx*>(ref)->m_tx->GetHash());
            m_graph->RemoveTransaction(*ref);
        }
    }
    ApplyRemovals();

    // No point in reconsidering if there are fewer than 2 transactions left. You need at least 2 to do package RBF.
    if (m_graph->GetTransactionCount(TxGraph::Level::MAIN) < 2) {
        m_status = Status::FINAL;
        return std::nullopt;
    }

    // Set the feerates of transactions that need package RBF to 0.
    for (const auto& [_, tx] : m_info) {
        if (tx.m_needs_package_rbf) {
            m_graph->SetTransactionFee(tx, 0);
        }
    }

    // Move on to the second linearization.
    m_graph->DoWork(100000);
    m_builder = m_graph->GetBlockBuilder();

    // Get the best chunk.
    if (auto builder_chunk{m_builder->GetCurrentChunk()}) {
        std::vector<CTransactionRef> result;
        result.reserve(builder_chunk->first.size());
        for (auto ref : builder_chunk->first) {
            const auto tx = static_cast<const Tx*>(ref);
            Assume(tx->m_tx != nullptr);
            result.emplace_back(tx->m_tx);
        }
        return result;
    }
    return std::nullopt;
}