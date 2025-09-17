// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_PACKAGES_H
#define BITCOIN_POLICY_PACKAGES_H

#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <txgraph.h>
#include <util/hasher.h>

#include <cstdint>
#include <optional>
#include <unordered_set>
#include <vector>

/** Default maximum number of transactions in a package. */
static constexpr uint32_t MAX_PACKAGE_COUNT{25};
/** Default maximum total weight of transactions in a package in weight
    to allow for context-less checks. This must allow a superset of sigops
    weighted vsize limited transactions to not disallow transactions we would
    have otherwise accepted individually. */
static constexpr uint32_t MAX_PACKAGE_WEIGHT = 404'000;
static_assert(MAX_PACKAGE_WEIGHT >= MAX_STANDARD_TX_WEIGHT);

// If a package is to be evaluated, it must be at least as large as the mempool's ancestor/descendant limits,
// otherwise transactions that would be individually accepted may be rejected in a package erroneously.
// Since a submitted package must be child-with-parents (all of the transactions are a parent
// of the child), package limits are ultimately bounded by mempool package limits. Ensure that the
// defaults reflect this constraint.
static_assert(DEFAULT_DESCENDANT_LIMIT >= MAX_PACKAGE_COUNT);
static_assert(DEFAULT_ANCESTOR_LIMIT >= MAX_PACKAGE_COUNT);
static_assert(MAX_PACKAGE_WEIGHT >= DEFAULT_ANCESTOR_SIZE_LIMIT_KVB * WITNESS_SCALE_FACTOR * 1000);
static_assert(MAX_PACKAGE_WEIGHT >= DEFAULT_DESCENDANT_SIZE_LIMIT_KVB * WITNESS_SCALE_FACTOR * 1000);

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

/** Represents a package that is being validated. Tracks the transactions' dependencies, feerate information, and
 * validation status (some might be skipped because they are already in mempool or invalid and not eligible for
 * reconsideration). Uses a TxGraph to determine the schedule in which subpackages should be validated, and splits
 * chunks into subchunks if a subchunk meets the minimum feerate. */
class MiniGraph
{
    // Copy of the transactions provided in the constructor. These must be sorted.
    const std::vector<CTransactionRef> m_txns;

    // Number of transactions we omit from m_info. These are transactions that are already in mempool or invalid and not eligible for reconsideration.
    unsigned int m_num_skip_linearization{0};

    // Minimum feerate: when transations meet this feerate, they can be scheduled individually instead of with their
    // full chunk.
    const FeePerWeight m_min_feerate;

    enum class TxStatus {
        UNKNOWN = 0,
        REJECTED,
        REGISTERED,
        VALID,
    };

    struct Tx : public TxGraph::Ref {
        CTransactionRef m_tx;
        std::optional<CAmount> m_fees_with_conflicts;
        bool m_remove_from_graph{false};
        Tx(TxGraph::Ref&& ref, const CTransactionRef& tx, std::optional<CAmount> fees_with_conflicts)
            : TxGraph::Ref(std::move(ref)),
              m_tx{tx},
              m_fees_with_conflicts{fees_with_conflicts}
            {}
    };

    /** Main data structure. */
    std::map<Txid, Tx> m_info;

    std::unique_ptr<TxGraph> m_graph;
    /** Used to construct validation schedule. */
    std::unique_ptr<TxGraph::BlockBuilder> m_builder;

    struct ChunkCache {
        // Full chunk from the builder.
        std::pair<std::vector<TxGraph::Ref*>, FeePerWeight> chunk;

        size_t start_index{0};
        size_t subchunk_len{0};
        FeePerWeight feerate{0, 0};

        // Initialize with a full chunk from the builder.
        ChunkCache(std::pair<std::vector<TxGraph::Ref*>, FeePerWeight>&& builder_chunk) : chunk{std::move(builder_chunk)} {}

        // Serve current (sub)chunk.
        std::pair<std::vector<TxGraph::Ref*>, FeePerWeight> GetChunk() const {
            Assume(start_index + subchunk_len <= chunk.first.size());
            return {std::vector<TxGraph::Ref*>(chunk.first.begin() + start_index, chunk.first.begin() + start_index + subchunk_len), feerate};
        }

        // Check whether the current chunk we are serving completes the full chunk.
        // If so, we need to ask the builder for the next chunk.
        bool EndOfChunk() const {
            Assume(start_index + subchunk_len <= chunk.first.size());
            return start_index + subchunk_len >= chunk.first.size();
        }
    };

    // Cache of the current chunk. When nullopt, there are no more chunks to serve.
    std::optional<ChunkCache> m_current_chunk;

    // Whether the transactions have been linearized.
    bool Linearized() const { return m_builder != nullptr; }

    // Proceed to the next (sub)chunk. This should be called at the end of ScheduleValidation, MarkValid, and
    // MarkRejected to update m_current_chunk for the next call to GetCurrentSubpackage.
    void UpdateCurrentChunk();

public:
    MiniGraph(const std::vector<CTransactionRef>& txns_in, CFeeRate min_feerate);

    /** Register feerate information for a transaction. Overwrites previous data if called
     * multiple times for the same transaction. Only allowed before linearization. */
    void RegisterInfo(const CTransactionRef& tx, CAmount fee, int64_t size, CAmount conflicting_fees);

    /** Schedule validation of transactions. Each transaction must either be valid, rejected, or
     * registered. Only allowed if linearization has not happened yet. */
    void ScheduleValidation();

    /** Get the next subpackage to validate: the smallest (sub)chunk that meets the minimum feerate.
     * Returns nullopt if there is nothing left to validate. ScheduleValidation must have already been called. This
     * value is cached; call MarkValid or MarkRejected before the next call to GetCurrentSubpackage, otherwise the same
     * transactions will be returned. Only allowed after linearization.
     */
    std::optional<std::pair<std::vector<CTransactionRef>, FeePerWeight>> GetCurrentSubpackage() const;

    /** Mark that transaction(s) were accepted to mempool (after linearization) or already found there (before
     * linearization). */
    void MarkValid(const std::vector<CTransactionRef>& subpackage);

    /** Mark that transaction(s) were rejected from mempool. These transactions will not be included in the
     * validation schedule. If validation schedule has already been created, these transactions'
     * cluster will be excluded from further calls to GetCurrentSubpackage. */
    void MarkRejected(const std::vector<CTransactionRef>& subpackage);

    /** Remove these transactions and any subsequent ones from the graph, preparing for a second round of linearization
     * where the feerates are discounted for conflicts so we don't have an accurate view of their feerate.
     * FIXME: this can be absorbed into GetCurrentSubpackage() since we know the minimum feerate. */
    void PruneLowFeerate();
};

class PackageValidationState : public ValidationState<PackageValidationResult> {};

/** If any direct dependencies exist between transactions (i.e. a child spending the output of a
 * parent), checks that all parents appear somewhere in the list before their respective children.
 * No other ordering is enforced. This function cannot detect indirect dependencies (e.g. a
 * transaction's grandparent if its parent is not present).
 * @returns true if sorted. False if any tx spends the output of a tx that appears later in txns.
 */
bool IsTopoSortedPackage(const Package& txns);

/** Checks that these transactions don't conflict, i.e., spend the same prevout. This includes
 * checking that there are no duplicate transactions. Since these checks require looking at the inputs
 * of a transaction, returns false immediately if any transactions have empty vin.
 *
 * Does not check consistency of a transaction with oneself; does not check if a transaction spends
 * the same prevout multiple times (see bad-txns-inputs-duplicate in CheckTransaction()).
 *
 * @returns true if there are no conflicts. False if any two transactions spend the same prevout.
 * */
bool IsConsistentPackage(const Package& txns);

/** Context-free package policy checks:
 * 1. The number of transactions cannot exceed MAX_PACKAGE_COUNT.
 * 2. The total weight cannot exceed MAX_PACKAGE_WEIGHT.
 * 3. If any dependencies exist between transactions, parents must appear before children.
 * 4. Transactions cannot conflict, i.e., spend the same inputs.
 */
bool IsWellFormedPackage(const Package& txns, PackageValidationState& state, bool require_sorted);

/** Context-free check that a package is exactly one child and its parents; not all parents need to
 * be present, but the package must not contain any transactions that are not the child's parents.
 * It is expected to be sorted, which means the last transaction must be the child.
 */
bool IsChildWithParents(const Package& package);

/** Context-free check that a package IsChildWithParents() and none of the parents depend on each
 * other (the package is a "tree").
 */
bool IsChildWithParentsTree(const Package& package);

/** Get the hash of the concatenated wtxids of transactions, with wtxids
 * treated as a little-endian numbers and sorted in ascending numeric order.
 */
uint256 GetPackageHash(const std::vector<CTransactionRef>& transactions);

#endif // BITCOIN_POLICY_PACKAGES_H
