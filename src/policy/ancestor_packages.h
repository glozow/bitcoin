// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_ANCESTOR_PACKAGES_H
#define BITCOIN_POLICY_ANCESTOR_PACKAGES_H

#include <policy/feerate.h>
#include <policy/packages.h>

#include <vector>

/** A potential ancestor package, i.e. one transaction with its set of unconfirmed ancestors.
 * This class does not have any knowledge of chainstate, so it cannot determine whether all
 * unconfirmed ancestors are present. Its constructor accepts any list of transactions that
 * IsConsistent(), linearizes them topologically, and determines whether it IsAncestorPackage().
 * If fee and vsizes are given for each transaction, it can also linearize the transactions using
 * the ancestor score-based mining algorithm via MiniMiner.
 *
 * Skip() and SkipWithDescendants() can be used to omit transactions. Txns() returns all
 * transactions linearized, and FilteredTxns() is the same but excludes the skipped ones.
 * FilteredAncestorSet() can be used to get a transaction's "subpackage," i.e. ancestor set within the
 * package, also excluding skipped ones.
 * */
class AncestorPackage
{
    /** Whether m_txns contains a connected package in which all transactions are ancestors of the
     * last transaction. This object is not aware of chainstate. So if m_txns only includes a
     * grandparent and not the "connecting" parent, this will (incorrectly) determine that the
     * grandparent is not an ancestor.
     * */
    bool m_ancestor_package_shaped{false};

    struct PackageEntry {
        /** Whether this transaction should be skipped in FilteredAncestorSet() and linearization by
         * fees, i.e. because it is already in the mempool.
         * This value can be set to true by calling Skip(). */
        bool skip{false};
        /** Whether this transaction "dangles," i.e. we know nothing about it it because it is
         * missing inputs or depends on another transaction that is missing inputs.
         * This value can be set to true by calling SkipWithDescendants(). */
        bool dangles{false};
        /** This value starts as std::nullopt when we don't have any fee information yet. It can be
         * updated by calling LinearizeWithFees() if this entry isn't being skipped. */
        std::optional<uint32_t> mining_sequence;
        /** Fees of this transaction. Starts as std::nullopt, can be updated using AddFeeAndVsize(). */
        std::optional<CAmount> fee;
        /** Virtual size of this transaction. Starts as std::nullopt, can be updated using AddFeeAndVsize(). */
        std::optional<int64_t> vsize;

        CTransactionRef tx;
        /** Txids of all in-package ancestors. Populated in ctor and does not change.
         * Use FilteredAncestorSet() to get ancestor sets with the skipped transactions removed.  */
        std::set<uint256> ancestor_subset;
        /** Txids of all in-package descendant. Populated in ctor and does not change. */
        std::set<uint256> descendant_subset;

        explicit PackageEntry(CTransactionRef tx_in) : tx(tx_in) {}

        // Used to sort Txns(), FilteredTxns(), and result of FilteredAncestorSet(). Always guarantees
        // topological sort to the best of our knowledge (see IsSorted()), and puts more
        // incentive-compatible packages first if that information is available.
        //
        // If ancestor score-based linearization sequence exists for both transactions, the
        // transaction with the lower sequence number comes first.
        //    If there is a tie, the transaction with fewer in-package ancestors comes first (topological sort).
        //       If there is still a tie, the transaction with the higher base feerate comes first.
        // Otherwise, the transaction with fewer in-package ancestors comes first (topological sort).
        bool operator<(const PackageEntry& rhs) const {
            if (mining_sequence == std::nullopt || rhs.mining_sequence == std::nullopt) {
                // If mining sequence is missing for either entry, default to topological order.
                if (ancestor_subset.size() == rhs.ancestor_subset.size()) {
                    return descendant_subset.size() > rhs.descendant_subset.size();
                }
                return ancestor_subset.size() < rhs.ancestor_subset.size();
            } else {
                if (mining_sequence.value() == rhs.mining_sequence.value()) {
                    // Identical mining sequence means they would be included in the same ancestor
                    // set. The one with fewer ancestors comes first.
                    if (ancestor_subset.size() == rhs.ancestor_subset.size()) {
                        // Individual feerate. This is not necessarily fee-optimal, but helps in some situations.
                        // (a.fee * b.vsize > b.fee * a.vsize) is a shortcut for (a.fee / a.vsize > b.fee / b.vsize)
                        return *fee * *rhs.vsize  > *rhs.fee * *vsize;
                    }
                    if (ancestor_subset.size() == rhs.ancestor_subset.size()) {
                        return descendant_subset.size() > rhs.descendant_subset.size();
                    }
                    return ancestor_subset.size() < rhs.ancestor_subset.size();
                } else {
                    return mining_sequence.value() < rhs.mining_sequence.value();
                }
            }
        }
    };
    /** Map from each txid to PackageEntry */
    std::map<uint256, PackageEntry> m_txid_to_entry;

    /** Linearized transactions. Topological (IsSorted()) or, if fee information is provided through
     * LinearizeWithFees(), using ancestor set scores. */
    std::vector<std::reference_wrapper<PackageEntry>> m_txns;

    /** Helper function for recursively constructing ancestor caches in ctor. */
    void visit(const CTransactionRef&);
public:
    /** Constructs ancestor package, sorting the transactions topologically and constructing the
     * txid_to_tx and ancestor_subsets maps. It is ok if the input txns is not sorted.
     * Expects:
     * - No duplicate transactions.
     * - No conflicts between transactions.
     */
    AncestorPackage(const Package& txns_in);

    bool IsAncestorPackage() const { return m_ancestor_package_shaped; }

    /** Returns all of the transactions, linearized. */
    Package Txns() const;

    /** Returns all of the transactions, without the skipped and dangling ones, linearized. */
    Package FilteredTxns() const;

    /** Get the sorted, filtered ancestor subpackage for a tx. Includes the tx. Does not
     * include skipped ancestors. If this transaction dangles, returns std::nullopt. */
    std::optional<std::vector<CTransactionRef>> FilteredAncestorSet(const CTransactionRef& tx) const;

    /** Get the total fee and vsize of the ancestor subpackage for a tx. Includes the tx. Does not
     * include skipped ancestors. If this transaction dangles or fee and vsize are
     * unavailable, returns std::nullopt. This result is always consistent with FilteredAncestorSet(). */
    std::optional<std::pair<CAmount, int64_t>> FilteredAncestorFeeAndVsize(const CTransactionRef& tx) const;

    /** Get the fee and vsize of a tx. Returns std::nullopt if this information is unknown. */
    std::optional<std::pair<CAmount, int64_t>> GetFeeAndVsize(const CTransactionRef& tx) const;

    /** From now on, skip this tx from any result in FilteredAncestorSet(). Does not affect Txns().
     * Should be called when a transaction is accepted to mempool or already found in it. */
    void Skip(const CTransactionRef& transaction);

    /** Skip a transaction and all of its descendants. From now on, if this transaction is present
     * in the ancestor set, FilteredAncestorSet() returns std::nullopt for that tx. Does not affect Txns().
     * Should be called when a transaction is missing inputs. */
    void SkipWithDescendants(const CTransactionRef& transaction);

    /** Add information about fee and vsize for a transaction. */
    void AddFeeAndVsize(const uint256& txid, CAmount fee, int64_t vsize);

    /** Re-linearize transactions using the fee and vsize information given. Updates Txns().
     * Information must have been provided for all non-skipped transactions via AddFeeAndVsize().
     * @returns true if successful, false if something went wrong. */
    bool LinearizeWithFees();
};
#endif // BITCOIN_POLICY_ANCESTOR_PACKAGES_H
