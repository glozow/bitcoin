// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_RBF_H
#define BITCOIN_POLICY_RBF_H

#include <txmempool.h>
#include <consensus/validation.h>

/** Maximum number of transactions that can be replaced by BIP125 RBF (Rule #5). This includes all
 * mempool conflicts and their descendants. */
static constexpr uint32_t MAX_BIP125_REPLACEMENT_CANDIDATES{100};

/** The rbf state of unconfirmed transactions */
enum class RBFTransactionState {
    /** Unconfirmed tx that does not signal rbf and is not in the mempool */
    UNKNOWN,
    /** Either this tx or a mempool ancestor signals rbf */
    REPLACEABLE_BIP125,
    /** Neither this tx nor a mempool ancestor signals rbf */
    FINAL,
};

/**
 * Determine whether an unconfirmed transaction is signaling opt-in to RBF
 * according to BIP 125
 * This involves checking sequence numbers of the transaction, as well
 * as the sequence numbers of all in-mempool ancestors.
 *
 * @param tx   The unconfirmed transaction
 * @param pool The mempool, which may contain the tx
 *
 * @return     The rbf state
 */
RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool) EXCLUSIVE_LOCKS_REQUIRED(pool.cs);
RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx);

/** Determine whether a mempool transaction is opting out of RBF. Mempool entries do not inherit
 * signaling from their parents in this implementation. */
bool IsRBFOptOut(const CTransaction& txConflicting);

/** Get all descendants of setIterConflicting. Also enforce BIP125 Rule 5 and quit as early as
 * possible. There cannot be more than MAX_BIP125_REPLACEMENT_CANDIDATES potential entries.
 * @param[out]  all_conflicts      Populated with all the mempool entries that would be replaced,
 *                                  which includes descendants of conflict_iterators. Not cleared at
 *                                  the start; any existing mempool entries will remain in the set.
 * @returns false if Rule 5 is broken.
 */
bool GetEntriesForRBF(const CTransaction& tx, CTxMemPool& pool,
                      const CTxMemPool::setEntries conflict_iterators, TxValidationState& state,
                      CTxMemPool::setEntries& all_conflicts) EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** Enforce BIP125 Rule 2: a replacement transaction must not add any new unconfirmed inputs. */
bool HasNoNewUnconfirmed(const CTransaction& tx, CTxMemPool& pool,
                         const CTxMemPool::setEntries setIterConflicting,
                         TxValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** Check the intersection between original mempool transactions (candidates for being replaced) and
 * the ancestors of replacement transactions.
 * @param[in]   hash    Transaction ID, included in the error message if violation occurs.
 * returns false if the intersection is empty, true if otherwise.
 */
bool SpendsAndConflictsDisjoint(CTxMemPool::setEntries& ancestors, std::set<uint256> set_conflicts,
                                TxValidationState& state, const uint256& hash);

/** Check that the feerate of the replacement transaction(s) is higher than the feerate of each
 * of the transactions in conflict_iterators.
 */
bool PaysMoreThanConflicts(const CTxMemPool::setEntries& conflict_iterators, CFeeRate replacement_feerate,
                           TxValidationState& state, const uint256& hash);

/** Enforce BIP125 Rules 3 and 4 to ensure that replacement transaction fees are sufficient to
 * replace all conflicting mempool entries.
 * @param[in]   conflict_fees    Total modified fees of original transaction(s).
 * @param[in]   conflict_vsize    Total virtual size of original transaction(s).
 * @param[in]   replacement_fees       Total modified fees of replacement transaction(s).
 * @param[in]   replacement_vsize               Total virtual size of replacement transaction(s).
 * @param[in]   hash                Transaction ID, included in the error message if violation occurs.
 * returns true if fees are sufficient, false if otherwise.
 */
bool PaysForRBF(CAmount conflict_fees, size_t conflict_vsize,
                CAmount replacement_fees, size_t replacement_vsize,
                TxValidationState& state, const uint256& hash);

#endif // BITCOIN_POLICY_RBF_H
