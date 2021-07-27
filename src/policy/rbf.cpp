// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <logging.h>
#include <policy/rbf.h>
#include <policy/settings.h>
#include <util/moneystr.h>
#include <util/rbf.h>

#include <string>

RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    AssertLockHeld(pool.cs);

    CTxMemPool::setEntries ancestors;

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) {
        return RBFTransactionState::REPLACEABLE_BIP125;
    }

    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool.exists(tx.GetHash())) {
        return RBFTransactionState::UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    CTxMemPoolEntry entry = *pool.mapTx.find(tx.GetHash());
    pool.CalculateMemPoolAncestors(entry, ancestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    for (CTxMemPool::txiter it : ancestors) {
        if (SignalsOptInRBF(it->GetTx())) {
            return RBFTransactionState::REPLACEABLE_BIP125;
        }
    }
    return RBFTransactionState::FINAL;
}

RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx)
{
    // If we don't have a local mempool we can only check the transaction itself.
    return SignalsOptInRBF(tx) ? RBFTransactionState::REPLACEABLE_BIP125 : RBFTransactionState::UNKNOWN;
}

bool IsRBFOptOut(const CTransaction& txConflicting)
{
    // Allow opt-out of transaction replacement by setting nSequence > MAX_BIP125_RBF_SEQUENCE
    // (SEQUENCE_FINAL-2) on all inputs.
    //
    // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by non-replaceable transactions.
    // All inputs rather than just one is for the sake of multi-party protocols, where we don't want
    // a single party to be able to disable replacement.
    //
    // Transactions that don't explicitly signal replaceability are *not* replaceable with the
    // current logic, even if one of their unconfirmed ancestors signals replaceability. This
    // diverges from BIP125's inherited signaling description (see CVE-2021-31876).  Applications
    // relying on first-seen mempool behavior should check all unconfirmed ancestors; otherwise an
    // opt-in ancestor might be replaced, causing removal of this descendant.
    for (const CTxIn &_txin : txConflicting.vin) {
        if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE) return false;
    }
    return true;
}

bool GetEntriesForRBF(const CTransaction& tx, CTxMemPool& pool,
                      const CTxMemPool::setEntries conflict_iterators,
                      TxValidationState& state, CTxMemPool::setEntries& all_conflicts)
{
    AssertLockHeld(pool.cs);
    const uint256 hash = tx.GetHash();
    std::set<uint256> set_conflictsParents;
    uint64_t nConflictingCount = 0;
    for (const auto& mi : conflict_iterators) {
        for (const CTxIn &txin : mi->GetTx().vin)
        {
            set_conflictsParents.insert(txin.prevout.hash);
        }

        nConflictingCount += mi->GetCountWithDescendants();
        // This potentially overestimates the number of actual descendants but we just want to be
        // conservative to avoid doing too much work.
        if (nConflictingCount > MAX_BIP125_REPLACEMENT_CANDIDATES) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too many potential replacements",
                    strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                        hash.ToString(),
                        nConflictingCount,
                        MAX_BIP125_REPLACEMENT_CANDIDATES));
        }
    }
    // If not too many to replace, then calculate the set of transactions that would have to be
    // evicted, which includes all of the descendants.
    for (CTxMemPool::txiter it : conflict_iterators) {
        pool.CalculateDescendants(it, all_conflicts);
    }
    for (unsigned int j = 0; j < tx.vin.size(); j++)
    {
        // We don't want to accept replacements that require low feerate junk to be mined first.
        // Ideally we'd keep track of the ancestor feerates and make the decision based on that, but
        // for now requiring all new inputs to be confirmed works.
        //
        // Note that if you relax this to make RBF a little more useful, this may break the
        // CalculateMempoolAncestors RBF relaxation, above. See the comment above the first
        // CalculateMempoolAncestors call for more info.
        if (!set_conflictsParents.count(tx.vin[j].prevout.hash))
        {
            // Rather than check the UTXO set - potentially expensive - it's cheaper to just check
            // if the new input refers to a tx that's in the mempool.
            if (pool.exists(tx.vin[j].prevout.hash)) {
                return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "replacement-adds-unconfirmed",
                        strprintf("replacement %s adds unconfirmed input, idx %d",
                            hash.ToString(), j));
            }
        }
    }
    return true;
}

bool SpendsAndConflictsDisjoint(CTxMemPool::setEntries& ancestors, std::set<uint256> set_conflicts,
                                TxValidationState& state, const uint256& hash)
{
    for (CTxMemPool::txiter ancestorIt : ancestors)
    {
        const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
        if (set_conflicts.count(hashAncestor))
        {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-spends-conflicting-tx",
                    strprintf("%s spends conflicting transaction %s",
                        hash.ToString(),
                        hashAncestor.ToString()));
        }
    }
    return true;
}

bool PaysMoreThanConflicts(CTxMemPool::setEntries& conflict_iterators, CFeeRate replacement_feerate,
                           TxValidationState& state, const uint256& hash)
{
    for (const auto& mi : conflict_iterators) {
        // Rule 2: Don't allow the replacement to reduce the feerate of the mempool.
        //
        // We usually don't want to accept replacements with lower feerates than what they replaced
        // as that would lower the feerate of the next block. Requiring that the feerate always be
        // increased is also an easy-to-reason about way to prevent DoS attacks via replacements.
        //
        // We only consider the feerates of transactions being directly replaced, not their indirect
        // descendants. While that does mean high feerate children are ignored when deciding whether
        // or not to replace, we do require the replacement to pay more overall fees too, mitigating
        // most cases.
        CFeeRate original_feerate(mi->GetModifiedFee(), mi->GetTxSize());
        if (replacement_feerate <= original_feerate)
        {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                    strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                        hash.ToString(),
                        replacement_feerate.ToString(),
                        original_feerate.ToString()));
        }
    }
    return true;
}

bool PaysForRBF(CAmount conflict_fees, size_t conflict_vsize,
                CAmount replacement_fees, size_t replacement_vsize,
                TxValidationState& state, const uint256& hash)
{
    // Rule 3: The replacement(s) must pay greater fees than the original transactions. If we didn't
    // enforce this, the bandwidth used by those conflicting transactions would not be paid for.
    if (replacement_fees < conflict_fees)
    {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                    hash.ToString(), FormatMoney(replacement_fees), FormatMoney(conflict_fees)));
    }

    // Rule 4: in addition to paying more fees than the conflicts, the new transaction must pay for
    // its own bandwidth.
    CAmount additional_fees = replacement_fees - conflict_fees;
    if (additional_fees < ::incrementalRelayFee.GetFee(replacement_vsize))
    {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                    hash.ToString(),
                    FormatMoney(additional_fees),
                    FormatMoney(::incrementalRelayFee.GetFee(replacement_vsize))));
    }
    return true;
}
