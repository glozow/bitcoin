// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <logging.h>
#include <policy/rbf.h>
#include <util/rbf.h>

#include <string>

RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    AssertLockHeld(pool.cs);

    CTxMemPool::setEntries setAncestors;

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
    pool.CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    for (CTxMemPool::txiter it : setAncestors) {
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

bool GetEntriesForRBF(const CTransaction& tx, CTxMemPool& m_pool,
                      const CTxMemPool::setEntries setIterConflicting,
                      TxValidationState& state, CTxMemPool::setEntries& allConflicting)
{
    AssertLockHeld(m_pool.cs);
    const uint256 hash = tx.GetHash();
    std::set<uint256> setConflictsParents;
    uint64_t nConflictingCount = 0;
    for (const auto& mi : setIterConflicting) {
        for (const CTxIn &txin : mi->GetTx().vin)
        {
            setConflictsParents.insert(txin.prevout.hash);
        }

        nConflictingCount += mi->GetCountWithDescendants();
        // This potentially overestimates the number of actual descendants
        // but we just want to be conservative to avoid doing too much
        // work.
        if (nConflictingCount > MAX_BIP125_REPLACEMENT_CANDIDATES) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too many potential replacements",
                    strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                        hash.ToString(),
                        nConflictingCount,
                        MAX_BIP125_REPLACEMENT_CANDIDATES));
        }
    }
    // If not too many to replace, then calculate the set of
    // transactions that would have to be evicted
    for (CTxMemPool::txiter it : setIterConflicting) {
        m_pool.CalculateDescendants(it, allConflicting);
    }
    for (unsigned int j = 0; j < tx.vin.size(); j++)
    {
        // We don't want to accept replacements that require low
        // feerate junk to be mined first. Ideally we'd keep track of
        // the ancestor feerates and make the decision based on that,
        // but for now requiring all new inputs to be confirmed works.
        //
        // Note that if you relax this to make RBF a little more useful,
        // this may break the CalculateMempoolAncestors RBF relaxation,
        // above. See the comment above the first CalculateMempoolAncestors
        // call for more info.
        if (!setConflictsParents.count(tx.vin[j].prevout.hash))
        {
            // Rather than check the UTXO set - potentially expensive -
            // it's cheaper to just check if the new input refers to a
            // tx that's in the mempool.
            if (m_pool.exists(tx.vin[j].prevout.hash)) {
                return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "replacement-adds-unconfirmed",
                        strprintf("replacement %s adds unconfirmed input, idx %d",
                            hash.ToString(), j));
            }
        }
    }
    return true;
}

