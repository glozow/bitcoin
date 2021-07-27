// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/rbf.h>

#include <primitives/transaction.h>

bool SignalsOptInRBF(const CTransaction &tx)
{
    for (const CTxIn &txin : tx.vin) {
        if (txin.nSequence <= MAX_BIP125_RBF_SEQUENCE) {
            return true;
        }
    }
    return false;
}

bool IsRBFOptOut(const CTransaction& txConflicting)
{
    // Allow opt-out of transaction replacement by setting
    // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
    //
    // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
    // non-replaceable transactions. All inputs rather than just one
    // is for the sake of multi-party protocols, where we don't
    // want a single party to be able to disable replacement.
    //
    // Transactions that don't explicitly signal replaceability are
    // *not* replaceable with the current logic, even if one of their
    // unconfirmed ancestors signals replaceability. This diverges
    // from BIP125's inherited signaling description (see CVE-2021-31876).
    // Applications relying on first-seen mempool behavior should
    // check all unconfirmed ancestors; otherwise an opt-in ancestor
    // might be replaced, causing removal of this descendant.
    for (const CTxIn &_txin : txConflicting.vin) {
        if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE) return false;
    }
    return true;
}
