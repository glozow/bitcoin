// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXCHEAPPOOL_H
#define BITCOIN_TXCHEAPPOOL_H

#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>


/** A class to track transactions that failed for having too low fee. */
class TxCheapPool {

/** Limit the number of entries in the TxCheapPool */
static constexpr int64_t MAX_CHEAP_POOL_ENTRIES{100};

/** Used for internal consistency */
Mutex cs;

public:
    /** Add a new transaction */
    bool AddTx(const CTransactionRef& tx, NodeId peer);

    /** Check if we already have a cheap transaction (by txid or wtxid) */
    bool HaveTx(const GenTxid& gtxid);

protected:
    struct CheapTx {
        CTransactionRef tx;
        CFeeRate feerate;
        NodeId fromPeer;
        int64_t nTimeExpire;
        size_t list_pos;
    };
};

#endif // BITCOIN_TXCHEAPPOOL_H
