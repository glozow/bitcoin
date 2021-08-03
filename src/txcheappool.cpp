// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txcheappool.h>

#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>


bool TxCheapPool::AddTx(const CTransactionRef& tx, NodeId peer)
{
    assert(tx);
    return true;
}
