// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_CONTRACT_POLICY_H
#define BITCOIN_POLICY_CONTRACT_POLICY_H

#include <consensus/amount.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <txmempool.h>

#include <string>

// This module enforces rules for transactions with nVersion=3 ("V3 transactions") which are
// intended for use in contracting protocols.

/** Maximum virtual size of a tx which spends from a V3 transaction, in vB. */
static constexpr unsigned int V3_CHILD_MAX_SIZE{4000};
/** Maximum number of transactions including a tx and its descendants. */
static constexpr unsigned int V3_DESCENDANT_LIMIT{2};

// Define additional values in case we want V3 ancestor limits to diverge from default ancestor limits.
/** Maximum number of transactions including a tx and all its mempool ancestors. */
static constexpr unsigned int V3_ANCESTOR_LIMIT{DEFAULT_ANCESTOR_LIMIT};
/** Maximum total virtual size of transactions, in KvB, including a tx and all its mempool ancestors. */
static constexpr unsigned int V3_ANCESTOR_SIZE_LIMIT_KVB{DEFAULT_ANCESTOR_SIZE_LIMIT_KVB};


/** Every transaction that spends an unconfirmed V3 transaction must also have V3. */
std::optional<std::string> CheckV3Inheritance(const CTransactionRef& ptx,
                                              const CTxMemPool::setEntries& ancestors)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** Filters the ancestors, returning the ones which are nVersion=3 ("V3 ancestors"). */
CTxMemPool::setEntries GetV3Ancestors(const CTxMemPool::setEntries& ancestors) EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** The following rules apply to V3 transactions:
 * 1. Tx with all of its ancestors (including non-nVersion=3) must be within V3_ANCESTOR_SIZE_LIMIT_KVB.
 * 2. Tx with all of its ancestors must be within V3_ANCESTOR_LIMIT.
 *
 * If a V3 tx has V3 ancestors,
 * 1. Each V3 ancestor and its descendants must be within V3_DESCENDANT_LIMIT.
 * 2. The tx must be within V3_CHILD_MAX_SIZE.
 */
std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& ancestors)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

#endif // BITCOIN_POLICY_CONTRACT_POLICY_H
