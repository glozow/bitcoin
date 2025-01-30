// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/amount.h>
#include <net.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/sign.h>
#include <test/util/setup_common.h>
#include <txorphanage.h>
#include <util/check.h>

#include <cstdint>
#include <memory>

// Creates a transaction spending outpoints (or 1 randomly generated input if none are given), with num_outputs outputs.
static CTransactionRef MakeTransactionSpending(const std::vector<COutPoint>& outpoints, unsigned int num_outputs, FastRandomContext& det_rand)
{
    CMutableTransaction tx;

    // Build vin
    // If no outpoints are given, create a random one.
    if (outpoints.empty()) {
        tx.vin.emplace_back(Txid::FromUint256(det_rand.rand256()), 0);
    } else {
        for (const auto& outpoint : outpoints) {
            tx.vin.emplace_back(outpoint);
        }
    }
    // Ensure txid != wtxid
    assert(tx.vin.size() > 0);
    tx.vin[0].scriptWitness.stack.push_back({1});

    // Build vout
    assert(num_outputs > 0);
    tx.vout.resize(num_outputs);
    for (unsigned int o = 0; o < num_outputs; ++o) {
        tx.vout[o].nValue = det_rand.randrange(100) * CENT;
        tx.vout[o].scriptPubKey = CScript() << CScriptNum(det_rand.randrange(o + 100)) << OP_EQUAL;
    }
    return MakeTransactionRef(tx);
}

static void OrphanageEvictionMany(benchmark::Bench& bench)
{
    NodeId NUM_PEERS{125};
    unsigned int NUM_TRANSACTIONS(DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS / NUM_PEERS);

    FastRandomContext det_rand{true};

    // Construct transactions to submit to orphanage: 1-in-1-out tiny transactions
    std::vector<CTransactionRef> txns;
    txns.reserve(NUM_TRANSACTIONS);
    for (unsigned int i{0}; i < NUM_TRANSACTIONS; ++i) {
        txns.emplace_back(MakeTransactionSpending({}, /*num_outputs=*/1, det_rand));
    }

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        TxOrphanage orphanage;
        for (unsigned int i{0}; i < NUM_TRANSACTIONS; ++i) {
            orphanage.AddTx(txns.at(i), i % NUM_PEERS);
        }
        assert(orphanage.Size() == NUM_TRANSACTIONS);
        orphanage.LimitOrphans(0, det_rand);
    });
}

static void OrphanageWorksetMany(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};

    // Create many orphans spending the same output from 1 transaction.
    auto ptx_parent = MakeTransactionSpending({}, /*num_outputs=*/1, det_rand);
    unsigned int num_orphans{DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS};
    std::vector<CTransactionRef> child_txns;
    child_txns.reserve(num_orphans);
    for (unsigned int c = 0; c < num_orphans; ++c) {
        child_txns.emplace_back(MakeTransactionSpending({{ptx_parent->GetHash(), 0}}, /*num_outputs=*/1, det_rand));
    }

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        TxOrphanage orphanage;

        // There is only 1 peer who provided all the orphans.
        for (const auto& orphan : child_txns) {
            orphanage.AddTx(orphan, 1);
        }

        // Every orphan spends ptx_parent, so they all need to be added to the peer's workset
        orphanage.AddChildrenToWorkSet(*ptx_parent, det_rand);
    });
}

static void OrphanageWorkset(benchmark::Bench& bench)
{
    NodeId NUM_PEERS{120};

    FastRandomContext det_rand{true};

    // Create big parent with many outputs.
    unsigned int num_outputs = 500;
    auto ptx_parent = MakeTransactionSpending({}, num_outputs, det_rand);
    // Create outpoints vector with all outputs from this tx
    std::vector<COutPoint> outpoints;
    outpoints.reserve(ptx_parent->vout.size());
    for (unsigned int o = 0; o < ptx_parent->vout.size(); ++o) {
        outpoints.emplace_back(ptx_parent->GetHash(), o);
    }

    unsigned int num_orphans = DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS / NUM_PEERS;
    std::vector<CTransactionRef> child_txns;
    child_txns.reserve(num_orphans);
    for (unsigned int c = 0; c < num_orphans; ++c) {
        std::shuffle(outpoints.begin(), outpoints.end(), det_rand);
        child_txns.emplace_back(MakeTransactionSpending(outpoints, /*num_outputs=*/1, det_rand));
    }

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        TxOrphanage orphanage;

        // Every orphan was provided by every peer.
        for (const auto& orphan : child_txns) {
            for (NodeId peer = 0; peer < NUM_PEERS; ++peer) {
                orphanage.AddTx(orphan, peer);
            }
        }

        // Every orphan spends ptx_parent, so they all need to be added to some peer's workset.
        orphanage.AddChildrenToWorkSet(*ptx_parent, det_rand);
    });
}

BENCHMARK(OrphanageEvictionMany, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageWorksetMany, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageWorkset, benchmark::PriorityLevel::HIGH);
