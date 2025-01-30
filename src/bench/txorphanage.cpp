// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/amount.h>
#include <net.h>
#include <net_processing.h>
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

static void OrphanageEraseForBlockSinglePeer(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};
    unsigned int num_orphans{DEFAULT_MAX_ORPHAN_TRANSACTIONS};
    unsigned int num_outputs{1500};

    // Create big parent with many outputs.
    auto ptx_parent = MakeTransactionSpending({}, /*num_outputs=*/num_outputs, det_rand);
    // Create outpoints vector with all outputs from this tx
    std::vector<COutPoint> outpoints;
    outpoints.reserve(ptx_parent->vout.size());
    for (unsigned int o = 0; o < ptx_parent->vout.size(); ++o) {
        outpoints.emplace_back(ptx_parent->GetHash(), o);
    }
    auto ptx_child_sweep = MakeTransactionSpending(outpoints, /*num_outputs=*/1, det_rand);
    CBlock block;
    block.vtx.push_back(ptx_parent);
    block.vtx.push_back(ptx_child_sweep);

    std::vector<CTransactionRef> child_txns;
    child_txns.reserve(num_orphans);
    for (unsigned int c = 0; c < num_orphans; ++c) {
        std::shuffle(outpoints.begin(), outpoints.end(), det_rand);
        child_txns.emplace_back(MakeTransactionSpending(outpoints, /*num_outputs=*/1, det_rand));
    }

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        TxOrphanage orphanage;

        // Every orphan was provided by the same peer.
        NodeId peer{2};
        for (const auto& orphan : child_txns) {
            Assert(orphanage.AddTx(orphan, peer));
        }
        Assert(orphanage.Size() == num_orphans);

        // Every orphan needs to be deleted because they all conflict with the block.
        orphanage.EraseForBlock(block);
        Assert(orphanage.Size() == 0);
    });
}

BENCHMARK(OrphanageEraseForBlockSinglePeer, benchmark::PriorityLevel::HIGH);
