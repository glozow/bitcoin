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
#include <node/txorphanage.h>
#include <util/check.h>

#include <cstdint>
#include <memory>

// Creates a transaction spending outpoints (or 1 randomly generated input if none are given), with num_outputs outputs.
static CTransactionRef MakeTransactionSpending(unsigned int num_outputs, FastRandomContext& det_rand)
{
    CMutableTransaction tx;

    tx.vin.emplace_back(Txid::FromUint256(det_rand.rand256()), 0);

    assert(num_outputs > 0);
    tx.vout.resize(num_outputs);
    for (unsigned int o = 0; o < num_outputs; ++o) {
        tx.vout[o].nValue = 0;
        tx.vout[o].scriptPubKey = CScript();
    }
    return MakeTransactionRef(tx);
}

static void OrphanageEvictionMany(int num_peers, bool trim, benchmark::Bench& bench)
{
    NodeId NUM_PEERS{num_peers};

    FastRandomContext det_rand{true};

    // Each peer fills up their announcements slots with tiny txns, followed by a single large one
    unsigned int NUM_TINY_TRANSACTIONS((node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS / NUM_PEERS) - 1);

    // Hand-picked to be nearly max weight
    unsigned int HUGE_TX_OUTPUTS{11100};

    // Construct transactions to submit to orphanage: 1-in-1-out tiny transactions
    std::vector<std::vector<CTransactionRef>> peer_tiny_txs;
    for (unsigned int peer{0}; peer < NUM_PEERS; peer++) {
        std::vector<CTransactionRef> tiny_txns;
        for (unsigned int i{0}; i < NUM_TINY_TRANSACTIONS; ++i) {
            tiny_txns.emplace_back(MakeTransactionSpending(/*num_outputs=*/1, det_rand));
        }
        peer_tiny_txs.push_back(tiny_txns);
    }

    std::vector<CTransactionRef> peer_large_txs;
    for (unsigned int peer{0}; peer < NUM_PEERS; peer++) {
            peer_large_txs.emplace_back(MakeTransactionSpending(/*num_outputs=*/HUGE_TX_OUTPUTS, det_rand));
    }

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        const auto orphanage{node::MakeTxOrphanage(/*max_global_ann=*/node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS, /*reserved_peer_usage=*/node::DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER)};

        // Populate the orphanage
        for (unsigned int peer{0}; peer < NUM_PEERS; peer++) {
            for (unsigned int txindex{0}; txindex < NUM_TINY_TRANSACTIONS; ++txindex) {
                assert(orphanage->AddTx(peer_tiny_txs.at(peer).at(txindex), peer));
            }
            assert(orphanage->AddTx(peer_large_txs.at(peer), peer));
        }
        // Should be oversized in weight after last huge tx
        // though it became oversized earlier
        assert(orphanage->CountAnnouncements() == node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS);
        assert(orphanage->NeedsTrim());

        if (trim) {
            orphanage->LimitOrphans();
            assert(!orphanage->NeedsTrim());
            if (NUM_PEERS == 125) {
                // If ~18 txns don't get evicted in 1 peer scenario, ~18*125=2250 won't in 125 peer scenario?
                assert(orphanage->CountAnnouncements() == node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS - 694);
            } else if (NUM_PEERS == 1) {
                assert(orphanage->CountAnnouncements() == node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS - 2982);
            }
        }
    });
}

static void OrphanageEvictionManyWithOnePeer(benchmark::Bench& bench)
{
    OrphanageEvictionMany(1, true, bench);
}

static void OrphanageEvictionManyWithManyPeers(benchmark::Bench& bench)
{
    OrphanageEvictionMany(125, true, bench);
}

static void OrphanageManyWithOnePeer(benchmark::Bench& bench)
{
    OrphanageEvictionMany(1, false, bench);
}

static void OrphanageManyWithManyPeers(benchmark::Bench& bench)
{
    OrphanageEvictionMany(125, false, bench);
}

BENCHMARK(OrphanageEvictionManyWithOnePeer, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageEvictionManyWithManyPeers, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageManyWithOnePeer, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageManyWithManyPeers, benchmark::PriorityLevel::HIGH);
