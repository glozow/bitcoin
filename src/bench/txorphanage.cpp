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

// Number of peers to use for ManyPeers benchmark. If we use more peers, the benchmark will not work because we will not
// hit the weight limit before the announcement limit. Divide by the approximate number of tiny transactions that will fit in the memory limit.
static constexpr unsigned int TINY_TX_WEIGHT{240};
static constexpr unsigned int NUM_TINY_IN_WEIGHT_LIMIT{node::DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER / TINY_TX_WEIGHT};
static constexpr unsigned int NUM_PEERS_MULTIPLE{node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS / NUM_TINY_IN_WEIGHT_LIMIT};

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
    unsigned int NUM_TINY_TRANSACTIONS((node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS / NUM_PEERS));

    // Hand-picked to be nearly max weight
    unsigned int HUGE_TX_OUTPUTS{11100};

    // Construct transactions to submit to orphanage: 1-in-1-out tiny transactions
    std::vector<CTransactionRef> tiny_txs;
    for (unsigned int peer{0}; peer < NUM_PEERS; peer++) {
        for (unsigned int i{0}; i < NUM_TINY_TRANSACTIONS; ++i) {
            tiny_txns.emplace_back(MakeTransactionSpending(/*num_outputs=*/1, det_rand));
        }
    }

    // Make a large tx for each peer.
    std::vector<CTransactionRef> peer_large_txs;
    int64_t large_tx_save_one{0};
    for (unsigned int peer{0}; peer < NUM_PEERS; peer++) {
        peer_large_txs.emplace_back(MakeTransactionSpending(/*num_outputs=*/HUGE_TX_OUTPUTS, det_rand));

        if (peer > 0) large_tx_save_one += GetTransactionWeight(*peer_large_txs.at(peer));
    }

    // We can fit this many tiny transactions. We want to be just under the weight limit before we add the (last) large transaction.
    // When NUM_PEERS == 1, large_tx_save_one is 0, so we pretty much fill up the whole space with tiny transactions.
    const int64_t total_tiny_tx_space = node::DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER * NUM_PEERS - large_tx_save_one;
    const int64_t total_tiny_tx_space_per_peer = total_tiny_tx_space / NUM_PEERS;

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        const auto orphanage{node::MakeTxOrphanage(/*max_global_ann=*/node::DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS, /*reserved_peer_usage=*/node::DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER)};

        // Populate the orphanage. To maximize the number of evictions, first fill up with tiny transactions, then add a huge one.
        for (unsigned int peer{0}; peer < NUM_PEERS; peer++) {
            // Add tiny transactions until we are just about to hit the memory limit, up to the max number of announcements.
            // We use the same tiny transactions for all peers to minimize their contribution to the usage limit.
            int64_t total_weight_to_add{0};
            for (unsigned int txindex{0}; txindex < NUM_TINY_TRANSACTIONS; ++txindex) {
                const auto& tx{tiny_txs.at(txindex)};

                total_weight_to_add += GetTransactionWeight(*tx);
                if (total_weight_to_add > total_tiny_tx_space_per_peer) break;

                assert(orphanage->AddTx(tx, peer));
                // In the real world, we always call LimitOrphans() after each AddTx().
                // If we need to trim here, that means the benchmark is not representative of what LimitOrphans may do in a single call.
                assert(!orphanage->NeedsTrim());

                // Sanity check: we should always be exiting at the point of hitting the weight limit.
                assert(txindex < NUM_TINY_TRANSACTIONS - 1);
            }
            // Then add the large transaction (all but 1 of the peers).
            if (peer > 0) assert(orphanage->AddTx(peer_large_txs.at(peer), peer));
        }

        // We should be just under the weight limit. There are small gaps for each peer, up to the size of 1 tiny transaction.
        assert(orphanage->TotalOrphanUsage() < orphanage->MaxGlobalUsage());
        assert(orphanage->TotalOrphanUsage() + NUM_PEERS * TINY_TX_WEIGHT > orphanage->MaxGlobalUsage());

        // Lastly, add peer0's large transaction.
        assert(orphanage->AddTx(peer_large_txs.at(0), 0));

        // We are now oversized in weight, by approximately the size of 1 large transaction.
        assert(orphanage->NeedsTrim());

        const auto num_announcements_before_trim{orphanage->CountAnnouncements()};
        if (trim) {
            // If there are multiple peers, note that they all have the same DoS score. We will evict only 1 item at a time for each new DoSiest peer.
            orphanage->LimitOrphans();
            assert(!orphanage->NeedsTrim());
            const auto num_announcements_after_trim{orphanage->CountAnnouncements()};
            const auto num_evicted{num_announcements_before_trim - num_announcements_after_trim};

            // The number of evictions is the same regardless of the number of peers. In both cases, we can exceed the
            // usage limit using 1 maximally-sized transaction.
            assert(num_evicted <= 1700);
            assert(num_evicted >= 1600);
        }
    });
}

static void OrphanageEvictionManyWithOnePeer(benchmark::Bench& bench)
{
    OrphanageEvictionMany(1, true, bench);
}

static void OrphanageEvictionManyWithManyPeers(benchmark::Bench& bench)
{
    OrphanageEvictionMany(NUM_PEERS_MULTIPLE, true, bench);
}

static void OrphanageManyWithOnePeer(benchmark::Bench& bench)
{
    OrphanageEvictionMany(1, false, bench);
}

static void OrphanageManyWithManyPeers(benchmark::Bench& bench)
{
    OrphanageEvictionMany(NUM_PEERS_MULTIPLE, false, bench);
}

BENCHMARK(OrphanageEvictionManyWithOnePeer, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageEvictionManyWithManyPeers, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageManyWithOnePeer, benchmark::PriorityLevel::HIGH);
BENCHMARK(OrphanageManyWithManyPeers, benchmark::PriorityLevel::HIGH);
