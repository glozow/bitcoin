// Copyright (c) 2011-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <node/mini_miner.h>
#include <policy/ancestor_packages.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>

#include <deque>

static void AncestorPackageRandom(benchmark::Bench& bench)
{

    FastRandomContext rand{false};
    Package txns;

    int cluster_size = 100;
    if (bench.complexityN() > 1) {
        cluster_size = static_cast<int>(bench.complexityN());
    }

    std::deque<COutPoint> available_coins;
    for (uint32_t i = 0; i < uint32_t{100}; ++i) {
        available_coins.push_back(COutPoint{uint256::ZERO, i});
    }

    for (uint32_t count = cluster_size - 1; !available_coins.empty() && count; --count)
    {
        CMutableTransaction mtx = CMutableTransaction();
        const size_t num_inputs = rand.randrange(available_coins.size()) + 1;
        const size_t num_outputs = rand.randrange(50) + 1;
        for (size_t n{0}; n < num_inputs; ++n) {
            auto prevout = available_coins.front();
            mtx.vin.push_back(CTxIn(prevout, CScript()));
            available_coins.pop_front();
        }
        for (uint32_t n{0}; n < num_outputs; ++n) {
            mtx.vout.push_back(CTxOut(100, P2WSH_OP_TRUE));
        }
        CTransactionRef tx = MakeTransactionRef(mtx);
        txns.push_back(tx);

        // At least one output is available for spending by descendant
        for (uint32_t n{0}; n < num_outputs; ++n) {
            if (n == 0 || rand.randbool()) {
                available_coins.push_back(COutPoint{tx->GetHash(), n});
            }
        }
    }

    assert(!available_coins.empty());

    // Now spend all available coins to make sure it's an ancestor package
    size_t num_coins = available_coins.size();
    CMutableTransaction child_mtx;
    for (size_t avail = 0; avail < num_coins; avail++) {
        auto prevout = available_coins[0];
        child_mtx.vin.push_back(CTxIn(prevout, CScript()));
        available_coins.pop_front();
    }
    child_mtx.vout.push_back(CTxOut(100, P2WSH_OP_TRUE));
    CTransactionRef child_tx = MakeTransactionRef(child_mtx);
    txns.push_back(child_tx);

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        AncestorPackage ancestor_package(txns);
        assert(ancestor_package.IsAncestorPackage());
        for (size_t i = 0; i < txns.size(); i++) {
            ancestor_package.AddFeeAndVsize(txns[i]->GetHash(), rand.randrange(1000000), rand.randrange(1000));
        }
        ancestor_package.LinearizeWithFees();
    });
}

static void AncestorPackageChain(benchmark::Bench& bench)
{
    const uint32_t num_txns{100};
    uint256 starting_txid{uint256::ZERO};
    uint256& last_txid = starting_txid;
    Package txns;
    txns.reserve(num_txns);

    for (uint32_t count{0}; count < 100; ++count)
    {
        CMutableTransaction mtx = CMutableTransaction();
        mtx.vin.push_back(CTxIn(COutPoint{last_txid, 0}, CScript()));
        mtx.vout.push_back(CTxOut(100, P2WSH_OP_TRUE));
        CTransactionRef tx = MakeTransactionRef(mtx);
        txns.emplace_back(tx);
        last_txid = tx->GetHash();
    }

    // Pass the transactions in backwards for worst-case sorting.
    Package reversed_txns(txns.rbegin(), txns.rend());

    bench.minEpochIterations(10).run([&]() NO_THREAD_SAFETY_ANALYSIS {
        AncestorPackage ancestor_package(reversed_txns);
        assert(ancestor_package.IsAncestorPackage());
        for (size_t i = 0; i < txns.size(); ++i) {
            // Decreasing feerate so that "mining" each transaction requires updating all the rest.
            // Make each transaction 100vB bigger than the previous one.
            ancestor_package.AddFeeAndVsize(txns.at(i)->GetHash(), 10000000, 100 * (i + 1));
        }
        ancestor_package.LinearizeWithFees();
    });
}

BENCHMARK(AncestorPackageRandom, benchmark::PriorityLevel::HIGH);
BENCHMARK(AncestorPackageChain, benchmark::PriorityLevel::HIGH);
