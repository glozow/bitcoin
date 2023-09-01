// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <validation.h>

constexpr size_t BLOCK_VTX_COUNT{4000};
constexpr size_t BLOCK_VTX_COUNT_10PERCENT{400};

using BlockTxns = decltype(CBlock::vtx);

/** Reorg where 1 block is disconnected and 2 blocks are connected. */
struct ReorgTxns {
    /** Disconnected block. */
    BlockTxns disconnected_txns;
    /** First connected block. */
    BlockTxns connected_txns_1;
    /** Second connected block, new chain tip. Has no overlap with disconnected_txns. */
    BlockTxns connected_txns_2;
    /** Transactions shared between disconnected_txns and connected_txns_1. */
    size_t num_shared;
};

static BlockTxns CreateRandomTransactions(size_t num_txns, uint32_t unique_set_num)
{
    FastRandomContext det_rand{true};
    // The unique_set_num trick won't work otherwise. It assumes that there's a different
    // unique_set_num each time we call CreateRandomTransactions and each batch is <= 4000.
    assert(num_txns <= BLOCK_VTX_COUNT);

    BlockTxns txns;
    txns.reserve(num_txns);
    // Simplest spk for every tx
    CScript spk = CScript() << OP_TRUE;
    for (uint32_t i = 0; i < num_txns; ++i) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        // We should get a different prevout hash every time. But just to be sure, change the index
        // as well to ensure every tx has a different txid.
        tx.vin.emplace_back(CTxIn{COutPoint{det_rand.rand256(), uint32_t(i + BLOCK_VTX_COUNT * unique_set_num)}});
        tx.vout.resize(1);
        tx.vout.emplace_back(CTxOut{CENT, spk});
        txns.emplace_back(MakeTransactionRef(tx));
    }
    return txns;
}

/** Creates 2 blocks with BLOCK_VTX_COUNT transactions each. There will be num_not_shared
 * transactions that are different, all other transactions the exact same. This is to simulate a
 * reorg in which all but num_not_shared transactions are confirmed in the new chain. */
static ReorgTxns CreateBlocks(TestChain100Setup& testing_setup, size_t num_not_shared)
{
    auto num_shared{BLOCK_VTX_COUNT - num_not_shared};
    const auto shared_txns{CreateRandomTransactions(/*num_txns=*/num_shared, /*unique_set_num=*/1)};

    // Create different sets of transactions...
    auto disconnected_block_txns{CreateRandomTransactions(/*num_txns=*/num_not_shared, /*unique_set_num=*/2)};
    std::copy(shared_txns.begin(), shared_txns.end(), std::back_inserter(disconnected_block_txns));

    auto connected_block_txns{CreateRandomTransactions(/*num_txns=*/num_not_shared, /*unique_set_num=*/3)};
    std::copy(shared_txns.begin(), shared_txns.end(), std::back_inserter(connected_block_txns));

    assert(disconnected_block_txns.size() == BLOCK_VTX_COUNT);
    assert(connected_block_txns.size() == BLOCK_VTX_COUNT);

    return ReorgTxns{/*disconnected_txns=*/disconnected_block_txns,
                     /*connected_txns_1=*/connected_block_txns,
                     /*connected_txns_2=*/CreateRandomTransactions(BLOCK_VTX_COUNT, /*unique_set_num=*/4),
                     /*num_shared=*/num_shared};
}

static void Reorg(const ReorgTxns& reorg)
{
    DisconnectedBlockTransactions disconnectpool;
    // Disconnect block
    for (auto it = reorg.disconnected_txns.rbegin(); it != reorg.disconnected_txns.rend(); ++it) {
        disconnectpool.addTransaction(*it);
    }
    assert(disconnectpool.queuedTx.size() == BLOCK_VTX_COUNT);

    disconnectpool.removeForBlock(reorg.connected_txns_1);
    assert(disconnectpool.queuedTx.size() == BLOCK_VTX_COUNT - reorg.num_shared);

    disconnectpool.removeForBlock(reorg.connected_txns_2);
    // No change in the transactions
    assert(disconnectpool.queuedTx.size() == BLOCK_VTX_COUNT - reorg.num_shared);

    // Pop transactions until empty, similar to when re-adding transactions to mempool. This is
    // also necessary to clear the data structures before destruction of disconnectpool.
    while (!disconnectpool.queuedTx.empty()) {
        auto it = disconnectpool.queuedTx.get<insertion_order>().begin();
        disconnectpool.removeEntry(it);
    }
}

/** Add transactions from DisconnectedBlockTransactions, remove all of them, and then pop from the front until empty. */
static void AddAndRemoveDisconnectedBlockTransactionsAll(benchmark::Bench& bench)
{
    auto testing_setup = MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST);
    const auto chains{CreateBlocks(*testing_setup.get(), /*num_not_shared=*/0)};
    assert(chains.num_shared == BLOCK_VTX_COUNT);

    bench.minEpochIterations(10).run([&]() NO_THREAD_SAFETY_ANALYSIS {
        Reorg(chains);
    });
}

/** Add transactions from DisconnectedBlockTransactions, remove 90% of them, and then pop from the front until empty. */
static void AddAndRemoveDisconnectedBlockTransactions90(benchmark::Bench& bench)
{
    auto testing_setup = MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST);
    const auto chains{CreateBlocks(*testing_setup.get(), /*num_not_shared=*/BLOCK_VTX_COUNT_10PERCENT)};
    assert(chains.num_shared == BLOCK_VTX_COUNT - BLOCK_VTX_COUNT_10PERCENT);

    bench.minEpochIterations(10).run([&]() NO_THREAD_SAFETY_ANALYSIS {
        Reorg(chains);
    });
}

/** Add transactions from DisconnectedBlockTransactions, remove 10% of them, and then pop from the front until empty. */
static void AddAndRemoveDisconnectedBlockTransactions10(benchmark::Bench& bench)
{
    auto testing_setup = MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST);
    const auto chains{CreateBlocks(*testing_setup.get(), /*num_not_shared=*/BLOCK_VTX_COUNT - BLOCK_VTX_COUNT_10PERCENT)};
    assert(chains.num_shared == BLOCK_VTX_COUNT_10PERCENT);

    bench.minEpochIterations(10).run([&]() NO_THREAD_SAFETY_ANALYSIS {
        Reorg(chains);
    });
}

BENCHMARK(AddAndRemoveDisconnectedBlockTransactionsAll, benchmark::PriorityLevel::HIGH);
BENCHMARK(AddAndRemoveDisconnectedBlockTransactions90, benchmark::PriorityLevel::HIGH);
BENCHMARK(AddAndRemoveDisconnectedBlockTransactions10, benchmark::PriorityLevel::HIGH);
