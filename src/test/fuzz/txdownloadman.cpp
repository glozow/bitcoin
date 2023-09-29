// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <node/context.h>
#include <node/mempool_args.h>
#include <node/miner.h>
#include <node/txdownloadman.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <util/hasher.h>
#include <util/rbf.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>

using node::NodeContext;

namespace {

const TestingSetup* g_setup;
std::vector<COutPoint> g_available_coins;
std::vector<CTransactionRef> g_transactions;
constexpr int NUM_PEERS = 16;

static CTransactionRef MakeTransactionSpending(const std::vector<COutPoint>& outpoints, size_t num_outputs, bool add_witness)
{
    CMutableTransaction tx;
    // If no outpoints are given, create a random one.
    for (const auto& outpoint : outpoints) {
        tx.vin.emplace_back(CTxIn(outpoint));
    }
    if (add_witness) {
        tx.vin[0].scriptWitness.stack.push_back({1});
    }
    tx.vout.emplace_back(CENT, P2WSH_OP_TRUE);
    return MakeTransactionRef(tx);
}
void initialize()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
    for (uint32_t i = 0; i < uint32_t{50}; ++i) {
        g_available_coins.push_back(COutPoint{(HashWriter() << i).GetHash(), i});
    }
    size_t outpoints_index = 0;
    // 2 parents 1 child
    {
        auto tx_parent_1{MakeTransactionSpending({g_available_coins.at(outpoints_index++)}, /*num_outputs=*/1, /*add_witness=*/true)};
        g_transactions.emplace_back(tx_parent_1);
        auto tx_parent_2{MakeTransactionSpending({g_available_coins.at(outpoints_index++)}, /*num_outputs=*/1, /*add_witness=*/false)};
        g_transactions.emplace_back(tx_parent_2);
        g_transactions.emplace_back(MakeTransactionSpending({COutPoint{tx_parent_1->GetHash(), 0}, COutPoint{tx_parent_2->GetHash(), 0}},
                                                            /*num_outputs=*/1, /*add_witness=*/true));
    }
    // 1 parent 2 children
    {
        auto tx_parent{MakeTransactionSpending({g_available_coins.at(outpoints_index++)}, /*num_outputs=*/2, /*add_witness=*/true)};
        g_transactions.emplace_back(tx_parent);
        g_transactions.emplace_back(MakeTransactionSpending({COutPoint{tx_parent->GetHash(), 0}},
                                                            /*num_outputs=*/1, /*add_witness=*/true));
        g_transactions.emplace_back(MakeTransactionSpending({COutPoint{tx_parent->GetHash(), 1}},
                                                            /*num_outputs=*/1, /*add_witness=*/true));
    }
    // chain of 5 segwit
    {
        COutPoint& last_outpoint = g_available_coins.at(outpoints_index++);
        for (auto i{0}; i < 5; ++i) {
            auto tx{MakeTransactionSpending({last_outpoint}, /*num_outputs=*/1, /*add_witness=*/true)};
            g_transactions.emplace_back(tx);
            last_outpoint = COutPoint{tx->GetHash(), 0};
        }
    }
    // chain of 5 non-segwit
    {
        COutPoint& last_outpoint = g_available_coins.at(outpoints_index++);
        for (auto i{0}; i < 5; ++i) {
            auto tx{MakeTransactionSpending({last_outpoint}, /*num_outputs=*/1, /*add_witness=*/false)};
            g_transactions.emplace_back(tx);
            last_outpoint = COutPoint{tx->GetHash(), 0};
        }
    }
    // Also create a loose tx for each outpoint. Some of these transactions conflict with the above.
    for (const auto& outpoint : g_available_coins) {
        g_transactions.emplace_back(MakeTransactionSpending({outpoint}, /*num_outputs=*/1, /*add_witness=*/true));
    }
}

FUZZ_TARGET(txdownloadman, .init = initialize)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Initialize txdownloadman
    const auto& node = g_setup->m_node;
    CTxMemPool pool{MemPoolOptionsForTest(node)};
    auto max_orphan_txs = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 300);
    node::TxDownloadManager txdownloadman{node::TxDownloadOptions{max_orphan_txs, pool}};

    std::chrono::microseconds time{244466666};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000)
    {
        // Random peer
        NodeId rand_peer = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, NUM_PEERS);
        // One of the preset transactions or a random one
        auto fuzz_tx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
        auto rand_tx = fuzz_tx.has_value() && fuzzed_data_provider.ConsumeBool() ?
            MakeTransactionRef(fuzz_tx.value()) :
            g_transactions.at(fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, g_transactions.size() - 1));

        CallOneOf(
            fuzzed_data_provider,
            [&] {
                node::TxDownloadConnectionInfo info{
                    .m_preferred = fuzzed_data_provider.ConsumeBool(),
                    .m_relay_permissions = fuzzed_data_provider.ConsumeBool(),
                    .m_wtxid_relay = fuzzed_data_provider.ConsumeBool()
                };
                txdownloadman.ConnectedPeer(rand_peer, info);
            },
            [&] {
                txdownloadman.DisconnectedPeer(rand_peer);
            },
            [&] {
                txdownloadman.BlockConnectedSync();
            },
            [&] {
                CBlock block;
                block.vtx.push_back(rand_tx);
                txdownloadman.BlockConnected(block, ConsumeUInt256(fuzzed_data_provider));
            },
            [&] {
                txdownloadman.BlockDisconnected();
            },
            [&] {
                txdownloadman.MempoolAcceptedTx(rand_tx);
            },
            [&] {
                TxValidationResult result = TxValidationResult::TX_MEMPOOL_POLICY;
                // FIXME set to a random value.
                txdownloadman.MempoolRejectedTx(rand_tx, result);
            },
            [&] {
                GenTxid gtxid = fuzzed_data_provider.ConsumeBool() ?
                                GenTxid::Txid(rand_tx->GetHash()) :
                                GenTxid::Wtxid(rand_tx->GetWitnessHash());
                txdownloadman.ReceivedTxInv(rand_peer, gtxid, time);
            },
            [&] {
                txdownloadman.GetRequestsToSend(rand_peer, time);
            },
            [&] {
                txdownloadman.ReceivedTx(rand_peer, rand_tx);
            },
            [&] {
                txdownloadman.ReceivedNotFound(rand_peer, {rand_tx->GetWitnessHash()});
            },
            [&] {
                const auto res = txdownloadman.NewOrphanTx(rand_tx, rand_peer, time);
                if (res.first) {
                    Assert(txdownloadman.AlreadyHaveTx(GenTxid::Wtxid(rand_tx->GetWitnessHash())));
                }
            },
            [&] {
                const auto ptx = txdownloadman.GetTxToReconsider(rand_peer);
                if (ptx) {
                    Assert(txdownloadman.AlreadyHaveTx(GenTxid::Wtxid(ptx->GetWitnessHash())));
                }
            }
        );
        // FIXME: change time
    }
}
} // namespace
