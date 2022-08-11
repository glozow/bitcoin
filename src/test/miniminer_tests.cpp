// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <node/mini_miner.h>
#include <txmempool.h>
#include <util/system.h>
#include <util/time.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <optional>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(miniminer_tests, TestingSetup)

static inline CTransactionRef make_tx(const std::vector<CTransactionRef>& inputs,
                                      const std::vector<CAmount>& output_values)
{
    CMutableTransaction tx = CMutableTransaction();
    tx.vin.resize(inputs.size());
    tx.vout.resize(output_values.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        tx.vin[i].prevout.hash = inputs[i]->GetHash();
        tx.vin[i].prevout.n = 0;
        // Add a witness so wtxid != txid
        CScriptWitness witness;
        witness.stack.push_back(std::vector<unsigned char>(i + 10));
        tx.vin[i].scriptWitness = witness;
    }
    for (size_t i = 0; i < output_values.size(); ++i) {
        tx.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        tx.vout[i].nValue = output_values[i];
    }
    return MakeTransactionRef(tx);
}

BOOST_FIXTURE_TEST_CASE(miniminer, TestChain100Setup)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    const CAmount low_fee{CENT/100};
    const CAmount normal_fee{CENT/10};
    const CAmount high_fee{CENT};

    // Create a parent tx1 and child tx2 with normal fees:
    const auto tx1 = make_tx(/*inputs=*/ {m_coinbase_txns[0]}, /*output_values=*/ {10 * COIN, 10 * COIN});
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx1));
    const auto tx2 = make_tx(/*inputs=*/ {tx1}, /*output_values=*/ {995 * CENT});
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx2));

    // Create a low-feerate parent tx3 and high-feerate child tx4 (cpfp)
    const auto tx3 = make_tx(/*inputs=*/ {m_coinbase_txns[1]}, /*output_values=*/ {1099 * CENT, 800 * CENT});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx3));
    const auto tx4 = make_tx(/*inputs=*/ {tx3}, /*output_values=*/ {999 * CENT});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx4));

    // Create a parent tx5 and child tx6 where both have very low fees
    const auto tx5 = make_tx(/*inputs=*/ {m_coinbase_txns[2]}, /*output_values=*/ {1099 * CENT});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx5));
    const auto tx6 = make_tx(/*inputs=*/ {tx5}, /*output_values=*/ {1098 * CENT});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx6));
    // Make tx6's modified fee much higher than its base fee. This should cause it to pass
    // the fee-related checks despite being low-feerate.
    pool.PrioritiseTransaction(tx6->GetHash(), 1 * COIN);

    // Two independent high-feerate transactions, tx7 and tx8
    const auto tx7 = make_tx(/*inputs=*/ {m_coinbase_txns[3]}, /*output_values=*/ {999 * CENT, 99 * CENT});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx7));
    const auto tx8 = make_tx(/*inputs=*/ {m_coinbase_txns[4]}, /*output_values=*/ {999 * CENT, 50 * CENT});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx8));

    std::vector<COutPoint> all_unspent_outpoints({
        COutPoint{tx1->GetHash(), 1},
        COutPoint{tx2->GetHash(), 0},
        COutPoint{tx3->GetHash(), 1},
        COutPoint{tx4->GetHash(), 0},
        COutPoint{tx6->GetHash(), 0},
        COutPoint{tx7->GetHash(), 0},
        COutPoint{tx8->GetHash(), 0}
    });
    for (const auto& outpoint : all_unspent_outpoints) BOOST_CHECK(!pool.isSpent(outpoint));

    std::vector<COutPoint> all_spent_outpoints({
        COutPoint{tx1->GetHash(), 0},
        COutPoint{tx3->GetHash(), 0},
        COutPoint{tx5->GetHash(), 0}
    });
    for (const auto& outpoint : all_spent_outpoints) BOOST_CHECK(pool.GetConflictTx(outpoint) != nullptr);

    std::vector<COutPoint> nonexistent_outpoints({ COutPoint{GetRandHash(), 0}, COutPoint{GetRandHash(), 3} });
    for (const auto& outpoint : nonexistent_outpoints) BOOST_CHECK(!pool.isSpent(outpoint));

    const auto entry1 = pool.GetIter(tx1->GetHash()).value();
    const auto entry2 = pool.GetIter(tx2->GetHash()).value();
    const auto entry3 = pool.GetIter(tx3->GetHash()).value();
    const auto entry4 = pool.GetIter(tx4->GetHash()).value();
    const auto entry5 = pool.GetIter(tx5->GetHash()).value();
    const auto entry6 = pool.GetIter(tx6->GetHash()).value();
    const auto entry7 = pool.GetIter(tx7->GetHash()).value();
    const auto entry8 = pool.GetIter(tx8->GetHash()).value();

    BOOST_CHECK_EQUAL(entry1->GetFee(), normal_fee);
    BOOST_CHECK_EQUAL(entry2->GetFee(), normal_fee);
    BOOST_CHECK_EQUAL(entry3->GetFee(), low_fee);
    BOOST_CHECK_EQUAL(entry4->GetFee(), high_fee);
    BOOST_CHECK_EQUAL(entry5->GetFee(), low_fee);
    BOOST_CHECK_EQUAL(entry6->GetFee(), low_fee);
    BOOST_CHECK_EQUAL(entry7->GetFee(), high_fee);
    BOOST_CHECK_EQUAL(entry8->GetFee(), high_fee);

    CTxMemPool::setEntries all_entries{entry1, entry2, entry3, entry4, entry5, entry6, entry7, entry8};
    const CFeeRate zero_feerate(0);
    const CFeeRate low_feerate(1);
    const CFeeRate normal_feerate(10);
    const CFeeRate high_feerate(100 * COIN);
    const std::vector<CFeeRate> various_feerates({zero_feerate, low_feerate, normal_feerate, high_feerate});

    // All nonexistent entries have a bumpfee of zero, regardless of feerate
    {
        for (const auto& feerate : various_feerates) {
            node::MiniMiner mini_miner(pool, nonexistent_outpoints);
            auto bump_fees = mini_miner.CalculateBumpFees(feerate);
            BOOST_CHECK(bump_fees.size() == nonexistent_outpoints.size());
            for (const auto& outpoint: nonexistent_outpoints) {
                auto it = bump_fees.find(outpoint);
                BOOST_CHECK(it != bump_fees.end());
                BOOST_CHECK_EQUAL(it->second, 0);
            }
        }
    }
    // All conflicting entries and their descendants have a bumpfee of zero, regardless of feerate
    {
        for (const auto& feerate : various_feerates) {
            node::MiniMiner mini_miner(pool, all_spent_outpoints);
            auto bump_fees = mini_miner.CalculateBumpFees(feerate);
            BOOST_CHECK_MESSAGE(bump_fees.size() == all_spent_outpoints.size(), "bumpfee size = " << bump_fees.size());
            for (const auto& outpoint: all_spent_outpoints) {
                auto it = bump_fees.find(outpoint);
                BOOST_CHECK(it != bump_fees.end());
                BOOST_CHECK_EQUAL(it->second, 0);
            }
        }
    }

    // Target feerate of 0: everything should have a bump fee of 0
    {
        node::MiniMiner mini_miner(pool, all_unspent_outpoints);
        auto bump_fees = mini_miner.CalculateBumpFees(zero_feerate);
        BOOST_CHECK(bump_fees.size() == all_unspent_outpoints.size());
        for (const auto& outpoint: all_unspent_outpoints) {
            auto it = bump_fees.find(outpoint);
            BOOST_CHECK(it != bump_fees.end());
            BOOST_CHECK_EQUAL(it->second, 0);
        }
    }
    // Target feerate high: everything should have a pretty big bump fee
    {
        node::MiniMiner mini_miner(pool, all_unspent_outpoints);
        auto bump_fees = mini_miner.CalculateBumpFees(high_feerate);
        BOOST_CHECK(bump_fees.size() == all_unspent_outpoints.size());
        for (const auto& outpoint: all_unspent_outpoints) {
            auto it = bump_fees.find(outpoint);
            BOOST_CHECK(it != bump_fees.end());
            BOOST_CHECK(it->second > 0);
            BOOST_CHECK(it->second < high_feerate.GetFee(500));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
