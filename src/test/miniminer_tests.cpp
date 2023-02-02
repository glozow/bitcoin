// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <node/mini_miner.h>
#include <txmempool.h>
#include <util/system.h>
#include <util/time.h>

#include <test/util/setup_common.h>
#include <test/util/txmempool.h>

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

static inline bool sanity_check(const std::vector<CTransactionRef>& transactions,
                                const std::map<COutPoint, CAmount>& bumpfees)
{
    // No negative bumpfees.
    for (const auto& [outpoint, fee] : bumpfees) {
        if (fee < 0) return false;
    }
    for (const auto& tx : transactions) {
        // If tx has 2 outputs, they must have the same bumpfee.
        if (tx->vout.size() > 1) {
            const auto bumpfee0 = bumpfees.find(COutPoint{tx->GetHash(), 0});
            const auto bumpfee1 = bumpfees.find(COutPoint{tx->GetHash(), 1});
            if (bumpfee0 != bumpfees.end() && bumpfee1 != bumpfees.end() &&
                bumpfee0->second != bumpfee1->second) return false;
        }
    }
    return true;
}

BOOST_FIXTURE_TEST_CASE(miniminer, TestChain100Setup)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    const CAmount low_fee{CENT/2000};
    const CAmount normal_fee{CENT/200};
    const CAmount high_fee{CENT/10};

    // Create mempool entries. The actual input and output values of these transactions don't really
    // matter, since all accounting will use the entries' cached fees.

    // Create a parent tx1 and child tx2 with normal fees:
    const auto tx1 = make_tx(/*inputs=*/ {m_coinbase_txns[0]}, /*output_values=*/ {COIN, COIN});
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx1));
    const auto tx2 = make_tx(/*inputs=*/ {tx1}, /*output_values=*/ {COIN});
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx2));

    // Create a low-feerate parent tx3 and high-feerate child tx4 (cpfp)
    const auto tx3 = make_tx(/*inputs=*/ {m_coinbase_txns[1]}, /*output_values=*/ {COIN, COIN});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx3));
    const auto tx4 = make_tx(/*inputs=*/ {tx3}, /*output_values=*/ {COIN});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx4));

    // Create a parent tx5 and child tx6 where both have very low fees
    const auto tx5 = make_tx(/*inputs=*/ {m_coinbase_txns[2]}, /*output_values=*/ {COIN, COIN});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx5));
    const auto tx6 = make_tx(/*inputs=*/ {tx5}, /*output_values=*/ {COIN});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx6));
    // Make tx6's modified fee much higher than its base fee. This should cause it to pass
    // the fee-related checks despite being low-feerate.
    pool.PrioritiseTransaction(tx6->GetHash(), COIN);

    // Create a high-feerate parent tx7, low-feerate child tx8, high-feerate grandchild tx9
    const auto tx7 = make_tx(/*inputs=*/ {m_coinbase_txns[3]}, /*output_values=*/ {COIN, COIN});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx7));
    const auto tx8 = make_tx(/*inputs=*/ {tx7}, /*output_values=*/ {COIN, COIN});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx8));
    const auto tx9 = make_tx(/*inputs=*/ {tx8}, /*output_values=*/ {COIN});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx9));

    std::vector<COutPoint> all_unspent_outpoints({
        COutPoint{tx1->GetHash(), 1},
        COutPoint{tx2->GetHash(), 0},
        COutPoint{tx3->GetHash(), 1},
        COutPoint{tx4->GetHash(), 0},
        COutPoint{tx5->GetHash(), 1},
        COutPoint{tx6->GetHash(), 0},
        COutPoint{tx7->GetHash(), 1},
        COutPoint{tx8->GetHash(), 1},
        COutPoint{tx9->GetHash(), 0}
    });
    for (const auto& outpoint : all_unspent_outpoints) BOOST_CHECK(!pool.isSpent(outpoint));

    std::vector<COutPoint> all_spent_outpoints({
        COutPoint{tx1->GetHash(), 0},
        COutPoint{tx3->GetHash(), 0},
        COutPoint{tx5->GetHash(), 0},
        COutPoint{tx7->GetHash(), 0},
        COutPoint{tx8->GetHash(), 0}
    });
    for (const auto& outpoint : all_spent_outpoints) BOOST_CHECK(pool.GetConflictTx(outpoint) != nullptr);

    std::vector<COutPoint> all_parent_outputs({
        COutPoint{tx1->GetHash(), 0},
        COutPoint{tx1->GetHash(), 1},
        COutPoint{tx3->GetHash(), 0},
        COutPoint{tx3->GetHash(), 1},
        COutPoint{tx5->GetHash(), 0},
        COutPoint{tx5->GetHash(), 1},
        COutPoint{tx7->GetHash(), 0},
        COutPoint{tx7->GetHash(), 1}
    });

    std::vector<COutPoint> nonexistent_outpoints({ COutPoint{GetRandHash(), 0}, COutPoint{GetRandHash(), 3} });
    for (const auto& outpoint : nonexistent_outpoints) BOOST_CHECK(!pool.isSpent(outpoint));

    std::vector<CTransactionRef> all_transactions{tx1, tx2, tx3, tx4, tx5, tx6, tx7, tx8, tx9};
    std::vector<CTxMemPool::txiter> all_entries;
    std::map<uint256, int64_t> tx_vsizes;
    std::map<uint256, CAmount> tx_modified_fees;
    std::map<uint256, CFeeRate> tx_feerates;
    for (const auto& tx : all_transactions) {
        const auto entry = pool.GetIter(tx->GetHash()).value();
        all_entries.push_back(entry);
        tx_vsizes.emplace(tx->GetHash(), entry->GetTxSize());
        tx_modified_fees.emplace(tx->GetHash(), entry->GetModifiedFee());
        tx_feerates.emplace(tx->GetHash(), CFeeRate(entry->GetModifiedFee(), entry->GetTxSize()));
    }

    const CFeeRate zero_feerate(0);
    const CFeeRate low_feerate(1000);
    const CFeeRate normal_feerate(20000);
    const CFeeRate high_feerate(100 * COIN);
    const std::vector<CFeeRate> various_feerates({zero_feerate, low_feerate, normal_feerate, high_feerate});
    const std::vector<CFeeRate> various_normal_feerates({CFeeRate(10), CFeeRate(500), CFeeRate(999),
                                                         CFeeRate(1000), CFeeRate(2000), CFeeRate(2500),
                                                         CFeeRate(3333), CFeeRate(7800), CFeeRate(11199),
                                                         CFeeRate(23330), CFeeRate(50000), CFeeRate(CENT)});

    // All nonexistent entries have a bumpfee of zero, regardless of feerate
    {
        for (const auto& feerate : various_feerates) {
            node::MiniMiner mini_miner(pool, nonexistent_outpoints);
            auto bump_fees = mini_miner.CalculateBumpFees(feerate);
            BOOST_CHECK(sanity_check(all_transactions, bump_fees));
            BOOST_CHECK(bump_fees.size() == nonexistent_outpoints.size());
            for (const auto& outpoint: nonexistent_outpoints) {
                auto it = bump_fees.find(outpoint);
                BOOST_CHECK(it != bump_fees.end());
                BOOST_CHECK_EQUAL(it->second, 0);
            }
        }
    }
    // Unpsent
    {
        for (const auto& target_feerate : various_feerates) {
            node::MiniMiner mini_miner(pool, all_unspent_outpoints);
            auto bump_fees = mini_miner.CalculateBumpFees(target_feerate);
            BOOST_CHECK(sanity_check(all_transactions, bump_fees));
            BOOST_CHECK_EQUAL(bump_fees.size(), all_unspent_outpoints.size());
            // Check tx1 bumpfee: no other bumper.
            const auto tx1_feerate = tx_feerates.find(tx1->GetHash())->second;
            auto it1_unspent = bump_fees.find(COutPoint{tx1->GetHash(), 1});
            BOOST_CHECK(it1_unspent != bump_fees.end());
            if (target_feerate <= tx1_feerate) {
                BOOST_CHECK_EQUAL(it1_unspent->second, 0);
            } else {
                // Difference is fee to bump tx1 from current to target feerate. 
                BOOST_CHECK_EQUAL(it1_unspent->second,
                    target_feerate.GetFee(tx_vsizes.find(tx1->GetHash())->second) - tx_modified_fees.find(tx1->GetHash())->second);
            }
            // Check tx3 bumpfee: assisted by tx4.
            const auto tx3_feerate = CFeeRate(
                tx_modified_fees.find(tx3->GetHash())->second + tx_modified_fees.find(tx4->GetHash())->second,
                tx_vsizes.find(tx3->GetHash())->second + tx_vsizes.find(tx4->GetHash())->second);
            auto it3_unspent = bump_fees.find(COutPoint{tx3->GetHash(), 1});
            BOOST_CHECK(it3_unspent != bump_fees.end());
            if (target_feerate <= tx3_feerate) {
                // As long as target feerate is below tx4's ancestor feerate, there is no bump fee.
                BOOST_CHECK_EQUAL(it3_unspent->second, 0);
            } else {
                // Difference is fee to bump tx3 from current to target feerate, without tx4.
                BOOST_CHECK_EQUAL(it3_unspent->second,
                    target_feerate.GetFee(tx_vsizes.find(tx3->GetHash())->second) - tx_modified_fees.find(tx3->GetHash())->second);
        }
            // Check tx5 bumpfee: assisted by tx6. Specifically, tx6's modified fees.
            const auto tx5_feerate = CFeeRate(
                tx_modified_fees.find(tx5->GetHash())->second + tx_modified_fees.find(tx6->GetHash())->second,
                tx_vsizes.find(tx5->GetHash())->second + tx_vsizes.find(tx6->GetHash())->second);
            auto it5_unspent = bump_fees.find(COutPoint{tx5->GetHash(), 1});
            /* BOOST_CHECK(it5_unspent != bump_fees.end()); */
            if (target_feerate <= tx5_feerate) {
                // As long as target feerate is below tx4's ancestor feerate, there is no bump fee.
                BOOST_CHECK_EQUAL(it5_unspent->second, 0);
            } else {
                // Difference is fee to bump tx5 from current to target feerate, without tx6.
                BOOST_CHECK_EQUAL(it5_unspent->second,
                    target_feerate.GetFee(tx_vsizes.find(tx5->GetHash())->second) - tx_modified_fees.find(tx5->GetHash())->second);
            }
        }
    }
    // Spent outpoints should usually not be requested as they would not be
    // considered available. However, when they are explicitly requested, we
    // can calculate their bumpfee to facilitate RBF-replacements
    {
        for (const auto& target_feerate : various_feerates) {
            node::MiniMiner mini_miner(pool, all_parent_outputs);
            auto bump_fees = mini_miner.CalculateBumpFees(target_feerate);
            // PANIK
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
