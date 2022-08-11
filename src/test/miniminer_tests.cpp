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

static inline CTransactionRef make_tx(const std::vector<COutPoint>& inputs, size_t num_outputs)
{
    CMutableTransaction tx = CMutableTransaction();
    tx.vin.resize(inputs.size());
    tx.vout.resize(num_outputs);
    for (size_t i = 0; i < inputs.size(); ++i) {
        tx.vin[i].prevout = inputs[i];
        // Add a witness so wtxid != txid
        CScriptWitness witness;
        witness.stack.push_back(std::vector<unsigned char>(i + 10));
        tx.vin[i].scriptWitness = witness;
    }
    for (size_t i = 0; i < num_outputs; ++i) {
        tx.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        // The actual input and output values of these transactions don't really
        // matter, since all accounting will use the entries' cached fees.
        tx.vout[i].nValue = COIN;
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
        // If tx has multiple outputs, they must all have the same bumpfee (if they exist).
        if (tx->vout.size() > 1) {
            std::set<CAmount> distinct_bumpfees;
            for (size_t i{0}; i < tx->vout.size(); ++i) {
                const auto bumpfee = bumpfees.find(COutPoint{tx->GetHash(), static_cast<uint32_t>(i)});
                if (bumpfee != bumpfees.end()) distinct_bumpfees.insert(bumpfee->second);
            }
            if (distinct_bumpfees.size() > 1) return false;
        }
    }
    return true;
}

BOOST_FIXTURE_TEST_CASE(miniminer_1p1c, TestChain100Setup)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    const CAmount low_fee{CENT/2000};
    const CAmount normal_fee{CENT/200};
    const CAmount high_fee{CENT/10};

    // Create a parent tx1 and child tx2 with normal fees:
    const auto tx1 = make_tx({COutPoint{m_coinbase_txns[0]->GetHash(), 0}}, /*num_outpus=*/2);
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx1));
    const auto tx2 = make_tx({COutPoint{tx1->GetHash(), 0}}, /*num_outputs=*/1);
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx2));

    // Create a low-feerate parent tx3 and high-feerate child tx4 (cpfp)
    const auto tx3 = make_tx({COutPoint{m_coinbase_txns[1]->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx3));
    const auto tx4 = make_tx({COutPoint{tx3->GetHash(), 0}}, /*num_outputs=*/1);
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx4));

    // Create a parent tx5 and child tx6 where both have very low fees
    const auto tx5 = make_tx({COutPoint{m_coinbase_txns[2]->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx5));
    const auto tx6 = make_tx({COutPoint{tx5->GetHash(), 0}}, /*num_outputs=*/1);
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx6));
    // Make tx6's modified fee much higher than its base fee. This should cause it to pass
    // the fee-related checks despite being low-feerate.
    pool.PrioritiseTransaction(tx6->GetHash(), COIN);

    // Create a high-feerate parent tx7, low-feerate child tx8
    const auto tx7 = make_tx({COutPoint{m_coinbase_txns[3]->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx7));
    const auto tx8 = make_tx({COutPoint{tx7->GetHash(), 0}}, /*num_outputs=*/1);
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx8));

    std::vector<COutPoint> all_unspent_outpoints({
        COutPoint{tx1->GetHash(), 1},
        COutPoint{tx2->GetHash(), 0},
        COutPoint{tx3->GetHash(), 1},
        COutPoint{tx4->GetHash(), 0},
        COutPoint{tx5->GetHash(), 1},
        COutPoint{tx6->GetHash(), 0},
        COutPoint{tx7->GetHash(), 1},
        COutPoint{tx8->GetHash(), 0}
    });
    for (const auto& outpoint : all_unspent_outpoints) BOOST_CHECK(!pool.isSpent(outpoint));

    std::vector<COutPoint> all_spent_outpoints({
        COutPoint{tx1->GetHash(), 0},
        COutPoint{tx3->GetHash(), 0},
        COutPoint{tx5->GetHash(), 0},
        COutPoint{tx7->GetHash(), 0}
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


    std::vector<CTransactionRef> all_transactions{tx1, tx2, tx3, tx4, tx5, tx6, tx7, tx8};
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

    const std::vector<CFeeRate> various_normal_feerates({CFeeRate(0), CFeeRate(500), CFeeRate(999),
                                                         CFeeRate(1000), CFeeRate(2000), CFeeRate(2500),
                                                         CFeeRate(3333), CFeeRate(7800), CFeeRate(11199),
                                                         CFeeRate(23330), CFeeRate(50000), CFeeRate(CENT)});

    // All nonexistent entries have a bumpfee of zero, regardless of feerate
    std::vector<COutPoint> nonexistent_outpoints({ COutPoint{GetRandHash(), 0}, COutPoint{GetRandHash(), 3} });
    for (const auto& outpoint : nonexistent_outpoints) BOOST_CHECK(!pool.isSpent(outpoint));
    for (const auto& feerate : various_normal_feerates) {
        node::MiniMiner mini_miner(pool, nonexistent_outpoints);
        BOOST_CHECK(mini_miner.IsReadyToCalculate());
        auto bump_fees = mini_miner.CalculateBumpFees(feerate);
        BOOST_CHECK(!mini_miner.IsReadyToCalculate());
        BOOST_CHECK(sanity_check(all_transactions, bump_fees));
        BOOST_CHECK(bump_fees.size() == nonexistent_outpoints.size());
        for (const auto& outpoint: nonexistent_outpoints) {
            auto it = bump_fees.find(outpoint);
            BOOST_CHECK(it != bump_fees.end());
            BOOST_CHECK_EQUAL(it->second, 0);
        }
    }

    // Gather bump fees for all available UTXOs.
    for (const auto& target_feerate : various_normal_feerates) {
        node::MiniMiner mini_miner(pool, all_unspent_outpoints);
        BOOST_CHECK(mini_miner.IsReadyToCalculate());
        auto bump_fees = mini_miner.CalculateBumpFees(target_feerate);
        BOOST_CHECK(!mini_miner.IsReadyToCalculate());
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
        BOOST_CHECK(it5_unspent != bump_fees.end());
        if (target_feerate <= tx5_feerate) {
            // As long as target feerate is below tx4's ancestor feerate, there is no bump fee.
            BOOST_CHECK_EQUAL(it5_unspent->second, 0);
        } else {
            // Difference is fee to bump tx5 from current to target feerate, without tx6.
            BOOST_CHECK_EQUAL(it5_unspent->second,
                target_feerate.GetFee(tx_vsizes.find(tx5->GetHash())->second) - tx_modified_fees.find(tx5->GetHash())->second);
        }
    }
    // Spent outpoints should usually not be requested as they would not be
    // considered available. However, when they are explicitly requested, we
    // can calculate their bumpfee to facilitate RBF-replacements
    for (const auto& target_feerate : various_normal_feerates) {
        node::MiniMiner mini_miner_all_spent(pool, all_spent_outpoints);
        BOOST_CHECK(mini_miner_all_spent.IsReadyToCalculate());
        auto bump_fees_all_spent = mini_miner_all_spent.CalculateBumpFees(target_feerate);
        BOOST_CHECK(!mini_miner_all_spent.IsReadyToCalculate());
        BOOST_CHECK_EQUAL(bump_fees_all_spent.size(), all_spent_outpoints.size());
        node::MiniMiner mini_miner_all_parents(pool, all_parent_outputs);
        BOOST_CHECK(mini_miner_all_parents.IsReadyToCalculate());
        auto bump_fees_all_parents = mini_miner_all_parents.CalculateBumpFees(target_feerate);
        BOOST_CHECK(!mini_miner_all_parents.IsReadyToCalculate());
        BOOST_CHECK_EQUAL(bump_fees_all_parents.size(), all_parent_outputs.size());
        for (auto& bump_fees : {bump_fees_all_parents, bump_fees_all_spent}) {
            // For all_parents case, both outputs from the parent should have the same bump fee,
            // even though only one of them is in a to-be-replaced transaction.
            BOOST_CHECK(sanity_check(all_transactions, bump_fees));
            // Check tx1 bumpfee: no other bumper.
            const auto tx1_feerate = tx_feerates.find(tx1->GetHash())->second;
            auto it1_spent = bump_fees.find(COutPoint{tx1->GetHash(), 0});
            BOOST_CHECK(it1_spent != bump_fees.end());
            if (target_feerate <= tx1_feerate) {
                BOOST_CHECK_EQUAL(it1_spent->second, 0);
            } else {
                // Difference is fee to bump tx1 from current to target feerate.
                BOOST_CHECK_EQUAL(it1_spent->second,
                    target_feerate.GetFee(tx_vsizes.find(tx1->GetHash())->second) - tx_modified_fees.find(tx1->GetHash())->second);
            }
            // Check tx3 bumpfee: no other bumper, because tx4 is to-be-replaced.
            const auto tx3_feerate_unbumped = tx_feerates.find(tx3->GetHash())->second;
            auto it3_spent = bump_fees.find(COutPoint{tx3->GetHash(), 0});
            BOOST_CHECK(it3_spent != bump_fees.end());
            if (target_feerate <= tx3_feerate_unbumped) {
                BOOST_CHECK_EQUAL(it3_spent->second, 0);
            } else {
                // Difference is fee to bump tx3 from current to target feerate, without tx4.
                BOOST_CHECK_EQUAL(it3_spent->second,
                    target_feerate.GetFee(tx_vsizes.find(tx3->GetHash())->second) - tx_modified_fees.find(tx3->GetHash())->second);
            }
            // Check tx5 bumpfee: no other bumper, because tx6 is to-be-replaced.
            const auto tx5_feerate_unbumped = tx_feerates.find(tx5->GetHash())->second;
            auto it5_spent = bump_fees.find(COutPoint{tx5->GetHash(), 0});
            BOOST_CHECK(it5_spent != bump_fees.end());
            if (target_feerate <= tx5_feerate_unbumped) {
                BOOST_CHECK_EQUAL(it5_spent->second, 0);
            } else {
                // Difference is fee to bump tx5 from current to target feerate, without tx6.
                BOOST_CHECK_EQUAL(it5_spent->second,
                    target_feerate.GetFee(tx_vsizes.find(tx5->GetHash())->second) - tx_modified_fees.find(tx5->GetHash())->second);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(miniminer_overlap, TestChain100Setup)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    const CAmount low_fee{CENT/2000};
    const CAmount med_fee{CENT/200};
    const CAmount high_fee{CENT/10};

    // Create 3 parents of different feerates, and 1 child spending from all 3.
    const auto tx1 = make_tx({COutPoint{m_coinbase_txns[0]->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx1));
    const auto tx2 = make_tx({COutPoint{m_coinbase_txns[1]->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(med_fee).FromTx(tx2));
    const auto tx3 = make_tx({COutPoint{m_coinbase_txns[2]->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx3));
    const auto tx4 = make_tx({COutPoint{tx1->GetHash(), 0}, COutPoint{tx2->GetHash(), 0}, COutPoint{tx3->GetHash(), 0}}, /*num_outputs=*/3);
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx4));

    // Create 1 grandparent and 1 parent, then 2 children.
    const auto tx5 = make_tx({COutPoint{m_coinbase_txns[3]->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx5));
    const auto tx6 = make_tx({COutPoint{tx5->GetHash(), 0}}, /*num_outputs=*/3);
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx6));
    const auto tx7 = make_tx({COutPoint{tx6->GetHash(), 0}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(med_fee).FromTx(tx7));
    const auto tx8 = make_tx({COutPoint{tx6->GetHash(), 1}}, /*num_outputs=*/2);
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx8));

    std::vector<CTransactionRef> all_transactions{tx1, tx2, tx3, tx4, tx5, tx6, tx7, tx8};
    std::vector<int64_t> tx_vsizes;
    tx_vsizes.reserve(all_transactions.size());
    for (const auto& tx : all_transactions) tx_vsizes.push_back(GetVirtualTransactionSize(*tx));

    std::vector<COutPoint> all_unspent_outpoints({
        COutPoint{tx1->GetHash(), 1},
        COutPoint{tx2->GetHash(), 1},
        COutPoint{tx3->GetHash(), 1},
        COutPoint{tx4->GetHash(), 0},
        COutPoint{tx4->GetHash(), 1},
        COutPoint{tx4->GetHash(), 2},
        COutPoint{tx5->GetHash(), 1},
        COutPoint{tx6->GetHash(), 2},
        COutPoint{tx7->GetHash(), 0},
        COutPoint{tx8->GetHash(), 0}
    });
    for (const auto& outpoint : all_unspent_outpoints) BOOST_CHECK(!pool.isSpent(outpoint));

    const auto tx3_feerate = CFeeRate(high_fee, tx_vsizes[2]);
    const auto tx4_feerate = CFeeRate(high_fee, tx_vsizes[3]);
    // tx4's feerate is lower than tx3's. same fee, different weight.
    BOOST_CHECK(tx3_feerate > tx4_feerate);
    const auto tx4_anc_feerate = CFeeRate(low_fee + med_fee + high_fee, tx_vsizes[0] + tx_vsizes[1] + tx_vsizes[3]);
    const auto tx5_feerate = CFeeRate(high_fee, tx_vsizes[4]);
    const auto tx7_anc_feerate = CFeeRate(low_fee + med_fee, tx_vsizes[5] + tx_vsizes[6]);
    const auto tx8_anc_feerate = CFeeRate(low_fee + high_fee, tx_vsizes[5] + tx_vsizes[7]);
    BOOST_CHECK(tx5_feerate > tx7_anc_feerate);
    BOOST_CHECK(tx5_feerate > tx8_anc_feerate);

    // Extremely high feerate: everybody's bumpfee is from their full ancestor set.
    {
        node::MiniMiner mini_miner(pool, all_unspent_outpoints);
        const CFeeRate very_high_feerate(COIN);
        BOOST_CHECK(tx4_anc_feerate < very_high_feerate);
        BOOST_CHECK(mini_miner.IsReadyToCalculate());
        auto bump_fees = mini_miner.CalculateBumpFees(very_high_feerate);
        BOOST_CHECK_EQUAL(bump_fees.size(), all_unspent_outpoints.size());
        BOOST_CHECK(!mini_miner.IsReadyToCalculate());
        BOOST_CHECK(sanity_check(all_transactions, bump_fees));
        const auto tx1_bumpfee = bump_fees.find(COutPoint{tx1->GetHash(), 1});
        BOOST_CHECK(tx1_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx1_bumpfee->second, very_high_feerate.GetFee(tx_vsizes[0]) - low_fee);
        const auto tx4_bumpfee = bump_fees.find(COutPoint{tx4->GetHash(), 0});
        BOOST_CHECK(tx4_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx4_bumpfee->second,
            very_high_feerate.GetFee(tx_vsizes[0] + tx_vsizes[1] + tx_vsizes[2] + tx_vsizes[3]) - (low_fee + med_fee + high_fee + high_fee));
        const auto tx7_bumpfee = bump_fees.find(COutPoint{tx7->GetHash(), 0});
        BOOST_CHECK(tx7_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx7_bumpfee->second,
            very_high_feerate.GetFee(tx_vsizes[4] + tx_vsizes[5] + tx_vsizes[6]) - (high_fee + low_fee + med_fee));
        const auto tx8_bumpfee = bump_fees.find(COutPoint{tx8->GetHash(), 0});
        BOOST_CHECK(tx8_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx8_bumpfee->second,
            very_high_feerate.GetFee(tx_vsizes[4] + tx_vsizes[5] + tx_vsizes[7]) - (high_fee + low_fee + high_fee));
        // Total fees: if spending multiple outputs from tx4 don't double-count fees.
        node::MiniMiner mini_miner_total_tx4(pool, {COutPoint{tx4->GetHash(), 0}, COutPoint{tx4->GetHash(), 1}});
        BOOST_CHECK(mini_miner_total_tx4.IsReadyToCalculate());
        const auto tx4_bump_fee = mini_miner_total_tx4.CalculateTotalBumpFees(very_high_feerate);
        BOOST_CHECK(!mini_miner_total_tx4.IsReadyToCalculate());
        BOOST_CHECK(tx4_bump_fee.has_value());
        BOOST_CHECK_EQUAL(tx4_bump_fee.value(),
            very_high_feerate.GetFee(tx_vsizes[0] + tx_vsizes[1] + tx_vsizes[2] + tx_vsizes[3]) - (low_fee + med_fee + high_fee + high_fee));
        // Total fees: if spending both tx7 and tx8, don't double-count fees.
        node::MiniMiner mini_miner_tx7_tx8(pool, {COutPoint{tx7->GetHash(), 0}, COutPoint{tx8->GetHash(), 0}});
        BOOST_CHECK(mini_miner_tx7_tx8.IsReadyToCalculate());
        const auto tx7_tx8_bumpfee = mini_miner_tx7_tx8.CalculateTotalBumpFees(very_high_feerate);
        BOOST_CHECK(!mini_miner_tx7_tx8.IsReadyToCalculate());
        BOOST_CHECK(tx7_tx8_bumpfee.has_value());
        BOOST_CHECK_EQUAL(tx7_tx8_bumpfee.value(),
            very_high_feerate.GetFee(tx_vsizes[4] + tx_vsizes[5] + tx_vsizes[6] + tx_vsizes[7]) - (high_fee + low_fee + med_fee + high_fee));
    }
    // Feerate just below tx5: tx7 and tx8 have different bump fees.
    {
        const auto just_below_tx5 = CFeeRate(tx5_feerate.GetFeePerK() - 5);
        node::MiniMiner mini_miner(pool, all_unspent_outpoints);
        BOOST_CHECK(mini_miner.IsReadyToCalculate());
        auto bump_fees = mini_miner.CalculateBumpFees(just_below_tx5);
        BOOST_CHECK(!mini_miner.IsReadyToCalculate());
        BOOST_CHECK_EQUAL(bump_fees.size(), all_unspent_outpoints.size());
        BOOST_CHECK(sanity_check(all_transactions, bump_fees));
        const auto tx7_bumpfee = bump_fees.find(COutPoint{tx7->GetHash(), 0});
        BOOST_CHECK(tx7_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx7_bumpfee->second, just_below_tx5.GetFee(tx_vsizes[5] + tx_vsizes[6]) - (low_fee + med_fee));
        const auto tx8_bumpfee = bump_fees.find(COutPoint{tx8->GetHash(), 0});
        BOOST_CHECK(tx8_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx8_bumpfee->second, just_below_tx5.GetFee(tx_vsizes[5] + tx_vsizes[7]) - (low_fee + high_fee));
        // Total fees: if spending both tx7 and tx8, don't double-count fees.
        node::MiniMiner mini_miner_tx7_tx8(pool, {COutPoint{tx7->GetHash(), 0}, COutPoint{tx8->GetHash(), 0}});
        BOOST_CHECK(mini_miner_tx7_tx8.IsReadyToCalculate());
        const auto tx7_tx8_bumpfee = mini_miner_tx7_tx8.CalculateTotalBumpFees(just_below_tx5);
        BOOST_CHECK(!mini_miner_tx7_tx8.IsReadyToCalculate());
        BOOST_CHECK(tx7_tx8_bumpfee.has_value());
        BOOST_CHECK_EQUAL(tx7_tx8_bumpfee.value(), just_below_tx5.GetFee(tx_vsizes[5] + tx_vsizes[6]) - (low_fee + med_fee));
    }
    // Feerate between tx7 and tx8's ancestor feerates: don't need to bump tx6 because tx8 already does.
    {
        const auto just_above_tx7 = CFeeRate(med_fee + 10, tx_vsizes[6]);
        BOOST_CHECK(just_above_tx7 <= CFeeRate(low_fee + high_fee, tx_vsizes[5] + tx_vsizes[7]));
        node::MiniMiner mini_miner(pool, all_unspent_outpoints);
        BOOST_CHECK(mini_miner.IsReadyToCalculate());
        auto bump_fees = mini_miner.CalculateBumpFees(just_above_tx7);
        BOOST_CHECK(!mini_miner.IsReadyToCalculate());
        BOOST_CHECK_EQUAL(bump_fees.size(), all_unspent_outpoints.size());
        BOOST_CHECK(sanity_check(all_transactions, bump_fees));
        const auto tx7_bumpfee = bump_fees.find(COutPoint{tx7->GetHash(), 0});
        BOOST_CHECK(tx7_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx7_bumpfee->second, just_above_tx7.GetFee(tx_vsizes[6]) - (med_fee));
        const auto tx8_bumpfee = bump_fees.find(COutPoint{tx8->GetHash(), 0});
        BOOST_CHECK(tx8_bumpfee != bump_fees.end());
        BOOST_CHECK_EQUAL(tx8_bumpfee->second, 0);
    }
}
BOOST_FIXTURE_TEST_CASE(calculate_cluster, TestChain100Setup)
{
    FastRandomContext det_rand{true};
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);

    // Add chain of size 500
    TestMemPoolEntryHelper entry;
    std::vector<uint256> chain_txids;
    auto& lasttx = m_coinbase_txns[0];
    for (auto i{0}; i < 500; ++i) {
        const auto tx = make_tx({COutPoint{lasttx->GetHash(), 0}}, /*num_outputs=*/1);
        pool.addUnchecked(entry.Fee(CENT).FromTx(tx));
        chain_txids.push_back(tx->GetHash());
        lasttx = tx;
    }
    const auto cluster_500tx = pool.CalculateCluster({lasttx->GetHash()});
    CTxMemPool::setEntries cluster_500tx_set{cluster_500tx.begin(), cluster_500tx.end()};
    BOOST_CHECK_EQUAL(cluster_500tx.size(), cluster_500tx_set.size());
    const auto vec_iters_500 = pool.GetIterVec(chain_txids);
    for (const auto& iter : vec_iters_500) BOOST_CHECK(cluster_500tx_set.count(iter));

    // CalculateCluster stops at 500 transactions.
    const auto tx_501 = make_tx({COutPoint{lasttx->GetHash(), 0}}, /*num_outputs=*/1);
    pool.addUnchecked(entry.Fee(CENT).FromTx(tx_501));
    const auto cluster_501 = pool.CalculateCluster({tx_501->GetHash()});
    BOOST_CHECK_EQUAL(cluster_501.size(), 0);

    // Zig Zag cluster:
    // txp0     txp1     txp2    ...  txp48  txp49
    //    \    /    \   /   \            \   /
    //     txc0     txc1    txc2  ...    txc48
    // Note that each transaction's ancestor size is 2 or 3, and each descendant size is 2 or 3.
    // However, all of these transactions are in the same cluster.
    std::vector<uint256> zigzag_txids;
    for (auto p{0}; p < 50; ++p) {
        const auto txp = make_tx({COutPoint{GetRandHash(), 0}}, /*num_outputs=*/2);
        pool.addUnchecked(entry.Fee(CENT).FromTx(txp));
        zigzag_txids.push_back(txp->GetHash());
    }
    for (auto c{0}; c < 49; ++c) {
        const auto txc = make_tx({COutPoint{zigzag_txids[c], 1}, COutPoint{zigzag_txids[c+1], 0}}, /*num_outputs=*/1);
        pool.addUnchecked(entry.Fee(CENT).FromTx(txc));
        zigzag_txids.push_back(txc->GetHash());
    }
    const auto vec_iters_zigzag = pool.GetIterVec(zigzag_txids);
    // It doesn't matter which tx we calculate cluster for, everybody is in it.
    const std::vector<size_t> indeces{0, 22, 72, zigzag_txids.size() - 1};
    for (const auto index : indeces) {
        const auto cluster = pool.CalculateCluster({zigzag_txids[index]});
        BOOST_CHECK_EQUAL(cluster.size(), zigzag_txids.size());
        CTxMemPool::setEntries clusterset{cluster.begin(), cluster.end()};
        BOOST_CHECK_EQUAL(cluster.size(), clusterset.size());
        for (const auto& iter : vec_iters_zigzag) BOOST_CHECK(clusterset.count(iter));
    }
}

BOOST_AUTO_TEST_SUITE_END()
