// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <policy/policy.h>
#include <policy/rbf.h>
#include <random.h>
#include <txmempool.h>
#include <util/system.h>
#include <util/time.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <optional>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(rbf_tests, TestingSetup)

inline CTransactionRef make_tx(std::vector<CAmount>&& output_values,
                               std::vector<CTransactionRef>&& inputs=std::vector<CTransactionRef>(),
                               std::vector<uint32_t>&& input_indices=std::vector<uint32_t>())
{
    CMutableTransaction tx = CMutableTransaction();
    tx.vin.resize(inputs.size());
    tx.vout.resize(output_values.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        tx.vin[i].prevout.hash = inputs[i]->GetHash();
        tx.vin[i].prevout.n = input_indices.size() > i ? input_indices[i] : 0;
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

BOOST_AUTO_TEST_CASE(rbf_helper_functions)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    const CAmount low_fee{100};
    const CAmount normal_fee{10000};
    const CAmount high_fee{1 * COIN};



    // Create a parent tx1 and child tx2 with normal fees:
    CTransactionRef tx1 = make_tx(/*output_values=*/ {10 * COIN});
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx1));
    CTransactionRef tx2 = make_tx(/*output_values=*/ {995 * CENT}, /*inputs=*/ {tx1});
    pool.addUnchecked(entry.Fee(normal_fee).FromTx(tx2));

    // Create a low-feerate parent tx3 and high-feerate child tx4 (cpfp)
    CTransactionRef tx3 = make_tx(/*output_values=*/ {1099 * CENT});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx3));
    CTransactionRef tx4 = make_tx(/*output_values=*/ {999 * CENT}, /*inputs=*/ {tx3});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx4));

    // Create a parent tx5 and child tx6 where both have very low fees
    CTransactionRef tx5 = make_tx(/*output_values=*/ {1099 * CENT});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx5));
    CTransactionRef tx6 = make_tx(/*output_values=*/ {1098 * CENT}, /*inputs=*/ {tx3});
    pool.addUnchecked(entry.Fee(low_fee).FromTx(tx6));
    // tx6 has a high modified fee
    pool.PrioritiseTransaction(tx6->GetHash(), 1 * COIN);

    // Two independent high-feerate transactions, tx7 and tx8
    CTransactionRef tx7 = make_tx(/*output_values=*/ {999 * CENT});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx7));
    CTransactionRef tx8 = make_tx(/*output_values=*/ {999 * CENT});
    pool.addUnchecked(entry.Fee(high_fee).FromTx(tx8));

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

    CTxMemPool::setEntries set_12_normal{entry1, entry2};
    CTxMemPool::setEntries set_34_cpfp{entry3, entry4};
    CTxMemPool::setEntries set_56_low{entry5, entry6};
    CTxMemPool::setEntries set_78_high{entry7, entry8};
    CTxMemPool::setEntries all_entries{entry1, entry2, entry3, entry4, entry5, entry6, entry7, entry8};
    CTxMemPool::setEntries empty_set;

    const auto unused_txid{GetRandHash()};

    // Tests for PaysMoreThanConflicts
    // These tests use feerate, not absolute fee.
    BOOST_CHECK(PaysMoreThanConflicts(set_12_normal, CFeeRate(entry1->GetModifiedFee() + 1, entry1->GetTxSize() + 2), unused_txid).has_value());
    // Replacement must be strictly greater than the originals.
    BOOST_CHECK(PaysMoreThanConflicts(set_12_normal, CFeeRate(entry1->GetModifiedFee(), entry1->GetTxSize()), unused_txid).has_value());
    BOOST_CHECK(PaysMoreThanConflicts(set_12_normal, CFeeRate(entry1->GetModifiedFee() + 1, entry1->GetTxSize()), unused_txid) == std::nullopt);
    // These tests use modified fees (including prioritisation), not base fees.
    BOOST_CHECK(PaysMoreThanConflicts({entry6}, CFeeRate(entry6->GetFee() + 1, entry6->GetTxSize()), unused_txid).has_value());
    BOOST_CHECK(PaysMoreThanConflicts({entry6}, CFeeRate(entry6->GetModifiedFee() + 1, entry6->GetTxSize()), unused_txid) == std::nullopt);
    // These tests only check individual feerate. Ancestor feerate does not matter.
    BOOST_CHECK(PaysMoreThanConflicts(set_34_cpfp, CFeeRate(entry4->GetModifiedFee(), entry4->GetTxSize()), unused_txid).has_value());

    // Tests for CheckMinerScores
    // Don't allow replacements with a low ancestor feerate.
    BOOST_CHECK(CheckMinerScores(/*replacement_fees=*/entry1->GetFee(),
                                 /*replacement_vsize=*/entry1->GetTxSize(),
                                 /*ancestors=*/{entry5},
                                 /*direct_conflicts=*/{entry1},
                                 /*original_transactions=*/set_12_normal).has_value());

    BOOST_CHECK(CheckMinerScores(entry3->GetFee() + entry4->GetFee() + 10000,
                                 entry3->GetTxSize() + entry4->GetTxSize(),
                                 {entry5},
                                 {entry3},
                                 set_34_cpfp).has_value());

    // These tests use modified fees (including prioritisation), not base fees.
    BOOST_CHECK(CheckMinerScores(entry5->GetFee() + entry6->GetFee() + 1,
                                 entry5->GetTxSize() + entry6->GetTxSize(),
                                 {empty_set},
                                 {entry5},
                                 set_56_low).has_value());
    BOOST_CHECK(CheckMinerScores(entry5->GetModifiedFee() + entry6->GetModifiedFee() + 1,
                                 entry5->GetTxSize() + entry6->GetTxSize(),
                                 {empty_set},
                                 {entry5},
                                 set_56_low) == std::nullopt);

    // High-feerate ancestors don't help raise the replacement's miner score.
    BOOST_CHECK(CheckMinerScores(entry1->GetFee() - 1,
                                 entry1->GetTxSize(),
                                 empty_set,
                                 set_12_normal,
                                 set_12_normal).has_value());

    BOOST_CHECK(CheckMinerScores(entry1->GetFee() - 1,
                                 entry1->GetTxSize(),
                                 set_78_high,
                                 set_12_normal,
                                 set_12_normal).has_value());

    // Replacement must be higher than the individual feerate of direct conflicts.
    // Note entry4's individual feerate is higher than its ancestor feerate
    BOOST_CHECK(CheckMinerScores(entry4->GetFee() - 1,
                                 entry4->GetTxSize(),
                                 empty_set,
                                 {entry4},
                                 {entry4}).has_value());

    BOOST_CHECK(CheckMinerScores(entry4->GetFee() - 1,
                                 entry4->GetTxSize(),
                                 empty_set,
                                 {entry3},
                                 set_34_cpfp) == std::nullopt);

    // Tests for EntriesAndTxidsDisjoint
    BOOST_CHECK(EntriesAndTxidsDisjoint(empty_set, {tx1->GetHash()}, unused_txid) == std::nullopt);
    BOOST_CHECK(EntriesAndTxidsDisjoint(set_12_normal, {tx3->GetHash(), tx8->GetHash()}, unused_txid) == std::nullopt);
    // EntriesAndTxidsDisjoint uses txids, not wtxids.
    BOOST_CHECK(EntriesAndTxidsDisjoint({entry2}, {tx2->GetWitnessHash()}, unused_txid) == std::nullopt);
    // If entry2 is an ancestor of a tx, that tx cannot replace entry1.  However,
    // EntriesAndTxidsDisjoint uses the ancestors directly. It does not calculate descendants.
    BOOST_CHECK(EntriesAndTxidsDisjoint(set_12_normal, {tx1->GetHash()}, unused_txid).has_value());
    BOOST_CHECK(EntriesAndTxidsDisjoint(set_12_normal, {tx2->GetHash()}, unused_txid).has_value());
    BOOST_CHECK(EntriesAndTxidsDisjoint({entry2}, {tx1->GetHash()}, unused_txid) == std::nullopt);

    // Tests for PaysForRBF
    const auto incremental_relay_fee{CFeeRate(DEFAULT_INCREMENTAL_RELAY_FEE)};
    const auto higher_relay_fee{CFeeRate(3000)};
    // Must pay at least as much as the original.
    BOOST_CHECK(PaysForRBF(/*original_fees=*/high_fee,
                           /*replacement_fees=*/high_fee,
                           /*replacement_vsize=*/1,
                           /*relay_fee=*/CFeeRate(0),
                           /*txid=*/unused_txid)
                           == std::nullopt);
    BOOST_CHECK(PaysForRBF(high_fee, high_fee - 1, 1, CFeeRate(0), unused_txid).has_value());
    BOOST_CHECK(PaysForRBF(high_fee + 1, high_fee, 1, CFeeRate(0), unused_txid).has_value());
    // Additional fees must cover the replacement's vsize at incremental relay fee
    BOOST_CHECK(PaysForRBF(high_fee, high_fee + 1, 2, incremental_relay_fee, unused_txid) .has_value());
    BOOST_CHECK(PaysForRBF(high_fee, high_fee + 2, 2, incremental_relay_fee, unused_txid) == std::nullopt);
    BOOST_CHECK(PaysForRBF(high_fee, high_fee + 2, 2, CFeeRate(2, 1), unused_txid) .has_value());
    BOOST_CHECK(PaysForRBF(high_fee, high_fee + 4, 2, CFeeRate(2, 1), unused_txid) == std::nullopt);
    BOOST_CHECK(PaysForRBF(low_fee, high_fee, 99999999, incremental_relay_fee, unused_txid) .has_value());
}

BOOST_AUTO_TEST_SUITE_END()
