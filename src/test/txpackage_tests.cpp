// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key_io.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <test/util/txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;

// A fee amount that is above 1sat/vB but below 5sat/vB for most transactions created within these
// unit tests.
static const CAmount low_fee_amt{200};

struct TxPackageTest : TestChain100Setup {
// Create placeholder transactions that have no meaning.
inline CTransactionRef create_placeholder_tx(size_t num_inputs, size_t num_outputs)
{
    CMutableTransaction mtx = CMutableTransaction();
    mtx.vin.resize(num_inputs);
    mtx.vout.resize(num_outputs);
    auto random_script = CScript() << ToByteVector(m_rng.rand256()) << ToByteVector(m_rng.rand256());
    for (size_t i{0}; i < num_inputs; ++i) {
        mtx.vin[i].prevout.hash = Txid::FromUint256(m_rng.rand256());
        mtx.vin[i].prevout.n = 0;
        mtx.vin[i].scriptSig = random_script;
    }
    for (size_t o{0}; o < num_outputs; ++o) {
        mtx.vout[o].nValue = 1 * CENT;
        mtx.vout[o].scriptPubKey = random_script;
    }
    return MakeTransactionRef(mtx);
}
}; // struct TxPackageTest

BOOST_FIXTURE_TEST_SUITE(txpackage_tests, TxPackageTest)

BOOST_AUTO_TEST_CASE(package_hash_tests)
{
    // Random real segwit transaction
    DataStream stream_1{
        "02000000000101964b8aa63509579ca6086e6012eeaa4c2f4dd1e283da29b67c8eea38b3c6fd220000000000fdffffff0294c618000000000017a9145afbbb42f4e83312666d0697f9e66259912ecde38768fa2c0000000000160014897388a0889390fd0e153a22bb2cf9d8f019faf50247304402200547406380719f84d68cf4e96cc3e4a1688309ef475b150be2b471c70ea562aa02206d255f5acc40fd95981874d77201d2eb07883657ce1c796513f32b6079545cdf0121023ae77335cefcb5ab4c1dc1fb0d2acfece184e593727d7d5906c78e564c7c11d125cf0c00"_hex,
    };
    CTransaction tx_1(deserialize, TX_WITH_WITNESS, stream_1);
    CTransactionRef ptx_1{MakeTransactionRef(tx_1)};

    // Random real nonsegwit transaction
    DataStream stream_2{
        "01000000010b26e9b7735eb6aabdf358bab62f9816a21ba9ebdb719d5299e88607d722c190000000008b4830450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d11000000001976a91404943fdd508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976a914a266436d2965547608b9e15d9032a7b9d64fa43188ac00000000"_hex,
    };
    CTransaction tx_2(deserialize, TX_WITH_WITNESS, stream_2);
    CTransactionRef ptx_2{MakeTransactionRef(tx_2)};

    // Random real segwit transaction
    DataStream stream_3{
        "0200000000010177862801f77c2c068a70372b4c435ef8dd621291c36a64eb4dd491f02218f5324600000000fdffffff014a0100000000000022512035ea312034cfac01e956a269f3bf147f569c2fbb00180677421262da042290d803402be713325ff285e66b0380f53f2fae0d0fb4e16f378a440fed51ce835061437566729d4883bc917632f3cff474d6384bc8b989961a1d730d4a87ed38ad28bd337b20f1d658c6c138b1c312e072b4446f50f01ae0da03a42e6274f8788aae53416a7fac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800357b2270223a226272632d3230222c226f70223a226d696e74222c227469636b223a224342414c222c22616d74223a2236393639227d6821c1f1d658c6c138b1c312e072b4446f50f01ae0da03a42e6274f8788aae53416a7f00000000"_hex,
    };
    CTransaction tx_3(deserialize, TX_WITH_WITNESS, stream_3);
    CTransactionRef ptx_3{MakeTransactionRef(tx_3)};

    // It's easy to see that wtxids are sorted in lexicographical order:
    Wtxid wtxid_1{Wtxid::FromHex("85cd1a31eb38f74ed5742ec9cb546712ab5aaf747de28a9168b53e846cbda17f").value()};
    Wtxid wtxid_2{Wtxid::FromHex("b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b").value()};
    Wtxid wtxid_3{Wtxid::FromHex("e065bac15f62bb4e761d761db928ddee65a47296b2b776785abb912cdec474e3").value()};
    BOOST_CHECK_EQUAL(tx_1.GetWitnessHash(), wtxid_1);
    BOOST_CHECK_EQUAL(tx_2.GetWitnessHash(), wtxid_2);
    BOOST_CHECK_EQUAL(tx_3.GetWitnessHash(), wtxid_3);

    BOOST_CHECK(wtxid_1.GetHex() < wtxid_2.GetHex());
    BOOST_CHECK(wtxid_2.GetHex() < wtxid_3.GetHex());

    // The txids are not (we want to test that sorting and hashing use wtxid, not txid):
    Txid txid_1{Txid::FromHex("bd0f71c1d5e50589063e134fad22053cdae5ab2320db5bf5e540198b0b5a4e69").value()};
    Txid txid_2{Txid::FromHex("b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b").value()};
    Txid txid_3{Txid::FromHex("ee707be5201160e32c4fc715bec227d1aeea5940fb4295605e7373edce3b1a93").value()};
    BOOST_CHECK_EQUAL(tx_1.GetHash(), txid_1);
    BOOST_CHECK_EQUAL(tx_2.GetHash(), txid_2);
    BOOST_CHECK_EQUAL(tx_3.GetHash(), txid_3);

    BOOST_CHECK(txid_2.GetHex() < txid_1.GetHex());

    BOOST_CHECK(txid_1.ToUint256() != wtxid_1.ToUint256());
    BOOST_CHECK(txid_2.ToUint256() == wtxid_2.ToUint256());
    BOOST_CHECK(txid_3.ToUint256() != wtxid_3.ToUint256());

    // We are testing that both functions compare using GetHex() and not uint256.
    // (in this pair of wtxids, hex string order != uint256 order)
    BOOST_CHECK(wtxid_2 < wtxid_1);
    // (in this pair of wtxids, hex string order == uint256 order)
    BOOST_CHECK(wtxid_2 < wtxid_3);

    // All permutations of the package containing ptx_1, ptx_2, ptx_3 have the same package hash
    std::vector<CTransactionRef> package_123{ptx_1, ptx_2, ptx_3};
    std::vector<CTransactionRef> package_132{ptx_1, ptx_3, ptx_2};
    std::vector<CTransactionRef> package_231{ptx_2, ptx_3, ptx_1};
    std::vector<CTransactionRef> package_213{ptx_2, ptx_1, ptx_3};
    std::vector<CTransactionRef> package_312{ptx_3, ptx_1, ptx_2};
    std::vector<CTransactionRef> package_321{ptx_3, ptx_2, ptx_1};

    uint256 calculated_hash_123 = (HashWriter() << wtxid_1 << wtxid_2 << wtxid_3).GetSHA256();

    uint256 hash_if_by_txid = (HashWriter() << wtxid_2 << wtxid_1 << wtxid_3).GetSHA256();
    BOOST_CHECK(hash_if_by_txid != calculated_hash_123);

    uint256 hash_if_use_txid = (HashWriter() << txid_2 << txid_1 << txid_3).GetSHA256();
    BOOST_CHECK(hash_if_use_txid != calculated_hash_123);

    uint256 hash_if_use_int_order = (HashWriter() << wtxid_2 << wtxid_1 << wtxid_3).GetSHA256();
    BOOST_CHECK(hash_if_use_int_order != calculated_hash_123);

    BOOST_CHECK_EQUAL(calculated_hash_123, GetPackageHash(package_123));
    BOOST_CHECK_EQUAL(calculated_hash_123, GetPackageHash(package_132));
    BOOST_CHECK_EQUAL(calculated_hash_123, GetPackageHash(package_231));
    BOOST_CHECK_EQUAL(calculated_hash_123, GetPackageHash(package_213));
    BOOST_CHECK_EQUAL(calculated_hash_123, GetPackageHash(package_312));
    BOOST_CHECK_EQUAL(calculated_hash_123, GetPackageHash(package_321));
}

BOOST_AUTO_TEST_CASE(package_sanitization_tests)
{
    // Packages can't have more than 25 transactions.
    Package package_too_many;
    package_too_many.reserve(MAX_PACKAGE_COUNT + 1);
    for (size_t i{0}; i < MAX_PACKAGE_COUNT + 1; ++i) {
        package_too_many.emplace_back(create_placeholder_tx(1, 1));
    }
    PackageValidationState state_too_many;
    BOOST_CHECK(!IsWellFormedPackage(package_too_many, state_too_many, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_too_many.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_too_many.GetRejectReason(), "package-too-many-transactions");

    // Packages can't have a total weight of more than 404'000WU.
    CTransactionRef large_ptx = create_placeholder_tx(150, 150);
    Package package_too_large;
    auto size_large = GetTransactionWeight(*large_ptx);
    size_t total_weight{0};
    while (total_weight <= MAX_PACKAGE_WEIGHT) {
        package_too_large.push_back(large_ptx);
        total_weight += size_large;
    }
    BOOST_CHECK(package_too_large.size() <= MAX_PACKAGE_COUNT);
    PackageValidationState state_too_large;
    BOOST_CHECK(!IsWellFormedPackage(package_too_large, state_too_large, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_too_large.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_too_large.GetRejectReason(), "package-too-large");

    // Packages can't contain transactions with the same txid.
    Package package_duplicate_txids_empty;
    for (auto i{0}; i < 3; ++i) {
        CMutableTransaction empty_tx;
        package_duplicate_txids_empty.emplace_back(MakeTransactionRef(empty_tx));
    }
    PackageValidationState state_duplicates;
    BOOST_CHECK(!IsWellFormedPackage(package_duplicate_txids_empty, state_duplicates, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_duplicates.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_duplicates.GetRejectReason(), "package-contains-duplicates");
    BOOST_CHECK(!IsConsistentPackage(package_duplicate_txids_empty));

    // Packages can't have transactions spending the same prevout
    CMutableTransaction tx_zero_1;
    CMutableTransaction tx_zero_2;
    COutPoint same_prevout{Txid::FromUint256(m_rng.rand256()), 0};
    tx_zero_1.vin.emplace_back(same_prevout);
    tx_zero_2.vin.emplace_back(same_prevout);
    // Different vouts (not the same tx)
    tx_zero_1.vout.emplace_back(CENT, P2WSH_OP_TRUE);
    tx_zero_2.vout.emplace_back(2 * CENT, P2WSH_OP_TRUE);
    Package package_conflicts{MakeTransactionRef(tx_zero_1), MakeTransactionRef(tx_zero_2)};
    BOOST_CHECK(!IsConsistentPackage(package_conflicts));
    // Transactions are considered sorted when they have no dependencies.
    BOOST_CHECK(IsTopoSortedPackage(package_conflicts));
    PackageValidationState state_conflicts;
    BOOST_CHECK(!IsWellFormedPackage(package_conflicts, state_conflicts, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_conflicts.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_conflicts.GetRejectReason(), "conflict-in-package");

    // IsConsistentPackage only cares about conflicts between transactions, not about a transaction
    // conflicting with itself (i.e. duplicate prevouts in vin).
    CMutableTransaction dup_tx;
    const COutPoint rand_prevout{Txid::FromUint256(m_rng.rand256()), 0};
    dup_tx.vin.emplace_back(rand_prevout);
    dup_tx.vin.emplace_back(rand_prevout);
    Package package_with_dup_tx{MakeTransactionRef(dup_tx)};
    BOOST_CHECK(IsConsistentPackage(package_with_dup_tx));
    package_with_dup_tx.emplace_back(create_placeholder_tx(1, 1));
    BOOST_CHECK(IsConsistentPackage(package_with_dup_tx));
}

BOOST_AUTO_TEST_CASE(package_validation_tests)
{
    LOCK(cs_main);
    unsigned int initialPoolSize = m_node.mempool->size();

    // Parent and Child Package
    CKey parent_key = GenerateRandomKey();
    CScript parent_locking_script = GetScriptForDestination(PKHash(parent_key.GetPubKey()));
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_locking_script,
                                                    /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);

    CKey child_key = GenerateRandomKey();
    CScript child_locking_script = GetScriptForDestination(PKHash(child_key.GetPubKey()));
    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/parent_key,
                                                   /*output_destination=*/child_locking_script,
                                                   /*output_amount=*/CAmount(48 * COIN), /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    Package package_parent_child{tx_parent, tx_child};
    const auto result_parent_child = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_parent_child, /*test_accept=*/true, /*client_maxfeerate=*/{});
    if (auto err_parent_child{CheckPackageMempoolAcceptResult(package_parent_child, result_parent_child, /*expect_valid=*/true, nullptr)}) {
        BOOST_ERROR(err_parent_child.value());
    } else {
        auto it_parent = result_parent_child.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child = result_parent_child.m_tx_results.find(tx_child->GetWitnessHash());

        BOOST_CHECK(it_parent->second.m_effective_feerate.value().GetFee(GetVirtualTransactionSize(*tx_parent)) == COIN);
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().front(), tx_parent->GetWitnessHash());

        BOOST_CHECK(it_child->second.m_effective_feerate.value().GetFee(GetVirtualTransactionSize(*tx_child)) == COIN);
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().front(), tx_child->GetWitnessHash());
    }
    // A single, giant transaction submitted through ProcessNewPackage fails on single tx policy.
    CTransactionRef giant_ptx = create_placeholder_tx(999, 999);
    BOOST_CHECK(GetVirtualTransactionSize(*giant_ptx) > DEFAULT_ANCESTOR_SIZE_LIMIT_KVB * 1000);
    Package package_single_giant{giant_ptx};
    auto result_single_large = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_single_giant, /*test_accept=*/true, /*client_maxfeerate=*/{});
    if (auto err_single_large{CheckPackageMempoolAcceptResult(package_single_giant, result_single_large, /*expect_valid=*/false, nullptr)}) {
        BOOST_ERROR(err_single_large.value());
    } else {
        BOOST_CHECK_EQUAL(result_single_large.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        BOOST_CHECK_EQUAL(result_single_large.m_state.GetRejectReason(), "transaction failed");
        auto it_giant_tx = result_single_large.m_tx_results.find(giant_ptx->GetWitnessHash());
        BOOST_CHECK_EQUAL(it_giant_tx->second.m_state.GetRejectReason(), "tx-size");
    }

    // Check that mempool size hasn't changed.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);
}

BOOST_AUTO_TEST_CASE(noncontextual_package_tests)
{
    // The signatures won't be verified so we can just use a placeholder
    CKey placeholder_key = GenerateRandomKey();
    CScript spk = GetScriptForDestination(PKHash(placeholder_key.GetPubKey()));
    CKey placeholder_key_2 = GenerateRandomKey();
    CScript spk2 = GetScriptForDestination(PKHash(placeholder_key_2.GetPubKey()));

    // Parent and Child Package
    {
        auto mtx_parent = CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 0, coinbaseKey, spk,
                                                        CAmount(49 * COIN), /*submit=*/false);
        CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);

        auto mtx_child = CreateValidMempoolTransaction(tx_parent, 0, 101, placeholder_key, spk2,
                                                       CAmount(48 * COIN), /*submit=*/false);
        CTransactionRef tx_child = MakeTransactionRef(mtx_child);

        PackageValidationState state;
        BOOST_CHECK(IsWellFormedPackage({tx_parent, tx_child}, state, /*require_sorted=*/true));
        BOOST_CHECK(!IsWellFormedPackage({tx_child, tx_parent}, state, /*require_sorted=*/true));
        BOOST_CHECK_EQUAL(state.GetResult(), PackageValidationResult::PCKG_POLICY);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "package-not-sorted");
        BOOST_CHECK(IsChildWithParents({tx_parent, tx_child}));
        BOOST_CHECK(GetPackageHash({tx_parent}) != GetPackageHash({tx_child}));
        BOOST_CHECK(GetPackageHash({tx_child, tx_child}) != GetPackageHash({tx_child}));
        BOOST_CHECK(GetPackageHash({tx_child, tx_parent}) != GetPackageHash({tx_child, tx_child}));
        BOOST_CHECK(!IsChildWithParents({}));
    }

    // 24 Parents and 1 Child
    {
        Package package;
        CMutableTransaction child;
        for (int i{0}; i < 24; ++i) {
            auto parent = MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[i + 1],
                                             0, 0, coinbaseKey, spk, CAmount(48 * COIN), false));
            package.emplace_back(parent);
            child.vin.emplace_back(COutPoint(parent->GetHash(), 0));
        }
        child.vout.emplace_back(47 * COIN, spk2);

        // The child must be in the package.
        BOOST_CHECK(!IsChildWithParents(package));

        // The parents can be in any order.
        FastRandomContext rng;
        std::shuffle(package.begin(), package.end(), rng);
        package.push_back(MakeTransactionRef(child));

        PackageValidationState state;
        BOOST_CHECK(IsWellFormedPackage(package, state, /*require_sorted=*/true));
        BOOST_CHECK(IsChildWithParents(package));

        package.erase(package.begin());
        BOOST_CHECK(IsChildWithParents(package));

        // The package cannot have unrelated transactions.
        package.insert(package.begin(), m_coinbase_txns[0]);
        BOOST_CHECK(!IsChildWithParents(package));
    }

    // 2 Parents and 1 Child where one parent depends on the other.
    {
        CMutableTransaction mtx_parent;
        mtx_parent.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
        mtx_parent.vout.emplace_back(20 * COIN, spk);
        mtx_parent.vout.emplace_back(20 * COIN, spk2);
        CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);

        CMutableTransaction mtx_parent_also_child;
        mtx_parent_also_child.vin.emplace_back(COutPoint(tx_parent->GetHash(), 0));
        mtx_parent_also_child.vout.emplace_back(20 * COIN, spk);
        CTransactionRef tx_parent_also_child = MakeTransactionRef(mtx_parent_also_child);

        CMutableTransaction mtx_child;
        mtx_child.vin.emplace_back(COutPoint(tx_parent->GetHash(), 1));
        mtx_child.vin.emplace_back(COutPoint(tx_parent_also_child->GetHash(), 0));
        mtx_child.vout.emplace_back(39 * COIN, spk);
        CTransactionRef tx_child = MakeTransactionRef(mtx_child);

        PackageValidationState state;
        BOOST_CHECK(IsChildWithParents({tx_parent, tx_parent_also_child}));
        BOOST_CHECK(IsChildWithParents({tx_parent, tx_child}));
        BOOST_CHECK(IsChildWithParents({tx_parent, tx_parent_also_child, tx_child}));
        // IsChildWithParents does not detect unsorted parents.
        BOOST_CHECK(IsChildWithParents({tx_parent_also_child, tx_parent, tx_child}));
        BOOST_CHECK(IsWellFormedPackage({tx_parent, tx_parent_also_child, tx_child}, state, /*require_sorted=*/true));
        BOOST_CHECK(!IsWellFormedPackage({tx_parent_also_child, tx_parent, tx_child}, state, /*require_sorted=*/true));
        BOOST_CHECK_EQUAL(state.GetResult(), PackageValidationResult::PCKG_POLICY);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "package-not-sorted");
    }
}

BOOST_AUTO_TEST_CASE(package_topology)
{
    // Mine blocks to mature coinbases.
    mineBlocks(20);
    CFeeRate minfeerate(5000);
    MockMempoolMinFee(minfeerate);
    LOCK(cs_main);
    unsigned int expected_pool_size = m_node.mempool->size();
    CKey parent_key = GenerateRandomKey();
    CScript parent_locking_script = GetScriptForDestination(PKHash(parent_key.GetPubKey()));
    const CAmount coinbase_value{50 * COIN};
    const CAmount generous_fee{1000};

    Package package_unrelated;
    for (size_t i{0}; i < 10; ++i) {
        auto mtx = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[i], /*input_vout=*/0,
                                                 /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                 /*output_destination=*/parent_locking_script,
                                                 /*output_amount=*/coinbase_value - generous_fee, /*submit=*/false);
        package_unrelated.emplace_back(MakeTransactionRef(mtx));
    }
    auto result_unrelated_submit = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                     package_unrelated, /*test_accept=*/false, /*client_maxfeerate=*/{});
    BOOST_CHECK(result_unrelated_submit.m_state.IsValid());
    expected_pool_size += 10;
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    // We should see a result for each transaction. They should have been validated individually.
    for (const auto& tx : package_unrelated) {
        auto it = result_unrelated_submit.m_tx_results.find(tx->GetWitnessHash());
        BOOST_CHECK(it != result_unrelated_submit.m_tx_results.end());
        BOOST_CHECK(it->second.m_state.IsValid());
        BOOST_CHECK_EQUAL(it->second.m_wtxids_fee_calculations.value().size(), 1);
    }
    // Parent and Child (and Grandchild) Package
    Package package_3gen;
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[10], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_locking_script,
                                                    /*output_amount=*/coinbase_value - generous_fee, /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);
    package_3gen.push_back(tx_parent);

    CKey child_key = GenerateRandomKey();
    CScript child_locking_script = GetScriptForDestination(PKHash(child_key.GetPubKey()));
    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/parent_key,
                                                   /*output_destination=*/child_locking_script,
                                                   /*output_amount=*/coinbase_value - 2 * generous_fee, /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    package_3gen.push_back(tx_child);

    CKey grandchild_key = GenerateRandomKey();
    CScript grandchild_locking_script = GetScriptForDestination(PKHash(grandchild_key.GetPubKey()));
    auto mtx_grandchild = CreateValidMempoolTransaction(/*input_transaction=*/tx_child, /*input_vout=*/0,
                                                       /*input_height=*/101, /*input_signing_key=*/child_key,
                                                       /*output_destination=*/grandchild_locking_script,
                                                       /*output_amount=*/coinbase_value - 3 * generous_fee, /*submit=*/false);
    CTransactionRef tx_grandchild = MakeTransactionRef(mtx_grandchild);
    package_3gen.push_back(tx_grandchild);

    // Submit package parent + child + grandchild.
    {
        auto result_3gen_submit = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                    package_3gen, /*test_accept=*/false, /*client_maxfeerate=*/{});
        expected_pool_size += 3;
        BOOST_CHECK_MESSAGE(result_3gen_submit.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << result_3gen_submit.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(result_3gen_submit.m_tx_results.size(), package_3gen.size());
        auto it_parent = result_3gen_submit.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child = result_3gen_submit.m_tx_results.find(tx_child->GetWitnessHash());
        auto it_grandchild = result_3gen_submit.m_tx_results.find(tx_grandchild->GetWitnessHash());

        BOOST_CHECK(it_parent->second.m_effective_feerate == CFeeRate(generous_fee, GetVirtualTransactionSize(*tx_parent)));
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().front(), tx_parent->GetWitnessHash());
        BOOST_CHECK(it_child->second.m_effective_feerate == CFeeRate(generous_fee, GetVirtualTransactionSize(*tx_child)));
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().front(), tx_child->GetWitnessHash());

        BOOST_CHECK(it_grandchild->second.m_effective_feerate == CFeeRate(generous_fee, GetVirtualTransactionSize(*tx_grandchild)));
        BOOST_CHECK_EQUAL(it_grandchild->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_grandchild->second.m_wtxids_fee_calculations.value().front(), tx_grandchild->GetWitnessHash());

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }
}

BOOST_AUTO_TEST_CASE(package_submission_tests)
{
    // Mine blocks to mature coinbases.
    mineBlocks(60);
    CFeeRate minfeerate(5000);
    MockMempoolMinFee(minfeerate);
    LOCK(cs_main);
    unsigned int expected_pool_size = m_node.mempool->size();
    CKey parent_key = GenerateRandomKey();
    CScript parent_locking_script = GetScriptForDestination(PKHash(parent_key.GetPubKey()));
    const CAmount coinbase_value{50 * COIN};

    // Parent and Child
    Package package_parent_child;
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_locking_script,
                                                    /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);
    package_parent_child.push_back(tx_parent);

    CKey child_key = GenerateRandomKey();
    CScript child_locking_script = GetScriptForDestination(PKHash(child_key.GetPubKey()));
    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/parent_key,
                                                   /*output_destination=*/child_locking_script,
                                                   /*output_amount=*/CAmount(48 * COIN), /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    package_parent_child.push_back(tx_child);

    // Parent and child package where transactions are invalid for reasons other than fee and
    // missing inputs, so the package validation isn't expected to happen.
    {
        CScriptWitness bad_witness;
        bad_witness.stack.emplace_back(1);
        CMutableTransaction mtx_parent_invalid{mtx_parent};
        mtx_parent_invalid.vin[0].scriptWitness = bad_witness;
        CTransactionRef tx_parent_invalid = MakeTransactionRef(mtx_parent_invalid);
        Package package_invalid_parent{tx_parent_invalid, tx_child};
        auto result_quit_early = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   package_invalid_parent, /*test_accept=*/ false, /*client_maxfeerate=*/{});
        if (auto err_parent_invalid{CheckPackageMempoolAcceptResult(package_invalid_parent, result_quit_early, /*expect_valid=*/false, m_node.mempool.get())}) {
            BOOST_ERROR(err_parent_invalid.value());
        } else {
            auto it_parent = result_quit_early.m_tx_results.find(tx_parent_invalid->GetWitnessHash());
            auto it_child = result_quit_early.m_tx_results.find(tx_child->GetWitnessHash());
            BOOST_CHECK_EQUAL(it_parent->second.m_state.GetResult(), TxValidationResult::TX_WITNESS_MUTATED);
            BOOST_CHECK_EQUAL(it_parent->second.m_state.GetRejectReason(), "bad-witness-nonstandard");
            BOOST_CHECK_EQUAL(it_child->second.m_state.GetResult(), TxValidationResult::TX_MISSING_INPUTS);
            BOOST_CHECK_EQUAL(it_child->second.m_state.GetRejectReason(), "bad-txns-inputs-missingorspent");
        }
        BOOST_CHECK_EQUAL(result_quit_early.m_state.GetResult(), PackageValidationResult::PCKG_TX);
    }

    // Submit package parent + child
    {
        auto result_parent_child_submit = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                    package_parent_child, /*test_accept=*/false, /*client_maxfeerate=*/{});
        expected_pool_size += 2;
        BOOST_CHECK_MESSAGE(result_parent_child_submit.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << result_parent_child_submit.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(result_parent_child_submit.m_tx_results.size(), package_parent_child.size());
        auto it_parent = result_parent_child_submit.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child = result_parent_child_submit.m_tx_results.find(tx_child->GetWitnessHash());

        BOOST_CHECK(it_parent->second.m_effective_feerate == CFeeRate(COIN, GetVirtualTransactionSize(*tx_parent)));
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().front(), tx_parent->GetWitnessHash());
        BOOST_CHECK(it_child->second.m_effective_feerate == CFeeRate(COIN, GetVirtualTransactionSize(*tx_child)));
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().front(), tx_child->GetWitnessHash());

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // Already-in-mempool transactions should be detected and de-duplicated.
    {
        const auto submit_deduped = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                      package_parent_child, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_deduped{CheckPackageMempoolAcceptResult(package_parent_child, submit_deduped, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_deduped.value());
        } else {
            auto it_parent_deduped = submit_deduped.m_tx_results.find(tx_parent->GetWitnessHash());
            auto it_child_deduped = submit_deduped.m_tx_results.find(tx_child->GetWitnessHash());
            BOOST_CHECK(it_parent_deduped->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
            BOOST_CHECK(it_child_deduped->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
        }

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // In-mempool parent and child with missing parent.
    {
        auto tx_parent_1 = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[1], /*input_vout=*/0,
                                                                            /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                                            /*output_destination=*/parent_locking_script,
                                                                            /*output_amount=*/CAmount(50 * COIN - low_fee_amt), /*submit=*/false));
        auto tx_parent_2 = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[2], /*input_vout=*/0,
                                                                            /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                                            /*output_destination=*/parent_locking_script,
                                                                            /*output_amount=*/CAmount(50 * COIN - 800), /*submit=*/false));

        auto tx_child_missing_parent = MakeTransactionRef(CreateValidMempoolTransaction({tx_parent_1, tx_parent_2},
                                                                                        {{tx_parent_1->GetHash(), 0}, {tx_parent_2->GetHash(), 0}},
                                                                                        /*input_height=*/0, {parent_key},
                                                                                        {{49 * COIN, child_locking_script}}, /*submit=*/false));

        Package package_missing_parent{tx_parent_1, tx_child_missing_parent};

        const auto result_missing_parent = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                             package_missing_parent, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_missing_parent{CheckPackageMempoolAcceptResult(package_missing_parent, result_missing_parent, /*expect_valid=*/false, m_node.mempool.get())}) {
            BOOST_ERROR(err_missing_parent.value());
        } else {
            auto it_parent = result_missing_parent.m_tx_results.find(tx_parent_1->GetWitnessHash());
            auto it_child = result_missing_parent.m_tx_results.find(tx_child_missing_parent->GetWitnessHash());

            BOOST_CHECK_EQUAL(result_missing_parent.m_state.GetResult(), PackageValidationResult::PCKG_TX);
            BOOST_CHECK_EQUAL(result_missing_parent.m_state.GetRejectReason(), "transaction failed");

            BOOST_CHECK_EQUAL(it_parent->second.m_state.GetResult(), TxValidationResult::TX_RECONSIDERABLE);
            BOOST_CHECK_EQUAL(it_child->second.m_state.GetResult(), TxValidationResult::TX_MISSING_INPUTS);
            BOOST_CHECK_EQUAL(it_child->second.m_state.GetRejectReason(), "bad-txns-inputs-missingorspent");
            BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        }

        // Submit parent2 ahead of time, should become ok.
        Package package_just_parent2{tx_parent_2};
        expected_pool_size += 1;
        const auto result_just_parent2 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                           package_just_parent2, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_parent2{CheckPackageMempoolAcceptResult(package_just_parent2, result_just_parent2, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_parent2.value());
        }
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        const auto result_parent_already_in = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                                package_missing_parent, /*test_accept=*/false, /*client_maxfeerate=*/{});
        expected_pool_size += 2;
        if (auto err_parent_already_in{CheckPackageMempoolAcceptResult(package_missing_parent, result_parent_already_in, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_parent_already_in.value());
        }
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // do not allow parents to pay for children
    {
        Package package_ppfc;
        // Diamond shape:
        //
        //     grandparent
        //      1.1sat/vB
        //     ^    ^    ^
        //  parent1 |  parent2
        //120sat/vB | 120sat/vB
        //       ^  |  ^
        //        child
        //       1sat/vB
        //
        // grandparent is below minfeerate
        // {grandparent + parent1} and {grandparent + parent2} are both below minfeerate
        // {grandparent + parent1 + parent2} is above minfeerate
        // child is below minfeerate
        // {grandparent + parent1 + parent2 + child} is above minfeerate, so they should be accepted
        const CFeeRate grandparent_feerate(1100);
        const CFeeRate parent_feerate(120 * 1000);
        const CFeeRate child_feerate(1000);
        std::vector<CTransactionRef> grandparent_input_txns;
        std::vector<COutPoint> grandparent_inputs;
        for (auto i{1}; i < 50; ++i) {
            grandparent_input_txns.emplace_back(m_coinbase_txns[i + 2]);
            grandparent_inputs.emplace_back(m_coinbase_txns[i + 2]->GetHash(), 0);
        }
        const CAmount init_parent_value{10*COIN};
        CAmount init_last_value = grandparent_inputs.size() * coinbase_value - 2 * init_parent_value;
        auto [mtx_grandparent, grandparent_fee] = CreateValidTransaction(/*input_transactions=*/grandparent_input_txns,
                                                                         /*inputs=*/grandparent_inputs,
                                                                         /*input_height=*/102,
                                                                         /*input_signing_keys=*/{coinbaseKey},
                                                                         /*outputs=*/{CTxOut{init_parent_value, parent_locking_script},
                                                                                      CTxOut{init_parent_value, parent_locking_script},
                                                                                      CTxOut{init_last_value, parent_locking_script}},
                                                                         /*feerate=*/grandparent_feerate,
                                                                         /*fee_output=*/2);
        CTransactionRef tx_grandparent = MakeTransactionRef(mtx_grandparent);
        package_ppfc.emplace_back(tx_grandparent);

        auto [mtx_parent1, parent_fee] = CreateValidTransaction(/*input_transactions=*/{tx_grandparent},
                                                                /*inputs=*/{COutPoint{tx_grandparent->GetHash(), 0}},
                                                                /*input_height=*/102,
                                                                /*input_signing_keys=*/{parent_key},
                                                                /*outputs=*/{CTxOut{init_parent_value, child_locking_script}},
                                                                /*feerate=*/parent_feerate,
                                                                /*fee_output=*/0);
        CTransactionRef tx_parent1 = MakeTransactionRef(mtx_parent1);
        package_ppfc.emplace_back(tx_parent1);
        auto [mtx_parent2, _] = CreateValidTransaction(/*input_transactions=*/{tx_grandparent},
                                                       /*inputs=*/{COutPoint{tx_grandparent->GetHash(), 1}},
                                                       /*input_height=*/102,
                                                       /*input_signing_keys=*/{parent_key},
                                                       /*outputs=*/{CTxOut{init_parent_value, child_locking_script}},
                                                       /*feerate=*/parent_feerate,
                                                       /*fee_output=*/0);
        CTransactionRef tx_parent2 = MakeTransactionRef(mtx_parent2);
        package_ppfc.emplace_back(tx_parent2);

        const CAmount child_value = grandparent_inputs.size() * coinbase_value;
        auto [mtx_child, child_fee] = CreateValidTransaction(/*input_transactions=*/package_ppfc,
                                                             /*inputs=*/{COutPoint{tx_grandparent->GetHash(), 2},
                                                                         COutPoint{tx_parent1->GetHash(), 0},
                                                                         COutPoint{tx_parent2->GetHash(), 0}},
                                                             /*input_height=*/102,
                                                             /*input_signing_keys=*/{coinbaseKey, parent_key, child_key},
                                                             /*outputs=*/{CTxOut{child_value, child_locking_script}},
                                                             /*feerate=*/child_feerate,
                                                             /*fee_output=*/0);

        CTransactionRef tx_child = MakeTransactionRef(mtx_child);
        package_ppfc.emplace_back(tx_child);

        // Neither parent can pay for the grandparent by itself
        BOOST_CHECK(minfeerate.GetFee(GetVirtualTransactionSize(*tx_grandparent) + GetVirtualTransactionSize(*tx_parent1)) > grandparent_fee + parent_fee);
        BOOST_CHECK(minfeerate.GetFee(GetVirtualTransactionSize(*tx_grandparent) + GetVirtualTransactionSize(*tx_parent2)) > grandparent_fee + parent_fee);
        const auto parents_vsize = GetVirtualTransactionSize(*tx_grandparent) + GetVirtualTransactionSize(*tx_parent1) + GetVirtualTransactionSize(*tx_parent2);
        // Combined, they can pay for the grandparent
        BOOST_CHECK(minfeerate.GetFee(parents_vsize) <= grandparent_fee + 2 * parent_fee);
        const auto total_vsize = parents_vsize + GetVirtualTransactionSize(*tx_child);
        BOOST_CHECK(minfeerate.GetFee(GetVirtualTransactionSize(*tx_child)) > child_fee);
        // Child feerate is less than the package feerate
        BOOST_CHECK(CFeeRate(child_fee, GetVirtualTransactionSize(*tx_child)) < CFeeRate(grandparent_fee + 2 * parent_fee + child_fee, total_vsize));

        const auto result_ppfc = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_ppfc, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_ppfc{CheckPackageMempoolAcceptResult(package_ppfc, result_ppfc, /*expect_valid=*/false, m_node.mempool.get())}) {
            BOOST_ERROR(err_ppfc.value());
        } else {
            BOOST_CHECK(result_ppfc.m_state.IsInvalid());
            BOOST_CHECK(result_ppfc.m_tx_results.at(tx_grandparent->GetWitnessHash()).m_state.IsValid());
            BOOST_CHECK(result_ppfc.m_tx_results.at(tx_parent1->GetWitnessHash()).m_state.IsValid());
            BOOST_CHECK(result_ppfc.m_tx_results.at(tx_parent2->GetWitnessHash()).m_state.IsValid());
            BOOST_CHECK(result_ppfc.m_tx_results.at(tx_child->GetWitnessHash()).m_state.IsInvalid());
            BOOST_CHECK_EQUAL(result_ppfc.m_tx_results.at(tx_child->GetWitnessHash()).m_state.GetResult(), TxValidationResult::TX_RECONSIDERABLE);

            CFeeRate feerate_1p2c(grandparent_fee + parent_fee + parent_fee,
                GetVirtualTransactionSize(*tx_grandparent) + GetVirtualTransactionSize(*tx_parent1) + GetVirtualTransactionSize(*tx_parent2));
            BOOST_CHECK_EQUAL(result_ppfc.m_tx_results.at(tx_grandparent->GetWitnessHash()).m_effective_feerate.value().GetFeePerK(), feerate_1p2c.GetFeePerK());
            BOOST_CHECK_EQUAL(result_ppfc.m_tx_results.at(tx_parent1->GetWitnessHash()).m_effective_feerate.value().GetFeePerK(), feerate_1p2c.GetFeePerK());
            BOOST_CHECK_EQUAL(result_ppfc.m_tx_results.at(tx_parent2->GetWitnessHash()).m_effective_feerate.value().GetFeePerK(), feerate_1p2c.GetFeePerK());
        }
        BOOST_CHECK_EQUAL(result_ppfc.m_state.GetRejectReason(), "transaction failed");
        expected_pool_size += 3;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }
}


BOOST_FIXTURE_TEST_CASE(package_missing_inputs, TestChain100Setup)
{
    CKey parent_key;
    parent_key.MakeNewKey(true);
    CScript parent_locking_script = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(parent_key.GetPubKey())));
    CKey child_key;
    child_key.MakeNewKey(true);
    CScript child_locking_script = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(child_key.GetPubKey())));
    std::string str;
    const CAmount coinbase_value{50 * COIN};

    // Create 2 conflicting transactions that both spend coinbase 0.
    auto coinbase0_spend1 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                          /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                          /*output_destination=*/parent_locking_script,
                                                          /*output_amount=*/coinbase_value - COIN, /*submit=*/false);
    auto coinbase0_spend2 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                          /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                          /*output_destination=*/parent_locking_script,
                                                          /*output_amount=*/coinbase_value - CENT, /*submit=*/false);

    // 1 parent and 1 child package. Parent is confirmed.
    Package package_confirmed_parent;
    CTransactionRef tx_confirmed_parent = MakeTransactionRef(coinbase0_spend1);
    package_confirmed_parent.emplace_back(tx_confirmed_parent);

    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_confirmed_parent, /*input_vout=*/0,
                                                   /*input_height=*/0, /*input_signing_key=*/parent_key,
                                                   /*output_destination=*/child_locking_script,
                                                   /*output_amount=*/CAmount(48 * COIN), /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    package_confirmed_parent.emplace_back(tx_child);

    // 2 parents and 1 child package. 1 parent conflicts with a confirmed tx.
    Package package_parent_dangles;
    auto tx_parent_dangle{MakeTransactionRef(coinbase0_spend2)};
    package_parent_dangles.emplace_back(tx_parent_dangle);
    auto mtx_parent_normal = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[1], /*input_vout=*/0,
                                                           /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                           /*output_destination=*/parent_locking_script,
                                                           /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    auto tx_parent_normal{MakeTransactionRef(mtx_parent_normal)};
    package_parent_dangles.emplace_back(tx_parent_normal);

    auto tx_child_dangles{MakeTransactionRef(CreateValidMempoolTransaction(/*input_transactions=*/package_parent_dangles,
                                                                           /*inputs=*/{COutPoint{tx_parent_dangle->GetHash(), 0},
                                                                                       COutPoint{tx_parent_normal->GetHash(), 0}},
                                                                           /*input_height=*/0,
                                                                           /*input_signing_keys=*/{parent_key},
                                                                           /*outputs=*/{CTxOut{96 * COIN, child_locking_script}},
                                                                           /*submit=*/false))};
    package_parent_dangles.emplace_back(tx_child_dangles);

    // Recently-confirmed transactions should be detected and skipped when possible.
    // Parent is confirmed
    CreateAndProcessBlock({coinbase0_spend1}, parent_locking_script);

    auto result_confirmed_parent = WITH_LOCK(cs_main,
        return ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_confirmed_parent, /*test_accept=*/false, /*client_maxfeerate=*/{}););
    if (auto err_confirmed_parent{CheckPackageMempoolAcceptResult(package_confirmed_parent, result_confirmed_parent, /*expect_valid=*/false, m_node.mempool.get())}) {
        BOOST_ERROR(err_confirmed_parent.value());
    } else {
        const auto& parent_result = result_confirmed_parent.m_tx_results.at(tx_confirmed_parent->GetWitnessHash());
        const auto& child_result = result_confirmed_parent.m_tx_results.at(tx_child->GetWitnessHash());
        BOOST_CHECK_EQUAL(parent_result.m_result_type, MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(parent_result.m_state.GetResult(), TxValidationResult::TX_CONFLICT);
        BOOST_CHECK_EQUAL(parent_result.m_state.GetRejectReason(), "txn-already-known");
        BOOST_CHECK_EQUAL(child_result.m_result_type, MempoolAcceptResult::ResultType::VALID);
    }

    // Transactions that dangle from a transaction with a missing
    // input are not validated, but the others can still be accepted.
    auto result_parent_dangles = WITH_LOCK(cs_main,
        return ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_parent_dangles, /*test_accept=*/false, /*client_maxfeerate=*/{}););
    if (auto err_dangle{CheckPackageMempoolAcceptResult(package_parent_dangles, result_parent_dangles, /*expect_valid=*/false, m_node.mempool.get())}) {
        BOOST_ERROR(err_dangle.value());
    } else {
        const auto& parent_dangle_result = result_parent_dangles.m_tx_results.at(tx_parent_dangle->GetWitnessHash());
        const auto& parent_normal_result = result_parent_dangles.m_tx_results.at(tx_parent_normal->GetWitnessHash());
        const auto& child_dangle_result = result_parent_dangles.m_tx_results.at(tx_child_dangles->GetWitnessHash());

        BOOST_CHECK_EQUAL(parent_dangle_result.m_result_type, MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(parent_dangle_result.m_state.GetResult(), TxValidationResult::TX_MISSING_INPUTS);
        BOOST_CHECK_EQUAL(parent_normal_result.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(child_dangle_result.m_result_type, MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(child_dangle_result.m_state.GetResult(), TxValidationResult::TX_MISSING_INPUTS);
    }
}

// Tests for packages containing a single transaction
BOOST_AUTO_TEST_CASE(package_single_tx)
{
    // Mine blocks to mature coinbases.
    mineBlocks(3);
    LOCK(cs_main);
    auto expected_pool_size{m_node.mempool->size()};

    const CAmount high_fee{1000};

    // No unconfirmed parents
    CKey single_key = GenerateRandomKey();
    CScript single_locking_script = GetScriptForDestination(PKHash(single_key.GetPubKey()));
    auto mtx_single = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/single_locking_script,
                                                    /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    CTransactionRef tx_single = MakeTransactionRef(mtx_single);
    Package package_tx_single{tx_single};
    const auto result_single_tx = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                    package_tx_single, /*test_accept=*/false, /*client_maxfeerate=*/{});
    expected_pool_size += 1;
    BOOST_CHECK_MESSAGE(result_single_tx.m_state.IsValid(),
                        "Package validation unexpectedly failed: " << result_single_tx.m_state.ToString());
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

    // Parent and Child. Both submitted by themselves through the ProcessNewPackage interface.
    CKey parent_key = GenerateRandomKey();
    CScript parent_locking_script = GetScriptForDestination(WitnessV0KeyHash(parent_key.GetPubKey()));
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[1], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_locking_script,
                                                    /*output_amount=*/CAmount(50 * COIN) - high_fee, /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);
    Package package_just_parent{tx_parent};
    const auto result_just_parent = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_just_parent, /*test_accept=*/false, /*client_maxfeerate=*/{});
    if (auto err_parent_child{CheckPackageMempoolAcceptResult(package_just_parent, result_just_parent, /*expect_valid=*/true, nullptr)}) {
        BOOST_ERROR(err_parent_child.value());
    } else {
        auto it_parent = result_just_parent.m_tx_results.find(tx_parent->GetWitnessHash());
        BOOST_CHECK_MESSAGE(it_parent->second.m_state.IsValid(), it_parent->second.m_state.ToString());
        BOOST_CHECK(it_parent->second.m_effective_feerate.value().GetFee(GetVirtualTransactionSize(*tx_parent)) == high_fee);
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().front(), tx_parent->GetWitnessHash());
    }
    expected_pool_size += 1;
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

    CKey child_key = GenerateRandomKey();
    CScript child_locking_script = GetScriptForDestination(WitnessV0KeyHash(child_key.GetPubKey()));
    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/parent_key,
                                                   /*output_destination=*/child_locking_script,
                                                   /*output_amount=*/CAmount(50 * COIN) - 2 * high_fee, /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    Package package_just_child{tx_child};
    const auto result_just_child = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_just_child, /*test_accept=*/false, /*client_maxfeerate=*/{});
    if (auto err_parent_child{CheckPackageMempoolAcceptResult(package_just_child, result_just_child, /*expect_valid=*/true, nullptr)}) {
        BOOST_ERROR(err_parent_child.value());
    } else {
        auto it_child = result_just_child.m_tx_results.find(tx_child->GetWitnessHash());
        BOOST_CHECK_MESSAGE(it_child->second.m_state.IsValid(), it_child->second.m_state.ToString());
        BOOST_CHECK(it_child->second.m_effective_feerate.value().GetFee(GetVirtualTransactionSize(*tx_child)) == high_fee);
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().front(), tx_child->GetWitnessHash());
    }
    expected_pool_size += 1;
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

    // Too-low fee to RBF tx_single
    auto mtx_single_low_fee = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/single_locking_script,
                                                    /*output_amount=*/CAmount(49 * COIN - 1), /*submit=*/false);
    CTransactionRef tx_single_low_fee = MakeTransactionRef(mtx_single_low_fee);
    Package package_tx_single_low_fee{tx_single_low_fee};
    const auto result_single_tx_low_fee = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                    package_tx_single_low_fee, /*test_accept=*/false, /*client_maxfeerate=*/{});

    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

    BOOST_CHECK(!result_single_tx_low_fee.m_state.IsValid());
    BOOST_CHECK_EQUAL(result_single_tx_low_fee.m_state.GetResult(), PackageValidationResult::PCKG_TX);
    auto it_low_fee = result_single_tx_low_fee.m_tx_results.find(tx_single_low_fee->GetWitnessHash());
    BOOST_CHECK_EQUAL(it_low_fee->second.m_state.GetResult(), TxValidationResult::TX_RECONSIDERABLE);
    if (auto err_single{CheckPackageMempoolAcceptResult(package_tx_single_low_fee, result_single_tx_low_fee, /*expect_valid=*/false, m_node.mempool.get())}) {
        BOOST_ERROR(err_single.value());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
}

// Tests for packages containing transactions that have same-txid-different-witness equivalents in
// the mempool.
BOOST_AUTO_TEST_CASE(package_witness_swap_tests)
{
    // Mine blocks to mature coinbases.
    mineBlocks(5);
    MockMempoolMinFee(CFeeRate(5000));
    LOCK(cs_main);

    // Transactions with a same-txid-different-witness transaction in the mempool should be ignored,
    // and the mempool entry's wtxid returned.
    CScript witnessScript = CScript() << OP_DROP << OP_TRUE;
    CScript scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/scriptPubKey,
                                                    /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    CTransactionRef ptx_parent = MakeTransactionRef(mtx_parent);

    // Make two children with the same txid but different witnesses.
    CScriptWitness witness1;
    witness1.stack.emplace_back(1);
    witness1.stack.emplace_back(witnessScript.begin(), witnessScript.end());

    CScriptWitness witness2(witness1);
    witness2.stack.emplace_back(2);
    witness2.stack.emplace_back(witnessScript.begin(), witnessScript.end());

    CKey child_key = GenerateRandomKey();
    CScript child_locking_script = GetScriptForDestination(WitnessV0KeyHash(child_key.GetPubKey()));
    CMutableTransaction mtx_child1;
    mtx_child1.version = 1;
    mtx_child1.vin.resize(1);
    mtx_child1.vin[0].prevout.hash = ptx_parent->GetHash();
    mtx_child1.vin[0].prevout.n = 0;
    mtx_child1.vin[0].scriptSig = CScript();
    mtx_child1.vin[0].scriptWitness = witness1;
    mtx_child1.vout.resize(1);
    mtx_child1.vout[0].nValue = CAmount(48 * COIN);
    mtx_child1.vout[0].scriptPubKey = child_locking_script;

    CMutableTransaction mtx_child2{mtx_child1};
    mtx_child2.vin[0].scriptWitness = witness2;

    CTransactionRef ptx_child1 = MakeTransactionRef(mtx_child1);
    CTransactionRef ptx_child2 = MakeTransactionRef(mtx_child2);

    // child1 and child2 have the same txid
    BOOST_CHECK_EQUAL(ptx_child1->GetHash(), ptx_child2->GetHash());
    // child1 and child2 have different wtxids
    BOOST_CHECK(ptx_child1->GetWitnessHash() != ptx_child2->GetWitnessHash());
    // Check that they have different package hashes
    BOOST_CHECK(GetPackageHash({ptx_parent, ptx_child1}) != GetPackageHash({ptx_parent, ptx_child2}));

    // Try submitting Package1{parent, child1} and Package2{parent, child2} where the children are
    // same-txid-different-witness.
    {
        Package package_parent_child1{ptx_parent, ptx_child1};
        const auto submit_witness1 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                       package_parent_child1, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_witness1{CheckPackageMempoolAcceptResult(package_parent_child1, submit_witness1, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_witness1.value());
        }

        // Child2 would have been validated individually.
        Package package_parent_child2{ptx_parent, ptx_child2};
        const auto submit_witness2 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                       package_parent_child2, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_witness2{CheckPackageMempoolAcceptResult(package_parent_child2, submit_witness2, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_witness2.value());
        } else {
            auto it_parent2_deduped = submit_witness2.m_tx_results.find(ptx_parent->GetWitnessHash());
            auto it_child2 = submit_witness2.m_tx_results.find(ptx_child2->GetWitnessHash());
            BOOST_CHECK(it_parent2_deduped->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
            BOOST_CHECK(it_child2->second.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS);
            BOOST_CHECK_EQUAL(ptx_child1->GetWitnessHash(), it_child2->second.m_other_wtxid.value());
        }

        // Deduplication should work when wtxid != txid. Submit package with the already-in-mempool
        // transactions again, which should not fail.
        const auto submit_segwit_dedup = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                           package_parent_child1, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_segwit_dedup{CheckPackageMempoolAcceptResult(package_parent_child1, submit_segwit_dedup, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_segwit_dedup.value());
        } else {
            auto it_parent_dup = submit_segwit_dedup.m_tx_results.find(ptx_parent->GetWitnessHash());
            auto it_child_dup = submit_segwit_dedup.m_tx_results.find(ptx_child1->GetWitnessHash());
            BOOST_CHECK(it_parent_dup->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
            BOOST_CHECK(it_child_dup->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
        }
    }

    // Try submitting Package1{child2, grandchild} where child2 is same-txid-different-witness as
    // the in-mempool transaction, child1. Since child1 exists in the mempool and its outputs are
    // available, child2 should be ignored and grandchild should be accepted.
    //
    // This tests a potential censorship vector in which an attacker broadcasts a competing package
    // where a parent's witness is mutated. The honest package should be accepted despite the fact
    // that we don't allow witness replacement.
    CKey grandchild_key = GenerateRandomKey();
    CScript grandchild_locking_script = GetScriptForDestination(WitnessV0KeyHash(grandchild_key.GetPubKey()));
    auto mtx_grandchild = CreateValidMempoolTransaction(/*input_transaction=*/ptx_child2, /*input_vout=*/0,
                                                        /*input_height=*/0, /*input_signing_key=*/child_key,
                                                        /*output_destination=*/grandchild_locking_script,
                                                        /*output_amount=*/CAmount(47 * COIN), /*submit=*/false);
    CTransactionRef ptx_grandchild = MakeTransactionRef(mtx_grandchild);
    // Check that they have different package hashes
    BOOST_CHECK(GetPackageHash({ptx_child1, ptx_grandchild}) != GetPackageHash({ptx_child2, ptx_grandchild}));
    // We already submitted child1 above.
    {
        Package package_child2_grandchild{ptx_child2, ptx_grandchild};
        const auto submit_spend_ignored = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                            package_child2_grandchild, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_spend_ignored{CheckPackageMempoolAcceptResult(package_child2_grandchild, submit_spend_ignored, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_spend_ignored.value());
        } else {
            auto it_child2_ignored = submit_spend_ignored.m_tx_results.find(ptx_child2->GetWitnessHash());
            auto it_grandchild = submit_spend_ignored.m_tx_results.find(ptx_grandchild->GetWitnessHash());
            BOOST_CHECK(it_child2_ignored->second.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS);
            BOOST_CHECK(it_grandchild->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        }
    }

    // A package Package{parent1, parent2, parent3, child} where the parents are a mixture of
    // identical-tx-in-mempool, same-txid-different-witness-in-mempool, and new transactions.
    Package package_mixed;

    // Give all the parents anyone-can-spend scripts so we don't have to deal with signing the child.
    CScript acs_script = CScript() << OP_TRUE;
    CScript acs_spk = GetScriptForDestination(WitnessV0ScriptHash(acs_script));
    CScriptWitness acs_witness;
    acs_witness.stack.emplace_back(acs_script.begin(), acs_script.end());

    // parent1 will already be in the mempool
    auto mtx_parent1 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[1], /*input_vout=*/0,
                                                     /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                     /*output_destination=*/acs_spk,
                                                     /*output_amount=*/CAmount(49 * COIN), /*submit=*/true);
    CTransactionRef ptx_parent1 = MakeTransactionRef(mtx_parent1);
    package_mixed.push_back(ptx_parent1);

    // parent2 will have a same-txid-different-witness tx already in the mempool
    CScript grandparent2_script = CScript() << OP_DROP << OP_TRUE;
    CScript grandparent2_spk = GetScriptForDestination(WitnessV0ScriptHash(grandparent2_script));
    CScriptWitness parent2_witness1;
    parent2_witness1.stack.emplace_back(1);
    parent2_witness1.stack.emplace_back(grandparent2_script.begin(), grandparent2_script.end());
    CScriptWitness parent2_witness2;
    parent2_witness2.stack.emplace_back(2);
    parent2_witness2.stack.emplace_back(grandparent2_script.begin(), grandparent2_script.end());

    // Create grandparent2 creating an output with multiple spending paths. Submit to mempool.
    auto mtx_grandparent2 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[2], /*input_vout=*/0,
                                                          /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                          /*output_destination=*/grandparent2_spk,
                                                          /*output_amount=*/CAmount(49 * COIN), /*submit=*/true);
    CTransactionRef ptx_grandparent2 = MakeTransactionRef(mtx_grandparent2);

    CMutableTransaction mtx_parent2_v1;
    mtx_parent2_v1.version = 1;
    mtx_parent2_v1.vin.resize(1);
    mtx_parent2_v1.vin[0].prevout.hash = ptx_grandparent2->GetHash();
    mtx_parent2_v1.vin[0].prevout.n = 0;
    mtx_parent2_v1.vin[0].scriptSig = CScript();
    mtx_parent2_v1.vin[0].scriptWitness = parent2_witness1;
    mtx_parent2_v1.vout.resize(1);
    mtx_parent2_v1.vout[0].nValue = CAmount(48 * COIN);
    mtx_parent2_v1.vout[0].scriptPubKey = acs_spk;

    CMutableTransaction mtx_parent2_v2{mtx_parent2_v1};
    mtx_parent2_v2.vin[0].scriptWitness = parent2_witness2;

    CTransactionRef ptx_parent2_v1 = MakeTransactionRef(mtx_parent2_v1);
    CTransactionRef ptx_parent2_v2 = MakeTransactionRef(mtx_parent2_v2);
    // Put parent2_v1 in the package, submit parent2_v2 to the mempool.
    const MempoolAcceptResult parent2_v2_result = m_node.chainman->ProcessTransaction(ptx_parent2_v2);
    BOOST_CHECK(parent2_v2_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    package_mixed.push_back(ptx_parent2_v1);

    // parent3 will be a new transaction. Put a low feerate to make it invalid on its own.
    auto mtx_parent3 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[3], /*input_vout=*/0,
                                                     /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                     /*output_destination=*/acs_spk,
                                                     /*output_amount=*/CAmount(50 * COIN - low_fee_amt), /*submit=*/false);
    CTransactionRef ptx_parent3 = MakeTransactionRef(mtx_parent3);
    package_mixed.push_back(ptx_parent3);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*ptx_parent3)) > low_fee_amt);
    BOOST_CHECK(m_node.mempool->m_opts.min_relay_feerate.GetFee(GetVirtualTransactionSize(*ptx_parent3)) <= low_fee_amt);

    // child spends parent1, parent2, and parent3
    CKey mixed_grandchild_key = GenerateRandomKey();
    CScript mixed_child_spk = GetScriptForDestination(WitnessV0KeyHash(mixed_grandchild_key.GetPubKey()));

    CMutableTransaction mtx_mixed_child;
    mtx_mixed_child.vin.emplace_back(COutPoint(ptx_parent1->GetHash(), 0));
    mtx_mixed_child.vin.emplace_back(COutPoint(ptx_parent2_v1->GetHash(), 0));
    mtx_mixed_child.vin.emplace_back(COutPoint(ptx_parent3->GetHash(), 0));
    mtx_mixed_child.vin[0].scriptWitness = acs_witness;
    mtx_mixed_child.vin[1].scriptWitness = acs_witness;
    mtx_mixed_child.vin[2].scriptWitness = acs_witness;
    mtx_mixed_child.vout.emplace_back((48 + 49 + 50 - 1) * COIN, mixed_child_spk);
    CTransactionRef ptx_mixed_child = MakeTransactionRef(mtx_mixed_child);
    package_mixed.push_back(ptx_mixed_child);

    // Submit package:
    // parent1 should be ignored
    // parent2_v1 should be ignored (and v2 wtxid returned)
    // parent3 should be accepted
    // child should be accepted
    {
        const auto mixed_result = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_mixed, false, /*client_maxfeerate=*/{});
        if (auto err_mixed{CheckPackageMempoolAcceptResult(package_mixed, mixed_result, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_mixed.value());
        } else {
            auto it_parent1 = mixed_result.m_tx_results.find(ptx_parent1->GetWitnessHash());
            auto it_parent2 = mixed_result.m_tx_results.find(ptx_parent2_v1->GetWitnessHash());
            auto it_parent3 = mixed_result.m_tx_results.find(ptx_parent3->GetWitnessHash());
            auto it_child = mixed_result.m_tx_results.find(ptx_mixed_child->GetWitnessHash());

            BOOST_CHECK(it_parent1->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
            BOOST_CHECK(it_parent2->second.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS);
            BOOST_CHECK(it_parent3->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
            BOOST_CHECK(it_child->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
            BOOST_CHECK_EQUAL(ptx_parent2_v2->GetWitnessHash(), it_parent2->second.m_other_wtxid.value());

            // package feerate should include parent3 and child. It should not include parent1 or parent2_v1.
            const CFeeRate expected_feerate(1 * COIN, GetVirtualTransactionSize(*ptx_parent3) + GetVirtualTransactionSize(*ptx_mixed_child));
            BOOST_CHECK(it_parent3->second.m_effective_feerate.value() == expected_feerate);
            BOOST_CHECK(it_child->second.m_effective_feerate.value() == expected_feerate);
            std::vector<Wtxid> expected_wtxids({ptx_parent3->GetWitnessHash(), ptx_mixed_child->GetWitnessHash()});
            BOOST_CHECK(it_parent3->second.m_wtxids_fee_calculations.value() == expected_wtxids);
            BOOST_CHECK(it_child->second.m_wtxids_fee_calculations.value() == expected_wtxids);
        }
    }
}

BOOST_AUTO_TEST_CASE(package_cpfp_tests)
{
    mineBlocks(6);
    MockMempoolMinFee(CFeeRate(5000));
    LOCK(::cs_main);
    size_t expected_pool_size = m_node.mempool->size();
    CKey child_key = GenerateRandomKey();
    CScript parent_spk = GetScriptForDestination(WitnessV0KeyHash(child_key.GetPubKey()));
    CKey grandchild_key = GenerateRandomKey();
    CScript child_spk = GetScriptForDestination(WitnessV0KeyHash(grandchild_key.GetPubKey()));

    // low-fee parent and high-fee child package
    const CAmount coinbase_value{50 * COIN};
    const CAmount parent_value{coinbase_value - low_fee_amt};
    const CAmount child_value{parent_value - COIN};

    Package package_cpfp;
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_spk,
                                                    /*output_amount=*/parent_value, /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);
    package_cpfp.push_back(tx_parent);

    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/child_key,
                                                   /*output_destination=*/child_spk,
                                                   /*output_amount=*/child_value, /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    package_cpfp.push_back(tx_child);

    // Package feerate is calculated using modified fees, and prioritisetransaction accepts negative
    // fee deltas. This should be taken into account. De-prioritise the parent transaction
    // to bring the package feerate to 0.
    m_node.mempool->PrioritiseTransaction(tx_parent->GetHash(), child_value - coinbase_value);
    for (auto test_accept : {true, false}) {
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_cpfp_deprio = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   package_cpfp, /*test_accept=*/ test_accept, /*client_maxfeerate=*/{});
        if (auto err_cpfp_deprio{CheckPackageMempoolAcceptResult(package_cpfp, submit_cpfp_deprio, /*expect_valid=*/false, test_accept ? nullptr : m_node.mempool.get())}) {
            BOOST_ERROR(err_cpfp_deprio.value());
        } else {
            BOOST_CHECK_EQUAL(submit_cpfp_deprio.m_state.GetResult(), PackageValidationResult::PCKG_TX);
            BOOST_CHECK_EQUAL(submit_cpfp_deprio.m_tx_results.find(tx_parent->GetWitnessHash())->second.m_state.GetResult(),
                              TxValidationResult::TX_MEMPOOL_POLICY);
            BOOST_CHECK_EQUAL(submit_cpfp_deprio.m_tx_results.find(tx_child->GetWitnessHash())->second.m_state.GetResult(),
                              TxValidationResult::TX_MISSING_INPUTS);
            BOOST_CHECK(submit_cpfp_deprio.m_tx_results.find(tx_parent->GetWitnessHash())->second.m_state.GetRejectReason() == "min relay fee not met");
            BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        }
    }

    // Clear the prioritisation of the parent transaction.
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->ClearPrioritisation(tx_parent->GetHash()));

    // Package CPFP: Even though the parent's feerate is below the mempool minimum feerate, the
    // child pays enough for the package feerate to meet the threshold.
    for (auto test_accept : {true, false}) {
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_cpfp = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   package_cpfp, /*test_accept=*/ test_accept, /*client_maxfeerate=*/{});
        if (auto err_cpfp{CheckPackageMempoolAcceptResult(package_cpfp, submit_cpfp, /*expect_valid=*/true, test_accept ? nullptr : m_node.mempool.get())}) {
            BOOST_ERROR(err_cpfp.value());
        } else {
            auto it_parent = submit_cpfp.m_tx_results.find(tx_parent->GetWitnessHash());
            auto it_child = submit_cpfp.m_tx_results.find(tx_child->GetWitnessHash());
            BOOST_CHECK_MESSAGE(it_parent->second.m_result_type == MempoolAcceptResult::ResultType::VALID, "failure: " << it_parent->second.m_state.GetRejectReason());
            BOOST_CHECK(it_parent->second.m_base_fees.value() == coinbase_value - parent_value);
            BOOST_CHECK_MESSAGE(it_child->second.m_result_type == MempoolAcceptResult::ResultType::VALID, "failure: " << it_child->second.m_state.GetRejectReason());
            BOOST_CHECK(it_child->second.m_base_fees.value() == COIN);

            const CFeeRate expected_feerate(coinbase_value - child_value,
                                            GetVirtualTransactionSize(*tx_parent) + GetVirtualTransactionSize(*tx_child));
            BOOST_CHECK(it_parent->second.m_effective_feerate.value() == expected_feerate);
            BOOST_CHECK(it_child->second.m_effective_feerate.value() == expected_feerate);
            std::vector<Wtxid> expected_wtxids({tx_parent->GetWitnessHash(), tx_child->GetWitnessHash()});
            BOOST_CHECK(it_parent->second.m_wtxids_fee_calculations.value() == expected_wtxids);
            BOOST_CHECK(it_child->second.m_wtxids_fee_calculations.value() == expected_wtxids);
            BOOST_CHECK(expected_feerate.GetFeePerK() > 1000);
        }
        expected_pool_size += test_accept ? 0 : 2;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // Just because we allow low-fee parents doesn't mean we allow low-feerate packages.
    // The mempool minimum feerate is 5sat/vB, but this package just pays 800 satoshis total.
    // The child fees would be able to pay for itself, but isn't enough for the entire package.
    Package package_still_too_low;
    const CAmount parent_fee{200};
    const CAmount child_fee{600};
    auto mtx_parent_cheap = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[1], /*input_vout=*/0,
                                                          /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                          /*output_destination=*/parent_spk,
                                                          /*output_amount=*/coinbase_value - parent_fee, /*submit=*/false);
    CTransactionRef tx_parent_cheap = MakeTransactionRef(mtx_parent_cheap);
    package_still_too_low.push_back(tx_parent_cheap);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*tx_parent_cheap)) > parent_fee);
    BOOST_CHECK(m_node.mempool->m_opts.min_relay_feerate.GetFee(GetVirtualTransactionSize(*tx_parent_cheap)) <= parent_fee);

    auto mtx_child_cheap = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent_cheap, /*input_vout=*/0,
                                                         /*input_height=*/101, /*input_signing_key=*/child_key,
                                                         /*output_destination=*/child_spk,
                                                         /*output_amount=*/coinbase_value - parent_fee - child_fee, /*submit=*/false);
    CTransactionRef tx_child_cheap = MakeTransactionRef(mtx_child_cheap);
    package_still_too_low.push_back(tx_child_cheap);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*tx_child_cheap)) <= child_fee);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*tx_parent_cheap) + GetVirtualTransactionSize(*tx_child_cheap)) > parent_fee + child_fee);
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

    // Cheap package should fail for being too low fee.
    for (auto test_accept : {true, false}) {
        const auto submit_package_too_low = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   package_still_too_low, /*test_accept=*/test_accept, /*client_maxfeerate=*/{});
        if (auto err_package_too_low{CheckPackageMempoolAcceptResult(package_still_too_low, submit_package_too_low, /*expect_valid=*/false, test_accept ? nullptr : m_node.mempool.get())}) {
            BOOST_ERROR(err_package_too_low.value());
        } else {
            // Package feerate of parent + child is too low.
            BOOST_CHECK_EQUAL(submit_package_too_low.m_tx_results.at(tx_parent_cheap->GetWitnessHash()).m_state.GetResult(),
                              TxValidationResult::TX_RECONSIDERABLE);
            BOOST_CHECK(submit_package_too_low.m_tx_results.at(tx_parent_cheap->GetWitnessHash()).m_effective_feerate.value() ==
                        CFeeRate(parent_fee + child_fee, GetVirtualTransactionSize(*tx_parent_cheap) + GetVirtualTransactionSize(*tx_child_cheap)));
            BOOST_CHECK_EQUAL(submit_package_too_low.m_tx_results.at(tx_child_cheap->GetWitnessHash()).m_state.GetResult(),
                              TxValidationResult::TX_RECONSIDERABLE);
            BOOST_CHECK(submit_package_too_low.m_tx_results.at(tx_child_cheap->GetWitnessHash()).m_effective_feerate.value() ==
                        CFeeRate(parent_fee + child_fee, GetVirtualTransactionSize(*tx_parent_cheap) + GetVirtualTransactionSize(*tx_child_cheap)));
        }
        BOOST_CHECK_EQUAL(submit_package_too_low.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        BOOST_CHECK_EQUAL(submit_package_too_low.m_state.GetRejectReason(), "transaction failed");
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // Package feerate includes the modified fees of the transactions.
    // This means a child with its fee delta from prioritisetransaction can pay for a parent.
    m_node.mempool->PrioritiseTransaction(tx_child_cheap->GetHash(), 1 * COIN);
    // Now that the child's fees have "increased" by 1 BTC, the cheap package should succeed.
    for (auto test_accept : {true, false}) {
        const auto submit_prioritised_package = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                                  package_still_too_low, /*test_accept=*/test_accept, /*client_maxfeerate=*/{});
        if (auto err_prioritised{CheckPackageMempoolAcceptResult(package_still_too_low, submit_prioritised_package, /*expect_valid=*/true, test_accept ? nullptr : m_node.mempool.get())}) {
            BOOST_ERROR(err_prioritised.value());
        } else {
            const CFeeRate expected_feerate(1 * COIN + parent_fee + child_fee,
                GetVirtualTransactionSize(*tx_parent_cheap) + GetVirtualTransactionSize(*tx_child_cheap));
            BOOST_CHECK_EQUAL(submit_prioritised_package.m_tx_results.size(), package_still_too_low.size());
            auto it_parent = submit_prioritised_package.m_tx_results.find(tx_parent_cheap->GetWitnessHash());
            auto it_child = submit_prioritised_package.m_tx_results.find(tx_child_cheap->GetWitnessHash());
            BOOST_CHECK(it_parent->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
            BOOST_CHECK(it_parent->second.m_base_fees.value() == parent_fee);
            BOOST_CHECK(it_parent->second.m_effective_feerate.value() == expected_feerate);
            BOOST_CHECK(it_child->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
            BOOST_CHECK(it_child->second.m_base_fees.value() == child_fee);
            BOOST_CHECK(it_child->second.m_effective_feerate.value() == expected_feerate);
            std::vector<Wtxid> expected_wtxids({tx_parent_cheap->GetWitnessHash(), tx_child_cheap->GetWitnessHash()});
            BOOST_CHECK(it_parent->second.m_wtxids_fee_calculations.value() == expected_wtxids);
            BOOST_CHECK(it_child->second.m_wtxids_fee_calculations.value() == expected_wtxids);
        }
        expected_pool_size += test_accept ? 0 : 2;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // Package feerate is calculated without topology in mind; it's just aggregating fees and sizes.
    // However, this should not allow parents to pay for children. Each transaction should be
    // validated individually first, eliminating sufficient-feerate parents before they are unfairly
    // included in the package feerate. It's also important that the low-fee child doesn't prevent
    // the parent from being accepted.
    Package package_rich_parent;
    const CAmount high_parent_fee{1 * COIN};
    auto mtx_parent_rich = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[2], /*input_vout=*/0,
                                                         /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                         /*output_destination=*/parent_spk,
                                                         /*output_amount=*/coinbase_value - high_parent_fee, /*submit=*/false);
    CTransactionRef tx_parent_rich = MakeTransactionRef(mtx_parent_rich);
    package_rich_parent.push_back(tx_parent_rich);

    auto mtx_child_poor = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent_rich, /*input_vout=*/0,
                                                        /*input_height=*/101, /*input_signing_key=*/child_key,
                                                        /*output_destination=*/child_spk,
                                                        /*output_amount=*/coinbase_value - high_parent_fee - low_fee_amt, /*submit=*/false);
    CTransactionRef tx_child_poor = MakeTransactionRef(mtx_child_poor);
    package_rich_parent.push_back(tx_child_poor);

    // Parent pays 1 BTC and child pays below mempool minimum feerate. The parent should be accepted without the child.
    for (auto test_accept : {true, false}) {
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_rich_parent = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                          package_rich_parent, /*test_accept=*/test_accept, /*client_maxfeerate=*/{});
        if (auto err_rich_parent{CheckPackageMempoolAcceptResult(package_rich_parent, submit_rich_parent, /*expect_valid=*/false, test_accept ? nullptr : m_node.mempool.get())}) {
            BOOST_ERROR(err_rich_parent.value());
        } else {
            // The child would have been validated on its own and failed.
            BOOST_CHECK_EQUAL(submit_rich_parent.m_state.GetResult(), PackageValidationResult::PCKG_TX);
            BOOST_CHECK_EQUAL(submit_rich_parent.m_state.GetRejectReason(), "transaction failed");

            auto it_parent = submit_rich_parent.m_tx_results.find(tx_parent_rich->GetWitnessHash());
            auto it_child = submit_rich_parent.m_tx_results.find(tx_child_poor->GetWitnessHash());
            BOOST_CHECK(it_parent->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
            BOOST_CHECK(it_child->second.m_result_type == MempoolAcceptResult::ResultType::INVALID);
            BOOST_CHECK(it_parent->second.m_state.GetRejectReason() == "");
            BOOST_CHECK_MESSAGE(it_parent->second.m_base_fees.value() == high_parent_fee,
                    strprintf("rich parent: expected fee %s, got %s", high_parent_fee, it_parent->second.m_base_fees.value()));
            BOOST_CHECK(it_parent->second.m_effective_feerate == CFeeRate(high_parent_fee, GetVirtualTransactionSize(*tx_parent_rich)));
            BOOST_CHECK_EQUAL(it_child->second.m_result_type, MempoolAcceptResult::ResultType::INVALID);
            BOOST_CHECK_EQUAL(it_child->second.m_state.GetResult(), TxValidationResult::TX_RECONSIDERABLE);
            BOOST_CHECK(it_child->second.m_state.GetRejectReason() == "mempool min fee not met");
        }
        expected_pool_size += test_accept ? 0 : 1;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // Package in which one of the transactions replaces something (by itself, without requiring
    // package RBF).
    const CAmount low_fee{1000};
    const CAmount med_fee{2000};
    const CAmount high_fee{3000};
    CTransactionRef txA_mempool = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[3], /*input_vout=*/0,
                                                                                    /*input_height=*/102, /*input_signing_key=*/coinbaseKey,
                                                                                    /*output_destination=*/parent_spk,
                                                                                    /*output_amount=*/coinbase_value - low_fee, /*submit=*/true));
    expected_pool_size += 1;
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

    Package package_with_rbf;
    // Conflicts with txA_mempool and can replace it.
    CTransactionRef txA_package = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[3], /*input_vout=*/0,
                                                                                    /*input_height=*/102, /*input_signing_key=*/coinbaseKey,
                                                                                    /*output_destination=*/parent_spk,
                                                                                    /*output_amount=*/coinbase_value - med_fee, /*submit=*/false));
    CTransactionRef txB_package = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[4], /*input_vout=*/0,
                                                                                    /*input_height=*/102, /*input_signing_key=*/coinbaseKey,
                                                                                    /*output_destination=*/parent_spk,
                                                                                    /*output_amount=*/coinbase_value - low_fee, /*submit=*/false));
    package_with_rbf.emplace_back(txA_package);
    package_with_rbf.emplace_back(txB_package);

    CTransactionRef txC_package = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transactions=*/package_with_rbf,
                                                                                    /*inputs=*/{COutPoint{txA_package->GetHash(), 0},
                                                                                                COutPoint{txB_package->GetHash(), 0}},
                                                                                    /*input_height=*/102,
                                                                                    /*input_signing_keys=*/{child_key},
                                                                                    /*outputs=*/{CTxOut{coinbase_value * 2 - low_fee - med_fee - high_fee, child_spk}},
                                                                                    /*submit=*/false));
    package_with_rbf.emplace_back(txC_package);

    // FIXME: This case requires subpackages to be split into individual transactions.
    for (auto test_accept : {false}) {
        const auto result_rbf = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_with_rbf, /*test_accept=*/test_accept, /*client_maxfeerate=*/{});
        // Replacement was accepted
        expected_pool_size += test_accept ? 0 : package_with_rbf.size() - 1;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK_EQUAL(result_rbf.m_tx_results.size(), package_with_rbf.size());
        BOOST_CHECK_MESSAGE(result_rbf.m_state.IsValid(),
            "failure: " << result_rbf.m_state.GetRejectReason() << " with " << result_rbf.m_tx_results.at(txA_package->GetWitnessHash()).m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(m_node.mempool->exists(txA_mempool->GetWitnessHash()), test_accept);
        for (size_t idx{0}; idx < package_with_rbf.size(); ++idx) {
            BOOST_CHECK_EQUAL(m_node.mempool->exists(package_with_rbf.at(idx)->GetWitnessHash()), !test_accept);
        }
    }
    // Again, we should accept the incentive-compatible transactions from the package. That could
    // mean rejecting the child but keeping some of the parents.
    // 2 parents and 1 child. Parent2 also spends Parent1. Child spends both.
    // Parent1 pays low fees, and Parent2 has a high feerate (enough to bump Parent1). Child pays low fees.
    // The correct behavior is to accept Parent1 and Parent2, but not the child.
    {
        Package package_ppfp;
        CTxOut parent_to_parent{25 * COIN - low_fee_amt, parent_spk};
        CTxOut parent_to_child{25 * COIN, child_spk};
        auto mtx_poor_parent = CreateValidMempoolTransaction(/*input_transactions=*/{m_coinbase_txns[5]},
                                                             /*inputs=*/{COutPoint{m_coinbase_txns[5]->GetHash(), 0}},
                                                             /*input_height=*/3,
                                                             /*input_signing_keys=*/{coinbaseKey},
                                                             /*outputs=*/{parent_to_parent, parent_to_child},
                                                             /*submit=*/false);
        auto tx_parent1 = MakeTransactionRef(mtx_poor_parent);
        package_ppfp.emplace_back(tx_parent1);

        // High feerate parent pays 1BTC in fees.
        const CAmount high_feerate_parent_output{25 * COIN - low_fee_amt - high_parent_fee};
        auto mtx_rich_parent = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent1,
                                                             /*input_vout=*/0,
                                                             /*input_height=*/103,
                                                             /*input_signing_key=*/child_key,
                                                             /*output_destination=*/parent_spk,
                                                             /*output_amount=*/high_feerate_parent_output,
                                                             /*submit=*/false);
        auto tx_parent2 = MakeTransactionRef(mtx_rich_parent);
        package_ppfp.emplace_back(tx_parent2);

        COutPoint parent1_1{tx_parent1->GetHash(), 1};
        COutPoint parent2_0{tx_parent2->GetHash(), 0};
        // Child pays low_fee_amt in fees.
        CTxOut child_out{coinbase_value - low_fee_amt - high_parent_fee - low_fee_amt, child_spk};
        auto mtx_child = CreateValidMempoolTransaction(/*input_transactions=*/{tx_parent1, tx_parent2},
                                                       /*inputs=*/{parent1_1, parent2_0},
                                                       /*input_height=*/103,
                                                       /*input_signing_keys=*/{child_key, grandchild_key},
                                                       /*outputs=*/{child_out},
                                                       /*submit=*/false);
        auto tx_child = MakeTransactionRef(mtx_child);
        package_ppfp.emplace_back(tx_child);

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_ppfp = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                           package_ppfp, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_ppfp{CheckPackageMempoolAcceptResult(package_ppfp, submit_ppfp, /*expect_valid=*/false, m_node.mempool.get())}) {
            BOOST_ERROR(err_ppfp.value());
        } else {
            const CFeeRate expected_feerate(low_fee_amt + high_parent_fee,
                                            GetVirtualTransactionSize(*tx_parent1) + GetVirtualTransactionSize(*tx_parent2));
            auto it_parent1 = submit_ppfp.m_tx_results.find(tx_parent1->GetWitnessHash());
            auto it_parent2 = submit_ppfp.m_tx_results.find(tx_parent2->GetWitnessHash());
            auto it_child = submit_ppfp.m_tx_results.find(tx_child->GetWitnessHash());
            BOOST_CHECK(it_parent1 != submit_ppfp.m_tx_results.end());
            BOOST_CHECK(it_parent2 != submit_ppfp.m_tx_results.end());
            BOOST_CHECK(it_child != submit_ppfp.m_tx_results.end());
            BOOST_CHECK_EQUAL(it_parent1->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
            BOOST_CHECK_EQUAL(it_parent2->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
            BOOST_CHECK(it_parent1->second.m_effective_feerate.value() == expected_feerate);
            BOOST_CHECK(it_parent2->second.m_effective_feerate.value() == expected_feerate);
        }
        expected_pool_size += 2;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK(m_node.mempool->exists(tx_parent1->GetHash()));
        BOOST_CHECK(m_node.mempool->exists(tx_parent2->GetHash()));
        BOOST_CHECK(!m_node.mempool->exists(tx_child->GetHash()));
    }
}

// Tests that show the benefits of linearization using fees.
BOOST_FIXTURE_TEST_CASE(linearization_tests, TestChain100Setup)
{
    mineBlocks(5);
    MockMempoolMinFee(CFeeRate(5000));
    LOCK(::cs_main);
    size_t expected_pool_size = m_node.mempool->size();
    CKey key1;
    CKey key2;
    CKey key3;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    key3.MakeNewKey(true);

    CScript spk1 = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(key1.GetPubKey())));
    CScript spk2 = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(key2.GetPubKey())));
    CScript spk3 = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(key3.GetPubKey())));

    const CAmount coinbase_value{50 * COIN};
    {
        // A package that exceeds descendant limits, but we should take the highest feerate one:
        //
        //          gen1
        //            ^
        //            .
        //            .
        //
        //            ^
        //          gen24
        //
        //       ^^^^^^^^^^
        //       10 parents
        //            ^
        //          child
        //
        // There are 10 parents with different feerates. Only 1 transaction can be accepted.
        // It should be the highest feerate one.

        // chain of 24 mempool transactions, each paying 1000sat
        const CAmount fee_per_mempool_tx{1000};
        CTransactionRef gen1_tx = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                                                  /*input_height=*/101, /*input_signing_key=*/coinbaseKey,
                                                                                  /*output_destination=*/spk1,
                                                                                  /*output_amount=*/coinbase_value - fee_per_mempool_tx, /*submit=*/true));
        CTransactionRef& last_tx = gen1_tx;
        for (auto i{2}; i <= 23; ++i) {
            last_tx = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/last_tx, /*input_vout=*/0,
                                                                       /*input_height=*/101, /*input_signing_key=*/key1,
                                                                       /*output_destination=*/spk1,
                                                                       /*output_amount=*/coinbase_value - (fee_per_mempool_tx * i),
                                                                       /*submit=*/true));
        }
        // The 24th transaction has 10 outputs, pays 3000sat fees.
        const CAmount amount_per_output{(coinbase_value - (23 * fee_per_mempool_tx) - 3000) / 10};

        std::vector<CKey> parent_keys;
        std::vector<CTxOut> gen24_outputs;
        for (auto o{0}; o < 10; ++o) {
            CKey parent_key;
            parent_key.MakeNewKey(true);
            CScript parent_spk = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(parent_key.GetPubKey())));
            gen24_outputs.emplace_back(amount_per_output, parent_spk);
            parent_keys.emplace_back(parent_key);
        }
        auto gen24_tx{MakeTransactionRef(CreateValidMempoolTransaction(/*input_transactions=*/{last_tx}, /*inputs=*/{COutPoint{last_tx->GetHash(), 0}},
                                                                       /*input_height=*/101, /*input_signing_keys=*/{key1},
                                                                       /*outputs=*/gen24_outputs, /*submit=*/true))};
        expected_pool_size += 24;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        Package package_desc_limits;
        std::vector<COutPoint> grandchild_outpoints;
        // Each parent pays 1000sat more than the previous one.
        for (auto parent_num{0}; parent_num < 10; ++parent_num) {
            auto parent_tx{MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/gen24_tx,
                                                                            /*input_vout=*/parent_num,
                                                                            /*input_height=*/101,
                                                                            /*input_signing_key=*/parent_keys.at(parent_num),
                                                                            /*output_destination=*/spk3,
                                                                            /*output_amount=*/amount_per_output - 1000 * (parent_num + 1),
                                                                            /*submit=*/false))};
            package_desc_limits.emplace_back(parent_tx);
            grandchild_outpoints.emplace_back(parent_tx->GetHash(), 0);
        }
        const auto& highest_feerate_parent_wtxid = package_desc_limits.back()->GetWitnessHash();
        // Child pays low fee (TODO: change this to be a CPFP to check that we can take subchunks)
        const CAmount child_value{(amount_per_output * 10 - 55 * 1000) - 1000};
        auto mtx_child{CreateValidMempoolTransaction(/*input_transactions=*/package_desc_limits,
                                                     /*inputs=*/grandchild_outpoints,
                                                     /*input_height=*/101,
                                                     /*input_signing_keys=*/{key3},
                                                     /*outputs=*/{CTxOut{child_value, spk1}},
                                                     /*submit=*/false)};
        CTransactionRef tx_child = MakeTransactionRef(mtx_child);
        package_desc_limits.emplace_back(tx_child);

        const auto result_desc_limits = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_desc_limits, /*test_accept=*/false, /*client_maxfeerate=*/{});
        if (auto err_desc_limits{CheckPackageMempoolAcceptResult(package_desc_limits, result_desc_limits, /*expect_valid=*/false, m_node.mempool.get())}) {
            BOOST_ERROR(err_desc_limits.value());
        } else {
            for (size_t idx{0}; idx < package_desc_limits.size(); ++idx) {
                const auto& txresult = result_desc_limits.m_tx_results.at(package_desc_limits.at(idx)->GetWitnessHash());
                if (idx == 9) {
                    // The last parent had the highest feerate and was accepted.
                    BOOST_CHECK(txresult.m_state.IsValid());
                } else if (idx == 8) {
                    // The second to last parent had the second highest feerate. It was submitted next and hit too-long-mempool-chain.
                    BOOST_CHECK_EQUAL(txresult.m_state.GetResult(), TxValidationResult::TX_MEMPOOL_POLICY);
                    BOOST_CHECK_EQUAL(txresult.m_state.GetRejectReason(), "too-long-mempool-chain");
                } else {
                    // Every else was skipped
                    BOOST_CHECK_EQUAL(txresult.m_state.GetResult(), TxValidationResult::TX_UNKNOWN);
                }
            }
        }
        BOOST_CHECK_EQUAL(result_desc_limits.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        expected_pool_size += 1;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK(m_node.mempool->exists(highest_feerate_parent_wtxid));
    }

    {
        // Package in which fee-based linearization will allow us to accept 4 instead of 1 transactions:
        // grandparent1  grandparent2 grandparent3
        //     3sat/vB     3sat/vB    20sat/vB
        //           ^     ^     ^    ^
        //          parent1     parent2
        //          8sat/vB     8sat/vB
        //         ^      ^      ^     ^
        //                  child
        //                 1sat/vB
        //
        //  child is also spending all the grandparents so that this is a child-with-parents package.
        const CFeeRate feerate_grandparents_low(3000);
        const CFeeRate feerate_grandparent_high(20000);
        const CFeeRate feerate_parents(8200);
        const CFeeRate feerate_child(1000);
        const CFeeRate mempool_min_feerate{m_node.mempool->GetMinFee()};

        BOOST_CHECK(feerate_grandparents_low < mempool_min_feerate);
        BOOST_CHECK(feerate_parents > mempool_min_feerate);
        BOOST_CHECK(feerate_child < mempool_min_feerate);

        const auto created_grandparent1 = CreateValidTransaction(/*input_transactions=*/{m_coinbase_txns[1]},
                                                                 /*inputs=*/{COutPoint{m_coinbase_txns[1]->GetHash(), 0}},
                                                                 /*input_height=*/101,
                                                                 /*input_signing_keys=*/{coinbaseKey},
                                                                 /*outputs=*/{CTxOut{coinbase_value / 3, spk1}, CTxOut{coinbase_value / 3, spk2}, CTxOut{coinbase_value / 3, spk3}},
                                                                 /*feerate=*/feerate_grandparents_low,
                                                                 /*fee_output=*/0);
        auto tx_grandparent1{MakeTransactionRef(created_grandparent1.first)};

        const auto created_grandparent2 = CreateValidTransaction(/*input_transactions=*/{m_coinbase_txns[2]},
                                                                 /*inputs=*/{COutPoint{m_coinbase_txns[2]->GetHash(), 0}},
                                                                 /*input_height=*/101,
                                                                 /*input_signing_keys=*/{coinbaseKey},
                                                                 /*outputs=*/{CTxOut{coinbase_value / 3, spk1}, CTxOut{coinbase_value / 3, spk2}, CTxOut{coinbase_value / 3, spk3}},
                                                                 /*feerate=*/feerate_grandparents_low,
                                                                 /*fee_output=*/0);
        auto tx_grandparent2{MakeTransactionRef(created_grandparent2.first)};

        const auto created_grandparent3 = CreateValidTransaction(/*input_transactions=*/{m_coinbase_txns[3]},
                                                                 /*inputs=*/{COutPoint{m_coinbase_txns[3]->GetHash(), 0}},
                                                                 /*input_height=*/101,
                                                                 /*input_signing_keys=*/{coinbaseKey},
                                                                 /*outputs=*/{CTxOut{coinbase_value / 3, spk1}, CTxOut{coinbase_value / 3, spk2}, CTxOut{coinbase_value / 3, spk3}},
                                                                 /*feerate=*/feerate_grandparent_high,
                                                                 /*fee_output=*/0);
        auto tx_grandparent3{MakeTransactionRef(created_grandparent3.first)};

        const auto created_parent1 = CreateValidTransaction(/*input_transactions=*/{tx_grandparent1, tx_grandparent2},
                                                            /*inputs=*/{COutPoint{tx_grandparent1->GetHash(), 0}, COutPoint{tx_grandparent2->GetHash(), 0}},
                                                            /*input_height=*/101,
                                                            /*input_signing_keys=*/{key1},
                                                            /*outputs=*/{CTxOut{coinbase_value * 2 / 3, spk3}},
                                                            /*feerate=*/feerate_parents,
                                                            /*fee_output=*/0);
        auto tx_parent1{MakeTransactionRef(created_parent1.first)};

        // parent1 is not able to CPFP both grandparents
        const auto vsize_grandparents_parent1{GetVirtualTransactionSize(*tx_grandparent1) + GetVirtualTransactionSize(*tx_grandparent2) + GetVirtualTransactionSize(*tx_parent1)};
        BOOST_CHECK(created_grandparent1.second + created_grandparent2.second + created_parent1.second < mempool_min_feerate.GetFee(vsize_grandparents_parent1));

        // But parent1 is able to CPFP grandparent1 (i.e. if grandparent2 has already been submitted)
        const auto vsize_pair1{GetVirtualTransactionSize(*tx_grandparent1) + GetVirtualTransactionSize(*tx_parent1)};
        BOOST_CHECK(created_grandparent1.second + created_parent1.second > mempool_min_feerate.GetFee(vsize_pair1));

        // Add coinbase output to increase the size of the transaction.
        const auto created_parent2 = CreateValidTransaction(/*input_transactions=*/{tx_grandparent2, tx_grandparent3},
                                                            /*inputs=*/{COutPoint{tx_grandparent2->GetHash(), 1}, COutPoint{tx_grandparent3->GetHash(), 1}},
                                                            /*input_height=*/101,
                                                            /*input_signing_keys=*/{key2},
                                                            /*outputs=*/{CTxOut{coinbase_value * 2 / 3, spk3}},
                                                            /*feerate=*/feerate_parents,
                                                            /*fee_output=*/0);
        auto tx_parent2{MakeTransactionRef(created_parent2.first)};

        // parent2 is able to CPFP grandparent2
        const auto vsize_pair2{GetVirtualTransactionSize(*tx_grandparent2) + GetVirtualTransactionSize(*tx_parent2)};
        BOOST_CHECK(created_grandparent2.second + created_parent2.second > mempool_min_feerate.GetFee(vsize_pair2));

        const auto created_child = CreateValidTransaction(/*input_transactions=*/{tx_grandparent1, tx_grandparent2, tx_grandparent3, tx_parent1, tx_parent2},
                                                          /*inputs=*/{COutPoint{tx_parent1->GetHash(), 0}, COutPoint{tx_parent2->GetHash(), 0},
                                                                      COutPoint{tx_grandparent1->GetHash(), 2}, COutPoint{tx_grandparent2->GetHash(), 2}, COutPoint{tx_grandparent3->GetHash(), 2}},
                                                          /*input_height=*/101,
                                                          /*input_signing_keys=*/{key3},
                                                          /*outputs=*/{CTxOut{3 * coinbase_value, spk1}},
                                                          /*feerate=*/feerate_child,
                                                          /*fee_output=*/0);
        auto tx_child{MakeTransactionRef(created_child.first)};

        Package package_needs_reorder{tx_grandparent1, tx_grandparent2, tx_grandparent3, tx_parent1, tx_parent2, tx_child};

        const auto result_needs_reorder = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_needs_reorder, /*test_accept=*/false, /*client_maxfeerate=*/{});
        // Everyone should be submitted except for the child which is below mempool minimum feerate
        BOOST_CHECK(m_node.mempool->exists(tx_grandparent1->GetWitnessHash()));
        BOOST_CHECK(m_node.mempool->exists(tx_grandparent2->GetWitnessHash()));
        BOOST_CHECK(m_node.mempool->exists(tx_grandparent3->GetWitnessHash()));
        BOOST_CHECK(m_node.mempool->exists(tx_parent1->GetWitnessHash()));
        BOOST_CHECK(m_node.mempool->exists(tx_parent2->GetWitnessHash()));
        BOOST_CHECK(!m_node.mempool->exists(tx_child->GetWitnessHash()));
        if (auto err_needs_reorder{CheckPackageMempoolAcceptResult(package_needs_reorder, result_needs_reorder, /*expect_valid=*/false, m_node.mempool.get())}) {
            BOOST_ERROR(err_needs_reorder.value());
        } else {
            BOOST_CHECK_EQUAL(result_needs_reorder.m_tx_results.at(tx_child->GetWitnessHash()).m_result_type, MempoolAcceptResult::ResultType::INVALID);
            BOOST_CHECK_EQUAL(result_needs_reorder.m_tx_results.at(tx_child->GetWitnessHash()).m_state.GetResult(), TxValidationResult::TX_RECONSIDERABLE);

            // grandparent3 got in by itself first ...
            BOOST_CHECK_EQUAL(result_needs_reorder.m_tx_results.at(tx_grandparent3->GetWitnessHash()).m_wtxids_fee_calculations->size(), 1);
            // ... then, grandparent2 + parent2
            std::vector<Wtxid> wtxids_pair2{tx_grandparent2->GetWitnessHash(),tx_parent2->GetWitnessHash()};
            BOOST_CHECK(result_needs_reorder.m_tx_results.at(tx_parent2->GetWitnessHash()).m_wtxids_fee_calculations.value() == wtxids_pair2);
            BOOST_CHECK(result_needs_reorder.m_tx_results.at(tx_grandparent2->GetWitnessHash()).m_wtxids_fee_calculations.value() == wtxids_pair2);
            // ... then, grandparent1 + parent1
            std::vector<Wtxid> wtxids_pair1{tx_grandparent1->GetWitnessHash(),tx_parent1->GetWitnessHash()};
            BOOST_CHECK(result_needs_reorder.m_tx_results.at(tx_parent1->GetWitnessHash()).m_wtxids_fee_calculations.value() == wtxids_pair1);
            BOOST_CHECK(result_needs_reorder.m_tx_results.at(tx_grandparent1->GetWitnessHash()).m_wtxids_fee_calculations.value() == wtxids_pair1);
        }
    }
}

BOOST_AUTO_TEST_CASE(package_rbf_tests)
{
    mineBlocks(5);
    LOCK(::cs_main);
    size_t expected_pool_size = m_node.mempool->size();
    CKey child_key{GenerateRandomKey()};
    CScript parent_spk = GetScriptForDestination(WitnessV0KeyHash(child_key.GetPubKey()));
    CKey grandchild_key{GenerateRandomKey()};
    CScript child_spk = GetScriptForDestination(WitnessV0KeyHash(grandchild_key.GetPubKey()));

    const CAmount coinbase_value{50 * COIN};
    // Test that de-duplication works. This is not actually package rbf.
    {
        // 1 parent paying 200sat, 1 child paying 300sat
        Package package1;
        // 1 parent paying 200sat, 1 child paying 500sat
        Package package2;
        // Package1 and package2 have the same parent. The children conflict.
        auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                        /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                        /*output_destination=*/parent_spk,
                                                        /*output_amount=*/coinbase_value - low_fee_amt, /*submit=*/false);
        CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);
        package1.push_back(tx_parent);
        package2.push_back(tx_parent);

        CTransactionRef tx_child_1 = MakeTransactionRef(CreateValidMempoolTransaction(tx_parent, 0, 101, child_key, child_spk, coinbase_value - low_fee_amt - 300, false));
        package1.push_back(tx_child_1);
        CTransactionRef tx_child_2 = MakeTransactionRef(CreateValidMempoolTransaction(tx_parent, 0, 101, child_key, child_spk, coinbase_value - low_fee_amt - 500, false));
        package2.push_back(tx_child_2);

        LOCK(m_node.mempool->cs);
        const auto submit1 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package1, /*test_accept=*/false, std::nullopt);
        if (auto err_1{CheckPackageMempoolAcceptResult(package1, submit1, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_1.value());
        }

        // Check precise ResultTypes and mempool size. We know it_parent_1 and it_child_1 exist from above call
        auto it_parent_1 = submit1.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child_1 = submit1.m_tx_results.find(tx_child_1->GetWitnessHash());
        BOOST_CHECK_EQUAL(it_parent_1->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(it_child_1->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        expected_pool_size += 2;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        const auto submit2 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package2, /*test_accept=*/false, std::nullopt);
        if (auto err_2{CheckPackageMempoolAcceptResult(package2, submit2, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_2.value());
        }

        // Check precise ResultTypes and mempool size. We know it_parent_2 and it_child_2 exist from above call
        auto it_parent_2 = submit2.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child_2 = submit2.m_tx_results.find(tx_child_2->GetWitnessHash());
        BOOST_CHECK_EQUAL(it_parent_2->second.m_result_type, MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
        BOOST_CHECK_EQUAL(it_child_2->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        // child1 has been replaced
        BOOST_CHECK(!m_node.mempool->exists(tx_child_1->GetHash()));
    }

    // Test package rbf.
    {
        CTransactionRef tx_parent_1 = MakeTransactionRef(CreateValidMempoolTransaction(
            m_coinbase_txns[1], /*input_vout=*/0, /*input_height=*/0,
            coinbaseKey, parent_spk, coinbase_value - 200, /*submit=*/false));
        CTransactionRef tx_child_1 = MakeTransactionRef(CreateValidMempoolTransaction(
            tx_parent_1, /*input_vout=*/0, /*input_height=*/101,
            child_key, child_spk, coinbase_value - 400, /*submit=*/false));

        CTransactionRef tx_parent_2 = MakeTransactionRef(CreateValidMempoolTransaction(
            m_coinbase_txns[1], /*input_vout=*/0, /*input_height=*/0,
            coinbaseKey, parent_spk, coinbase_value - 800, /*submit=*/false));
        CTransactionRef tx_child_2 = MakeTransactionRef(CreateValidMempoolTransaction(
            tx_parent_2, /*input_vout=*/0, /*input_height=*/101,
            child_key, child_spk, coinbase_value - 800 - 200, /*submit=*/false));

        CTransactionRef tx_parent_3 = MakeTransactionRef(CreateValidMempoolTransaction(
            m_coinbase_txns[1], /*input_vout=*/0, /*input_height=*/0,
            coinbaseKey, parent_spk, coinbase_value - 199, /*submit=*/false));
        CTransactionRef tx_child_3 = MakeTransactionRef(CreateValidMempoolTransaction(
            tx_parent_3, /*input_vout=*/0, /*input_height=*/101,
            child_key, child_spk, coinbase_value - 199 - 1300, /*submit=*/false));

        // In all packages, the parents conflict with each other
        BOOST_CHECK(tx_parent_1->GetHash() != tx_parent_2->GetHash() && tx_parent_2->GetHash() != tx_parent_3->GetHash());

        // 1 parent paying 200sat, 1 child paying 200sat.
        Package package1{tx_parent_1, tx_child_1};
        // 1 parent paying 800sat, 1 child paying 200sat.
        Package package2{tx_parent_2, tx_child_2};
        // 1 parent paying 199sat, 1 child paying 1300sat.
        Package package3{tx_parent_3, tx_child_3};

        const auto submit1 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package1, false, std::nullopt);
        if (auto err_1{CheckPackageMempoolAcceptResult(package1, submit1, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_1.value());
        }
        auto it_parent_1 = submit1.m_tx_results.find(tx_parent_1->GetWitnessHash());
        auto it_child_1 = submit1.m_tx_results.find(tx_child_1->GetWitnessHash());
        BOOST_CHECK_EQUAL(it_parent_1->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(it_child_1->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        expected_pool_size += 2;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        // This replacement is actually not package rbf; the parent carries enough fees
        // to replace the entire package on its own.
        const auto submit2 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package2, false, std::nullopt);
        if (auto err_2{CheckPackageMempoolAcceptResult(package2, submit2, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_2.value());
        }
        auto it_parent_2 = submit2.m_tx_results.find(tx_parent_2->GetWitnessHash());
        auto it_child_2 = submit2.m_tx_results.find(tx_child_2->GetWitnessHash());
        BOOST_CHECK_EQUAL(it_parent_2->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(it_child_2->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        // Package RBF, in which the replacement transaction's child sponsors the fees to meet RBF feerate rules
        const auto submit3 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package3, false, std::nullopt);
        if (auto err_3{CheckPackageMempoolAcceptResult(package3, submit3, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_3.value());
        }
        auto it_parent_3 = submit3.m_tx_results.find(tx_parent_3->GetWitnessHash());
        auto it_child_3 = submit3.m_tx_results.find(tx_child_3->GetWitnessHash());
        BOOST_CHECK_EQUAL(it_parent_3->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(it_child_3->second.m_result_type, MempoolAcceptResult::ResultType::VALID);

        // package3 was considered as a package to replace both package2 transactions
        BOOST_CHECK(it_parent_3->second.m_replaced_transactions.size() == 2);
        BOOST_CHECK(it_child_3->second.m_replaced_transactions.empty());

        std::vector<Wtxid> expected_package3_wtxids({tx_parent_3->GetWitnessHash(), tx_child_3->GetWitnessHash()});
        const auto package3_total_vsize{GetVirtualTransactionSize(*tx_parent_3) + GetVirtualTransactionSize(*tx_child_3)};
        BOOST_CHECK(it_parent_3->second.m_wtxids_fee_calculations.value() == expected_package3_wtxids);
        BOOST_CHECK(it_child_3->second.m_wtxids_fee_calculations.value() == expected_package3_wtxids);
        BOOST_CHECK_EQUAL(it_parent_3->second.m_effective_feerate.value().GetFee(package3_total_vsize), 199 + 1300);
        BOOST_CHECK_EQUAL(it_child_3->second.m_effective_feerate.value().GetFee(package3_total_vsize), 199 + 1300);

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        // Finally, check that we can prioritise tx_child_1 to get package1 into the mempool.
        // It should not be possible to resubmit package1 and get it in without prioritisation.
        const auto submit4 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package1, false, std::nullopt);
        if (auto err_4{CheckPackageMempoolAcceptResult(package1, submit4, /*expect_valid=*/false, m_node.mempool.get())}) {
            BOOST_ERROR(err_4.value());
        }
        m_node.mempool->PrioritiseTransaction(tx_child_1->GetHash(), 1363);
        const auto submit5 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package1, false, std::nullopt);
        if (auto err_5{CheckPackageMempoolAcceptResult(package1, submit5, /*expect_valid=*/true, m_node.mempool.get())}) {
            BOOST_ERROR(err_5.value());
        }
        it_parent_1 = submit5.m_tx_results.find(tx_parent_1->GetWitnessHash());
        it_child_1 = submit5.m_tx_results.find(tx_child_1->GetWitnessHash());
        BOOST_CHECK_EQUAL(it_parent_1->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(it_child_1->second.m_result_type, MempoolAcceptResult::ResultType::VALID);
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(m_node.mempool->GetIter(tx_parent_1->GetHash()).has_value());
        BOOST_CHECK(m_node.mempool->GetIter(tx_child_1->GetHash()).has_value());
    }
}
BOOST_AUTO_TEST_SUITE_END()
