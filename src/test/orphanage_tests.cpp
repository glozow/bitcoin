// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <consensus/validation.h>
#include <pubkey.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txorphanage.h>

#include <array>
#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(orphanage_tests, TestingSetup)

class TxOrphanageTest : public TxOrphanage
{
public:
    inline size_t CountOrphans() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_orphans.size();
    }

    CTransactionRef RandomOrphan() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        std::map<uint256, OrphanTx>::iterator it;
        it = m_orphans.lower_bound(InsecureRand256());
        if (it == m_orphans.end())
            it = m_orphans.begin();
        return it->second.tx;
    }
};

static void MakeNewKeyWithFastRandomContext(CKey& key)
{
    std::vector<unsigned char> keydata;
    keydata = g_insecure_rand_ctx.randbytes(32);
    key.Set(keydata.data(), keydata.data() + keydata.size(), /*fCompressedIn=*/true);
    assert(key.IsValid());
}

static CTransactionRef MakeLargeOrphan()
{
    CKey key;
    MakeNewKeyWithFastRandomContext(key);
    CMutableTransaction tx;
    tx.vout.resize(1);
    tx.vout[0].nValue = CENT;
    tx.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    tx.vin.resize(80);
    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        tx.vin[j].prevout.n = j;
        tx.vin[j].prevout.hash = GetRandHash();
        tx.vin[j].scriptWitness.stack.reserve(100);
        for (int i = 0; i < 100; ++i) {
            tx.vin[j].scriptWitness.stack.push_back(std::vector<unsigned char>(j));
        }
    }
    return MakeTransactionRef(tx);
}

BOOST_AUTO_TEST_CASE(DoS_mapOrphans)
{
    // This test had non-deterministic coverage due to
    // randomly selected seeds.
    // This seed is chosen so that all branches of the function
    // ecdsa_signature_parse_der_lax are executed during this test.
    // Specifically branches that run only when an ECDSA
    // signature's R and S values have leading zeros.
    g_insecure_rand_ctx = FastRandomContext{uint256{33}};

    TxOrphanageTest orphanage;
    CKey key;
    MakeNewKeyWithFastRandomContext(key);
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    size_t expected_count{0};
    size_t expected_total_size{0};

    // 50 orphan transactions:
    for (int i = 0; i < 50; i++)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = InsecureRand256();
        tx.vin[0].scriptSig << OP_1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

        auto ptx{MakeTransactionRef(tx)};
        if (orphanage.AddTx(ptx, i, {})) {
            ++expected_count;
            expected_total_size += ptx->GetTotalSize();
        }
    }
    BOOST_CHECK_EQUAL(orphanage.Size(), expected_count);
    BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);

    // ... and 50 that depend on other orphans:
    for (int i = 0; i < 50; i++)
    {
        CTransactionRef txPrev = orphanage.RandomOrphan();

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = txPrev->GetHash();
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
        SignatureData empty;
        BOOST_CHECK(SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL, empty));

        auto ptx{MakeTransactionRef(tx)};
        if (orphanage.AddTx(ptx, i, {})) {
            ++expected_count;
            expected_total_size += ptx->GetTotalSize();
        }
    }
    BOOST_CHECK_EQUAL(orphanage.Size(), expected_count);
    BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);

    // This really-big orphan should be ignored:
    for (int i = 0; i < 10; i++)
    {
        CTransactionRef txPrev = orphanage.RandomOrphan();

        CMutableTransaction tx;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
        tx.vin.resize(2777);
        for (unsigned int j = 0; j < tx.vin.size(); j++)
        {
            tx.vin[j].prevout.n = j;
            tx.vin[j].prevout.hash = txPrev->GetHash();
        }
        SignatureData empty;
        BOOST_CHECK(SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL, empty));
        // Re-use same signature for other inputs
        // (they don't have to be valid for this test)
        for (unsigned int j = 1; j < tx.vin.size(); j++)
            tx.vin[j].scriptSig = tx.vin[0].scriptSig;

        BOOST_CHECK(!orphanage.AddTx(MakeTransactionRef(tx), i, {}));
    }
    BOOST_CHECK_EQUAL(orphanage.Size(), expected_count);
    BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);

    // Test EraseOrphansFor:
    for (NodeId i = 0; i < 3; i++)
    {
        size_t sizeBefore = orphanage.CountOrphans();
        orphanage.EraseForPeer(i);
        BOOST_CHECK(orphanage.CountOrphans() < sizeBefore);
    }

    // Test LimitOrphanTxSize() function:
    orphanage.LimitOrphans(40);
    BOOST_CHECK(orphanage.CountOrphans() <= 40);
    orphanage.LimitOrphans(10);
    BOOST_CHECK(orphanage.CountOrphans() <= 10);
    orphanage.LimitOrphans(0);
    BOOST_CHECK(orphanage.CountOrphans() == 0);

    expected_count = 0;
    expected_total_size = 0;
    BOOST_CHECK_EQUAL(orphanage.CountOrphans(), expected_count);
    BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);
}
BOOST_AUTO_TEST_CASE(multiple_announcers)
{
    const NodeId node0{0};
    const NodeId node1{1};
    size_t expected_total_count{0};
    size_t expected_total_size{0};
    size_t expected_node0_size{0};
    size_t expected_node1_size{0};
    TxOrphanageTest orphanage;
    // Check that accounting for bytes per peer is accurate.
    {
        auto ptx{MakeLargeOrphan()};
        const auto tx_size = ptx->GetTotalSize();
        orphanage.AddTx(ptx, node0, {});
        expected_total_size += tx_size;
        expected_total_count += 1;
        expected_node0_size += tx_size;
        BOOST_CHECK_EQUAL(orphanage.Size(), expected_total_count);
        BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node0), expected_node0_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node1), expected_node1_size);
        // Adding again should do nothing.
        orphanage.AddTx(ptx, node0, {});
        BOOST_CHECK_EQUAL(orphanage.Size(), expected_total_count);
        BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node0), expected_node0_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node1), expected_node1_size);
        // Adding existing tx for another peer should change that peer's bytes, but not total bytes.
        orphanage.AddTx(ptx, node1, {});
        expected_node1_size += tx_size;
        BOOST_CHECK_EQUAL(orphanage.Size(), expected_total_count);
        BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node0), expected_node0_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node1), expected_node1_size);
        // if EraseForPeer is called for an orphan with multiple announcers, the orphanage should only
        // decrement the number of bytes for that peer.
        orphanage.EraseForPeer(node0);
        expected_node0_size -= tx_size;
        BOOST_CHECK(orphanage.HaveTx(GenTxid::Txid(ptx->GetHash())));
        BOOST_CHECK_EQUAL(orphanage.Size(), expected_total_count);
        BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node0), expected_node0_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node1), expected_node1_size);
        // EraseForPeer should delete the orphan if it's the only announcer left.
        orphanage.EraseForPeer(node1);
        expected_total_count -= 1;
        expected_total_size -= tx_size;
        expected_node1_size -= tx_size;
        BOOST_CHECK_EQUAL(orphanage.Size(), expected_total_count);
        BOOST_CHECK_EQUAL(orphanage.TotalOrphanBytes(), expected_total_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node0), expected_node0_size);
        BOOST_CHECK_EQUAL(orphanage.BytesFromPeer(node1), expected_node1_size);
        BOOST_CHECK(!orphanage.HaveTx(GenTxid::Txid(ptx->GetHash())));
    }
}

BOOST_AUTO_TEST_SUITE_END()
