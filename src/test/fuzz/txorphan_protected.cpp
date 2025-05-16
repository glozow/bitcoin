// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <net_processing.h>
#include <node/eviction.h>
#include <node/txorphanage_impl.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

void initialize_protected_orphanage()
{
    static const auto testing_setup = MakeNoLogFileContext();
}

FUZZ_TARGET(txorphan_protected, .init = initialize_protected_orphanage)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FastRandomContext orphanage_rng{/*fDeterministic=*/true};
    SetMockTime(ConsumeTime(fuzzed_data_provider));

    // Peer that must have orphans protected from eviction
    NodeId honest_peerid{0};

    // We have NUM_PEERS, of which Peer==0 is the "honest" one
    // who will never exceed their reserved weight of announcement
    // count, and should therefore never be evicted.
    const unsigned int NUM_PEERS = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(1, 125);

    // Params for orphanage.
    const unsigned int global_announcement_limit = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(NUM_PEERS, 6'000);
    const int64_t per_peer_weight_reservation = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(1, 4'040'000);
    node::TxOrphanageImpl orphanage{global_announcement_limit, per_peer_weight_reservation};

    // The actual limit, MaxPeerAnnouncements(), may be higher, since TxOrphanage only counts peers
    // that have announced an orphan. The honest peer will not experience evictions if it never
    // exceeds this.
    const unsigned int honest_ann_limit = global_announcement_limit / NUM_PEERS;
    // Honest peer will not experience evictions if it never exceeds this.
    const int64_t honest_mem_limit = per_peer_weight_reservation;

    std::vector<COutPoint> outpoints; // Duplicates are tolerated
    outpoints.reserve(200'000);

    // initial outpoints used to construct transactions later
    for (uint8_t i = 0; i < 4; i++) {
        outpoints.emplace_back(Txid::FromUint256(uint256{i}), 0);
    }

    CTransactionRef ptx_potential_parent = nullptr;

    LIMITED_WHILE(outpoints.size() < 200'000 && fuzzed_data_provider.ConsumeBool(), 10 * global_announcement_limit)
    {
        // construct transaction
        const CTransactionRef tx = [&] {
            CMutableTransaction tx_mut;
            const auto num_in = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(1, outpoints.size());
            const auto num_out = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(1, 256);
            // pick outpoints from outpoints as input. We allow input duplicates on purpose, given we are not
            // running any transaction validation logic before adding transactions to the orphanage
            tx_mut.vin.reserve(num_in);
            for (uint32_t i = 0; i < num_in; i++) {
                auto& prevout = PickValue(fuzzed_data_provider, outpoints);
                // try making transactions unique by setting a random nSequence, but allow duplicate transactions if they happen
                tx_mut.vin.emplace_back(prevout, CScript{}, fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, CTxIn::SEQUENCE_FINAL));
            }
            // output amount or spendability will not affect txorphanage
            tx_mut.vout.reserve(num_out);
            for (uint32_t i = 0; i < num_out; i++) {
                const auto payload_size = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(1, 100000);
                if (payload_size) {
                    tx_mut.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(payload_size));
                } else {
                    tx_mut.vout.emplace_back(0, CScript{});
                }
            }
            auto new_tx = MakeTransactionRef(tx_mut);
            // add newly constructed outpoints to the coin pool
            for (uint32_t i = 0; i < num_out; i++) {
                outpoints.emplace_back(new_tx->GetHash(), i);
            }
            return new_tx;
        }();

        const auto wtxid{tx->GetWitnessHash()};

        // orphanage functions
        LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10 * global_announcement_limit)
        {
            NodeId peer_id = fuzzed_data_provider.ConsumeIntegralInRange<NodeId>(0, NUM_PEERS - 1);
            const auto tx_weight{GetTransactionWeight(*tx)};

            // This protected peer will never send orphans that would
            // exceed their own personal allotment, so is never evicted.
            const bool peer_is_protected{peer_id == honest_peerid};

            CallOneOf(
                fuzzed_data_provider,
                [&] { // AddTx
                    bool have_tx_and_peer = orphanage.HaveTxFromPeer(wtxid, peer_id);
                    if (peer_is_protected && !have_tx_and_peer &&
                        (orphanage.UsageFromPeer(peer_id) + tx_weight > honest_mem_limit ||
                        orphanage.AnnouncementsFromPeer(peer_id) + 1 > honest_ann_limit)) {
                        // We never want our protected peer oversized or over-announced
                    } else {
                        orphanage.AddTx(tx, peer_id);
                    }
                },
                [&] { // AddAnnouncer
                    bool have_tx_and_peer = orphanage.HaveTxFromPeer(tx->GetWitnessHash(), peer_id);
                    // AddAnnouncer should return false if tx doesn't exist or we already HaveTxFromPeer.
                    {
                        if (peer_is_protected && !have_tx_and_peer &&
                            (orphanage.UsageFromPeer(peer_id) + tx_weight > honest_mem_limit ||
                            orphanage.AnnouncementsFromPeer(peer_id) + 1 > honest_ann_limit)) {
                            // We never want our protected peer oversized
                        } else {
                            orphanage.AddAnnouncer(tx->GetWitnessHash(), peer_id);
                        }
                    }
                },
                [&] { // EraseForPeer
                    if (peer_id != honest_peerid) {
                        orphanage.EraseForPeer(peer_id);
                    }
                },
                [&] { // LimitOrphans
                    // Assert that protected peer is never affected by LimitOrphans.
                    const auto protected_bytes{orphanage.UsageFromPeer(honest_peerid)};
                    const auto protected_txns{orphanage.AnnouncementsFromPeer(honest_peerid)};

                    orphanage.LimitOrphans();

                    Assert(orphanage.CountAnnouncements() <= global_announcement_limit);
                    Assert(orphanage.TotalOrphanUsage() <= per_peer_weight_reservation * NUM_PEERS);

                    // This should never differ before and after since we aren't allowing
                    // expiries and we've never exceeded the per-peer reservations.
                    Assert(protected_bytes == orphanage.UsageFromPeer(honest_peerid));
                    Assert(protected_txns == orphanage.AnnouncementsFromPeer(honest_peerid));
                });

        }
    }

    orphanage.SanityCheck();
}
