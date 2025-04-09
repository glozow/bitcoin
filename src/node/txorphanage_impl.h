// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <coins.h>
#include <consensus/amount.h>
#include <indirectmap.h>
#include <net.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <util/epochguard.h>
#include <util/hasher.h>
#include <util/result.h>
#include <util/feefrac.h>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/tag.hpp>
#include <boost/multi_index_container.hpp>

#include <atomic>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

class TxOrphanageImpl
{
    // Type alias for sequence numbers
    using SequenceNumber = uint64_t;
    using UsageBytes = int64_t;

    /** Global sequence number, increment each time an announcement is added. */
    SequenceNumber m_current_sequence{0};

    /** One orphan announcement. */
    struct Announcement
    {
        CTransactionRef m_tx;
        /** Which peer announced this tx */
        NodeId m_announcer;
        /** What order this transaction entered the orphanage */
        SequenceNumber m_entry_sequence;
        /** Whether this tx should be reconsidered. Always starts out false. */
        bool m_reconsider{false};

        Announcement(const CTransactionRef& tx, NodeId peer, SequenceNumber seq) :
            m_tx{tx}, m_announcer{peer}, m_entry_sequence{seq}
        { }

        /** Get the weight of the transaction, our approximation for "memory usage". */
        UsageBytes GetUsage()  const {
            return GetTransactionWeight(*m_tx);
        }
    };

    // Index by wtxid
    struct ByWtxid {};
    using ByWtxidView = std::tuple<Wtxid, NodeId>;
    struct WtxidExtractor
    {
        using result_type = ByWtxidView;
        result_type operator()(const Announcement& ann) const
        {
            return ByWtxidView{ann.m_tx->GetWitnessHash(), ann.m_announcer};
        }
    };

    // Sort by peer, then by whether it is ready to reconsider, then from least to most recent
    struct ByPeer {};
    using ByPeerView = std::tuple<NodeId, bool, SequenceNumber>;
    struct ByPeerViewExtractor {
        using result_type = ByPeerView;
        result_type operator()(const Announcement& ann) const
        {
            return ByPeerView{ann.m_announcer, ann.m_reconsider, ann.m_entry_sequence};
        }
    };

    struct OrphanIndices final : boost::multi_index::indexed_by<
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByWtxid>, WtxidExtractor>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByPeer>, ByPeerViewExtractor>
    >{};

    using OrphanMap = boost::multi_index::multi_index_container<Announcement, OrphanIndices>;
    template<typename Tag>
    using Iter = typename OrphanMap::index<Tag>::type::iterator;
    OrphanMap m_orphans;

    /** Index from the parents' outputs to wtxids that exist in m_orphans. Used to find children of
     * a transaction that can be reconsidered and to remove entries that conflict with a block.*/
    std::map<COutPoint, std::set<Wtxid>> m_outpoint_to_orphan_it;

    struct PeerInfo {
        UsageBytes m_total_usage{0};
        int64_t m_count_announcements{0};
        bool operator==(const PeerInfo& other) const
        {
            return m_total_usage == other.m_total_usage &&
                   m_count_announcements == other.m_count_announcements;
        }
        void Add(const Announcement& ann)
        {
            m_total_usage += ann.GetUsage();
            m_count_announcements += 1;
        }
        bool Subtract(const Announcement& ann)
        {
            m_total_usage -= ann.GetUsage();
            m_count_announcements -= 1;
            return m_count_announcements == 0;
        }
    };
    /** Store per-peer statistics. Used to determine each peer's DoS score. */
    std::unordered_map<NodeId, PeerInfo> m_peer_orphanage_info;

    /** Recompute peer info from m_orphans. Used to check that m_peer_orphanage_info is accurate. */
    std::unordered_map<NodeId, PeerInfo> RecomputePeerInfo() const
    {
        std::unordered_map<NodeId, PeerInfo> result;
        for (const auto& ann : m_orphans) {
            auto& peer_info = result.try_emplace(ann.m_announcer).first->second;
            peer_info.m_total_usage += ann.GetUsage();
            peer_info.m_count_announcements += 1;
        }
        return result;
    }

    /** Erase from m_orphans and update m_peer_orphanage_info.
     * If cleanup_outpoints_map is true, removes this wtxid from the sets corresponding to each
     * outpoint in m_outpoint_to_orphan_it. The caller must remember to set this to true when all
     * announcements for a transaction are erased, otherwise m_outpoint_to_orphan_it will keep
     * growing. Set it to false when other announcements for the same tx exist.
     */
    template<typename Tag>
    void Erase(Iter<Tag> it, bool cleanup_outpoints_map)
    {
        // Update m_peer_orphanage_info and clean up entries if they point to an empty struct.
        // This means peers that are not storing any orphans do not have an entry in
        // m_peer_orphanage_info (they can be added back later if they announce another orphan) and
        // ensures disconnected peers are not tracked forever.
        auto peer_it = m_peer_orphanage_info.find(it->m_announcer);
        if (peer_it->second.Subtract(*it)) m_peer_orphanage_info.erase(peer_it);

        if (cleanup_outpoints_map) {
            // Remove references in m_outpoint_to_orphan_it
            const auto& wtxid{it->m_tx->GetWitnessHash()};
            for (const auto& input : it->m_tx->vin) {
                auto it_prev = m_outpoint_to_orphan_it.find(input.prevout);
                if (it_prev != m_outpoint_to_orphan_it.end()) {
                    it_prev->second.erase(wtxid);
                    // Clean up keys if they point to an empty set.
                    if (it_prev->second.empty()) {
                        m_outpoint_to_orphan_it.erase(it_prev);
                    }
                }
            }
        }
        m_orphans.get<Tag>().erase(it);
    }
public:
    /** Number of announcements ones for the same wtxid are not de-duplicated. */
    unsigned int CountAnnouncements() const { return m_orphans.size(); }

    void SanityCheck() const
    {
        // Recalculate the per-peer stats from m_orphans and compare to m_peer_orphanage_info
        assert(RecomputePeerInfo() == m_peer_orphanage_info);

        // TODO: replace with a check that every outpoint points to a tx that exists, and every
        // input of each orphan is tracked properly
        assert(m_orphans.empty() == m_outpoint_to_orphan_it.empty());
    }

    bool AddTx(const CTransactionRef& tx, NodeId peer)
    {
        const auto& wtxid{tx->GetWitnessHash()};
        // Quit if we already have this announcement (same wtxid and peer).
        if (m_orphans.get<ByWtxid>().count(ByWtxidView{wtxid, peer})) return false;

        // We will return false if the tx already exists under a different peer.
        const bool brand_new{!HaveTx(wtxid)};

        auto ret = m_orphans.get<ByWtxid>().emplace(tx, peer, m_current_sequence);
        if (!Assume(ret.second)) return false;

        ++m_current_sequence;
        auto& peer_info = m_peer_orphanage_info.try_emplace(peer).first->second;
        peer_info.Add(*ret.first);

        // Add links in m_outpoint_to_orphan_it
        for (const auto& input : tx->vin) {
            auto& wtxids_for_prevout = m_outpoint_to_orphan_it.try_emplace(input.prevout).first->second;
            wtxids_for_prevout.emplace(wtxid);
        }
        return brand_new;
    }

    bool AddAnnouncer(const Wtxid& wtxid, NodeId peer)
    {
        auto it = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, 0});
        // If we don't have at least one announcement for this wtxid, we can't add another announcer as
        // we need a copy of the tx.
        if (it->m_tx->GetWitnessHash() != wtxid) return false;
        const auto& ptx = it->m_tx;

        while (it != m_orphans.get<ByWtxid>().end() && it->m_tx->GetWitnessHash() == wtxid) {
            // Quit if we already have this announcement (same wtxid and peer).
            if (it->m_announcer == peer) return false;
            ++it;
        }

        // Add another announcement, copying one that exists
        auto ret = m_orphans.get<ByWtxid>().emplace(ptx, peer, m_current_sequence);
        if (!Assume(ret.second)) return false;

        ++m_current_sequence;
        auto& peer_info = m_peer_orphanage_info.try_emplace(peer).first->second;
        peer_info.Add(*ret.first);

        return true;
    }

    CTransactionRef GetTx(const Wtxid& wtxid) const
    {
        auto it_lower = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, 0});
        if (it_lower != m_orphans.end() && it_lower->m_tx->GetWitnessHash() == wtxid) return it_lower->m_tx;
        return nullptr;
    }

    bool HaveTx(const Wtxid& wtxid) const
    {
        auto it_lower = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, 0});
        return it_lower != m_orphans.end() && it_lower->m_tx->GetWitnessHash() == wtxid;
    }

    bool HaveTxFromPeer(const Wtxid& wtxid, NodeId peer) const
    {
        return m_orphans.get<ByWtxid>().count(ByWtxidView{wtxid, peer}) > 0;
    }

    /** Returns whether this wtxid exists and is unique. If there is no entry with this wtxid, or
     * there are multiple announcements for the same wtxid, returns false. */
    bool HaveUnique(const Wtxid& wtxid) const
    {
        auto it = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, 0});
        // Less than 1 instance?
        if (it == m_orphans.end() || it->m_tx->GetWitnessHash() != wtxid) return false;

        // More than 1 instance?
        it = std::next(it);
        if (it != m_orphans.end() && it->m_tx->GetWitnessHash() == wtxid) return false;

        return true;
    }

    /** Erase all entries by this peer. */
    void EraseForPeer(NodeId peer)
    {
        auto& index_by_peer = m_orphans.get<ByPeer>();
        auto it = index_by_peer.lower_bound(ByPeerView{peer, false, 0});
        while (it != index_by_peer.end() && it->m_announcer == peer) {
            // Decide what will happen next before the iter is invalidated.
            const bool last_item{std::next(it) == index_by_peer.end() || std::next(it)->m_announcer != peer};
            auto it_next = last_item ? index_by_peer.end() : std::next(it);

            // Delete item, cleaning up m_outpoint_to_orphan_it iff this entry is unique by wtxid.
            Erase<ByPeer>(it, /*cleanup_outpoints_map=*/HaveUnique(it->m_tx->GetWitnessHash()));

            // Advance pointer
            it = it_next;
        }
        Assume(!m_peer_orphanage_info.contains(peer));
    }

    /** Erase all entries with this wtxid. */
    unsigned int EraseTx(const Wtxid& wtxid)
    {
        unsigned int num_erased{0};
        auto& index_by_wtxid = m_orphans.get<ByWtxid>();
        auto it = index_by_wtxid.lower_bound(ByWtxidView{wtxid, 0});
        while (it != index_by_wtxid.end() && it->m_tx->GetWitnessHash() == wtxid) {
            // Decide what will happen next before the iter is invalidated.
            const bool last_item{std::next(it) == index_by_wtxid.end() || std::next(it)->m_tx->GetWitnessHash() != wtxid};
            auto it_next = last_item ? index_by_wtxid.end() : std::next(it);

            // Delete item. We only need to clean up m_outpoint_to_orphan_it the first time.
            Erase<ByWtxid>(it, /*cleanup_outpoints_map=*/num_erased == 0);

            // Advance pointer
            it = it_next;
            num_erased += 1;
        }
        return num_erased;
    }

    /** Return whether there is a tx that can be reconsidered. */
    bool HaveTxToReconsider(NodeId peer) const
    {
        auto it = m_orphans.get<ByPeer>().lower_bound(ByPeerView{peer, true, 0});
        return it != m_orphans.get<ByPeer>().end() && it->m_announcer == peer && it->m_reconsider;
    }

    /** If there is a tx that can be reconsidered, return it. Otherwise, return a nullptr. */
    CTransactionRef GetTxToReconsider(NodeId peer)
    {
        auto it = m_orphans.get<ByPeer>().lower_bound(ByPeerView{peer, true, 0});
        if (it != m_orphans.get<ByPeer>().end() && it->m_announcer == peer && it->m_reconsider) {
            // Flip m_reconsider. Even if this transaction stays in orphanage, it shouldn't be
            // reconsidered again until there is a new reason to do so.
            auto mark_reconsidered_modifier = [](auto& ann) { ann.m_reconsider = false; };
            m_orphans.get<ByPeer>().modify(it, mark_reconsidered_modifier);
            return it->m_tx;
        }
        return nullptr;
    }

    unsigned int EraseForBlock(const CBlock& block)
    {
        std::set<Wtxid> wtxids_to_erase;
        for (const CTransactionRef& ptx : block.vtx) {
            const CTransaction& block_tx = *ptx;

            // Which orphan pool entries must we evict?
            for (const auto& input : block_tx.vin) {
                auto it_prev = m_outpoint_to_orphan_it.find(input.prevout);
                if (it_prev != m_outpoint_to_orphan_it.end()) {
                    // Copy all wtxids to wtxids_to_erase.
                    std::copy(it_prev->second.cbegin(), it_prev->second.cend(), std::inserter(wtxids_to_erase, wtxids_to_erase.end()));
                    for (const auto& wtxid : it_prev->second) {
                        wtxids_to_erase.insert(wtxid);
                    }
                }
            }
        }

        unsigned int num_erased{0};
        for (const auto& wtxid : wtxids_to_erase) {
            num_erased += EraseTx(wtxid);
        }
        // fixme: log that we erased %u announcements for %u transactions included or conflicted by block
        return wtxids_to_erase.size();
    }


    /** Get all children that spend from this tx and were received from nodeid. Sorted from most
     * recent to least recent. */
    std::vector<CTransactionRef> GetChildrenFromSamePeer(const CTransactionRef& parent, NodeId peer) const
    {
        std::vector<CTransactionRef> children_found;
        const auto& parent_txid{parent->GetHash()};

        // Iterate through all orphans from this peer, in reverse order, so that more recent
        // transactions are added first. Doing so helps avoid work when one of the orphans replaced
        // an earlier one. Since we require the NodeId to match, one peer's announcement order does
        // not bias how we process other peer's orphans.
        auto& index_by_peer = m_orphans.get<ByPeer>();
        auto it_upper = index_by_peer.upper_bound(ByPeerView{peer, true, std::numeric_limits<uint64_t>::max()});
        auto it_lower = index_by_peer.lower_bound(ByPeerView{peer, false, 0});

        if (it_upper != index_by_peer.begin()) {
            auto rit = std::make_reverse_iterator(it_upper);
            auto rit_end = std::make_reverse_iterator(it_lower);
            while (rit != rit_end) {
                if (rit->m_announcer != peer) continue;
                // Check if this tx spends from parent.
                for (const auto& input : rit->m_tx->vin) {
                    if (input.prevout.hash == parent_txid) {
                        children_found.emplace_back(rit->m_tx);
                        break;
                    }
                }
                ++rit;
            }

        }
        return children_found;
    }
};
#endif // BITCOIN_TXMEMPOOL_H
