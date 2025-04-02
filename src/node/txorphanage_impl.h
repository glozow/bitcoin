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

    /** Erase from m_orphans and update m_peer_orphanage_info. */
    template<typename Tag>
    Iter<Tag> Erase(Iter<Tag> it)
    {
        auto peer_it = m_peer_orphanage_info.find(it->m_announcer);
        // Clean up m_peer_orphanage_info entries if they become empty.
        if (peer_it->second.Subtract(*it)) m_peer_orphanage_info.erase(peer_it);
        return m_orphans.get<Tag>().erase(it);
    }
public:
    void SanityCheck() const
    {
        // Recalculate the per-peer stats from m_orphans and compare to m_peer_orphanage_info
        assert(RecomputePeerInfo() == m_peer_orphanage_info);
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

    /** Erase all entries by this peer. */
    void EraseForPeer(NodeId peer)
    {
        auto& index_by_peer = m_orphans.get<ByPeer>();
        auto it = index_by_peer.lower_bound(ByPeerView{peer, false, 0});
        while (it != index_by_peer.end() && it->m_announcer == peer) {
            // Decide what will happen next before the iter is invalidated.
            const bool last_item{std::next(it) == index_by_peer.end() || std::next(it)->m_announcer != peer};
            auto it_next = last_item ? index_by_peer.end() : std::next(it);

            // Delete item
            Erase<ByPeer>(it);

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

            // Delete item
            Erase<ByWtxid>(it);

            // Advance pointer
            it = it_next;
            num_erased += 1;
        }
        return num_erased;
    }
};
#endif // BITCOIN_TXMEMPOOL_H
