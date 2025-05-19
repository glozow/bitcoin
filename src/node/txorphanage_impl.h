// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <coins.h>
#include <consensus/amount.h>
#include <indirectmap.h>
#include <logging.h>
#include <net.h>
#include <node/txorphanage.h>
#include <policy/policy.h>
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

namespace node {
/** Default value for TxOrphanage::m_reserved_usage_per_peer. */
static constexpr int64_t DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER{404'000};
/** Default value for TxOrphanage::m_max_global_announcements. */
static constexpr unsigned int DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS{100};
/** Minimum NodeId for lower_bound lookups (in practice, NodeIds start at 0). */
static constexpr NodeId min_peer{std::numeric_limits<NodeId>::min()};

class TxOrphanageImpl
{
    // Type alias for sequence numbers
    using SequenceNumber = uint64_t;

    /** Global sequence number, increment each time an announcement is added. */
    SequenceNumber m_current_sequence{0};

    /** One orphan announcement. Each announcement (i.e. combination of wtxid, nodeid) is unique. There may be multiple
     * announcements for the same tx, and multiple transactions with the same txid but different wtxid are possible. */
    struct Announcement
    {
        CTransactionRef m_tx;
        /** Which peer announced this tx */
        NodeId m_announcer;
        /** What order this transaction entered the orphanage. */
        SequenceNumber m_entry_sequence;
        /** Whether this tx should be reconsidered. Always starts out false. A peer's workset is the collection of all
         * announcements with m_reconsider=true. */
        bool m_reconsider{false};

        Announcement(const CTransactionRef& tx, NodeId peer, SequenceNumber seq) :
            m_tx{tx}, m_announcer{peer}, m_entry_sequence{seq}
        { }

        /** Get the weight of the transaction, our approximation for "memory usage". */
        int64_t GetUsage()  const {
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

    // Sort by peer, then by whether it is ready to reconsider, then by recency
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
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByWtxid>, WtxidExtractor>,
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByPeer>, ByPeerViewExtractor>
    >{};

    using OrphanMap = boost::multi_index::multi_index_container<Announcement, OrphanIndices>;
    template<typename Tag>
    using Iter = typename OrphanMap::index<Tag>::type::iterator;
    OrphanMap m_orphans;

    const unsigned int m_max_global_announcements{DEFAULT_MAX_ORPHAN_ANNOUNCEMENTS};
    const int64_t m_reserved_usage_per_peer{DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER};

    /** Number of unique orphans by wtxid. Less than or equal to the number of entries in m_orphans. */
    unsigned int m_unique_orphans{0};

    /** Total bytes used by orphans, deduplicated by wtxid. */
    unsigned int m_unique_orphan_bytes{0};

    /** Index from the parents' outputs to wtxids that exist in m_orphans. Used to find children of
     * a transaction that can be reconsidered and to remove entries that conflict with a block.*/
    std::map<COutPoint, std::set<Wtxid>> m_outpoint_to_orphan_it;

    struct PeerInfo {
        int64_t m_total_usage{0};
        unsigned int m_count_announcements{0};
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
        /** There are 2 DoS scores:
        * - CPU score (ratio of num announcements / max allowed announcements)
        * - Memory score (ratio of total usage / max allowed usage).
        *
        * If the peer is using more than the allowed for either resource, its DoS score is > 1.
        * A peer having a DoS score > 1 does not necessarily mean that something is wrong, since we
        * do not trim unless the orphanage exceeds global limits, but it means that this peer will
        * be selected for trimming sooner. If the global announcement or global memory usage
        * limits are exceeded, it must be that there is a peer whose DoS score > 1. */
        FeeFrac GetDosScore(unsigned int max_peer_count, int64_t max_peer_bytes) const
        {
            const FeeFrac cpu_score(m_count_announcements, max_peer_count);
            const FeeFrac mem_score(m_total_usage, max_peer_bytes);
            return std::max<FeeFrac>(cpu_score, mem_score);
        }
    };
    /** Store per-peer statistics. Used to determine each peer's DoS score. */
    std::unordered_map<NodeId, PeerInfo> m_peer_orphanage_info;
    using PeerMap = decltype(m_peer_orphanage_info);

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
            m_unique_orphans -= 1;
            m_unique_orphan_bytes -= it->GetUsage();

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

    /** Return number of announcements with the same wtxid as it. */
    unsigned int CountSameWtxid(Iter<ByWtxid> it) const
    {
        if (it == m_orphans.end()) return 0;

        unsigned int count{0};
        const auto& wtxid{it->m_tx->GetWitnessHash()};
        while (it != m_orphans.end() && it->m_tx->GetWitnessHash() == wtxid) {
            ++count;
            ++it;
        }
        return count;
    }

    /** Return number of announcements with this wtxid. */
    unsigned int CountWtxid(const Wtxid& wtxid) const
    {
        auto it = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, min_peer});
        if (it == m_orphans.end()) return 0;
        return CountSameWtxid(it);
    }
public:
    TxOrphanageImpl() = default;
    TxOrphanageImpl(unsigned int max_global_ann, int64_t reserved_peer_usage) :
        m_max_global_announcements{max_global_ann},
        m_reserved_usage_per_peer{reserved_peer_usage}
    {}

    /** Number of announcements ones for the same wtxid are not de-duplicated. */
    unsigned int CountAnnouncements() const { return m_orphans.size(); }

    /** Total number of bytes used by orphans, de-duplicated by wtxid. */
    int64_t TotalOrphanUsage() const { return m_unique_orphan_bytes; }

    /** Number of unique orphans */
    unsigned int CountUniqueOrphans() const { return m_unique_orphans; }

    /** Number of orphans from this peer */
    unsigned int AnnouncementsFromPeer(NodeId peer) const {
        auto it = m_peer_orphanage_info.find(peer);
        return it == m_peer_orphanage_info.end() ? 0 : it->second.m_count_announcements;
    }

    /** Total usage of orphans from this peer */
    int64_t UsageFromPeer(NodeId peer) const {
        auto it = m_peer_orphanage_info.find(peer);
        return it == m_peer_orphanage_info.end() ? 0 : it->second.m_total_usage;
    }

    void SanityCheck() const
    {
        std::unordered_map<NodeId, PeerInfo> reconstructed_peer_info;
        std::map<Wtxid, int64_t > unique_wtxids_to_usage;
        std::set<COutPoint> all_outpoints;

        for (auto it = m_orphans.begin(); it != m_orphans.end(); ++it) {
            for (const auto& input : it->m_tx->vin) {
                all_outpoints.insert(input.prevout);
            }
            unique_wtxids_to_usage.emplace(it->m_tx->GetWitnessHash(), it->GetUsage());

            auto& peer_info = reconstructed_peer_info.try_emplace(it->m_announcer).first->second;
            peer_info.m_total_usage += it->GetUsage();
            peer_info.m_count_announcements += 1;
        }

        // Recalculated per-peer stats are identical to m_peer_orphanage_info
        assert(reconstructed_peer_info == m_peer_orphanage_info);

        // All outpoints exist in m_outpoint_to_orphan_it, all keys in m_outpoint_to_orphan_it correspond to some
        // orphan, and all wtxids referenced in m_outpoint_to_orphan_it are also in m_orphans.
        assert(all_outpoints.size() == m_outpoint_to_orphan_it.size());
        for (const auto& [outpoint, wtxid_set] : m_outpoint_to_orphan_it) {
            assert(all_outpoints.contains(outpoint));
            for (const auto& wtxid : wtxid_set) {
                assert(unique_wtxids_to_usage.contains(wtxid));
            }
        }

        // Cached m_unique_orphans value is correct.
        assert(m_orphans.size() >= m_unique_orphans);
        assert(unique_wtxids_to_usage.size() == m_unique_orphans);

        const auto calculated_dedup_usage = std::accumulate(unique_wtxids_to_usage.begin(), unique_wtxids_to_usage.end(),
            int64_t{0}, [](int64_t sum, const auto pair) { return sum + pair.second; });
        assert(calculated_dedup_usage == m_unique_orphan_bytes);
    }

    bool AddTx(const CTransactionRef& tx, NodeId peer)
    {
        const auto& wtxid{tx->GetWitnessHash()};
        const auto& txid{tx->GetHash()};
        // Quit if we already have this announcement (same wtxid and peer).
        if (HaveTxFromPeer(wtxid, peer)) return false;

        // Ignore transactions above max standard size to avoid a send-big-orphans memory exhaustion attack.
        int64_t sz = GetTransactionWeight(*tx);
        if (sz > MAX_STANDARD_TX_WEIGHT) {
            LogDebug(BCLog::TXPACKAGES, "ignoring large orphan tx (size: %u, txid: %s, wtxid: %s)\n", sz, txid.ToString(), wtxid.ToString());
            return false;
        }

        // We will return false if the tx already exists under a different peer.
        const bool brand_new{!HaveTx(wtxid)};

        auto ret = m_orphans.get<ByWtxid>().emplace(tx, peer, m_current_sequence);
        if (!Assume(ret.second)) return false;

        ++m_current_sequence;
        auto& peer_info = m_peer_orphanage_info.try_emplace(peer).first->second;
        peer_info.Add(*ret.first);

        // Add links in m_outpoint_to_orphan_it
        if (brand_new) {
            for (const auto& input : tx->vin) {
                auto& wtxids_for_prevout = m_outpoint_to_orphan_it.try_emplace(input.prevout).first->second;
                wtxids_for_prevout.emplace(wtxid);
            }

            m_unique_orphans += 1;
            m_unique_orphan_bytes += ret.first->GetUsage();

            LogDebug(BCLog::TXPACKAGES, "stored orphan tx %s (wtxid=%s), weight: %u (mapsz %u outsz %u)\n",
                     txid.ToString(), wtxid.ToString(), sz, m_orphans.size(), m_outpoint_to_orphan_it.size());
            Assume(CountWtxid(wtxid) == 1);
        } else {
            LogDebug(BCLog::TXPACKAGES, "added peer=%d as announcer of orphan tx %s (wtxid=%s)\n",
                     peer, txid.ToString(), wtxid.ToString());
            Assume(CountWtxid(wtxid) > 1);
        }
        return brand_new;
    }

    bool AddAnnouncer(const Wtxid& wtxid, NodeId peer)
    {
        auto it = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, min_peer});

        // Do nothing if this transaction isn't already present. We can't create an entry if we don't
        // have the tx data.
        if (it == m_orphans.end()) return false;
        if (it->m_tx->GetWitnessHash() != wtxid) return false;

        // Quit if we already have this announcement (same wtxid and peer).
        if (HaveTxFromPeer(wtxid, peer)) return false;

        // Add another announcement, copying one that exists
        const auto& ptx = it->m_tx;
        auto ret = m_orphans.get<ByWtxid>().emplace(ptx, peer, m_current_sequence);
        if (!Assume(ret.second)) return false;

        ++m_current_sequence;
        auto& peer_info = m_peer_orphanage_info.try_emplace(peer).first->second;
        peer_info.Add(*ret.first);

        const auto& txid = ret.first->m_tx->GetHash();
        LogDebug(BCLog::TXPACKAGES, "added peer=%d as announcer of orphan tx %s (wtxid=%s)\n",
                 peer, txid.ToString(), wtxid.ToString());

        Assume(CountWtxid(wtxid) > 1);
        return true;
    }

    CTransactionRef GetTx(const Wtxid& wtxid) const
    {
        auto it_lower = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, min_peer});
        if (it_lower != m_orphans.end() && it_lower->m_tx->GetWitnessHash() == wtxid) return it_lower->m_tx;
        return nullptr;
    }

    bool HaveTx(const Wtxid& wtxid) const
    {
        auto it_lower = m_orphans.get<ByWtxid>().lower_bound(ByWtxidView{wtxid, min_peer});
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
        unsigned int num_erased{0};
        while (it != index_by_peer.end() && it->m_announcer == peer) {
            // Decide what will happen next before the iter is invalidated.
            const bool last_item{std::next(it) == index_by_peer.end() || std::next(it)->m_announcer != peer};
            auto it_next = last_item ? index_by_peer.end() : std::next(it);

            // Delete item, cleaning up m_outpoint_to_orphan_it iff this entry is unique by wtxid.
            Erase<ByPeer>(it, /*cleanup_outpoints_map=*/CountWtxid(it->m_tx->GetWitnessHash()) == 1);

            // Advance pointer
            it = it_next;
            num_erased += 1;
        }
        Assume(!m_peer_orphanage_info.contains(peer));

        if (num_erased > 0) LogDebug(BCLog::TXPACKAGES, "Erased %d orphan transaction(s) from peer=%d\n", num_erased, peer);
    }

    /** Erase all entries with this wtxid. Return the number of announcements erased. */
    unsigned int EraseAll(const Wtxid& wtxid)
    {
        unsigned int num_erased{0};
        auto& index_by_wtxid = m_orphans.get<ByWtxid>();
        auto it = index_by_wtxid.lower_bound(ByWtxidView{wtxid, min_peer});
        const auto& txid = it->m_tx->GetHash();
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

        if (num_erased > 0) {
            LogDebug(BCLog::TXPACKAGES, "removed orphan tx %s (wtxid=%s) (%u announcements)\n", txid.ToString(), wtxid.ToString(), num_erased);
        }

        return num_erased;
    }

    /** Erase all entries with this wtxid. Return the number of unique orphans by wtxid erased. */
    unsigned int EraseTx(const Wtxid& wtxid)
    {
        const unsigned int num_announcements_erased{EraseAll(wtxid)};
        return std::min<unsigned int>(1, num_announcements_erased);
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

        if (num_erased != 0) {
            LogDebug(BCLog::TXPACKAGES, "Erased %d orphan transaction(s) included or conflicted by block\n", num_erased);
        }
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

    void AddChildrenToWorkSet(const CTransaction& tx, FastRandomContext& rng)
    {
        auto& index_by_wtxid = m_orphans.get<ByWtxid>();
        for (unsigned int i = 0; i < tx.vout.size(); i++) {
            const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(tx.GetHash(), i));
            if (it_by_prev != m_outpoint_to_orphan_it.end()) {
                for (const auto& wtxid : it_by_prev->second) {
                    // Belt and suspenders, each entry in m_outpoint_to_orphan_it should always have at least 1 announcement.
                    auto it = index_by_wtxid.lower_bound(ByWtxidView{wtxid, min_peer});
                    if (!Assume(it != index_by_wtxid.end())) continue;

                    // Select a random peer to assign orphan processing, reducing wasted work if the orphan is still missing
                    // inputs. However, we don't want to create an issue in which the assigned peer can purposefully stop us
                    // from processing the orphan by disconnecting.
                    const auto num_announcers{CountWtxid(wtxid)};
                    if (!Assume(num_announcers > 0)) continue;
                    std::advance(it, rng.randrange(num_announcers));
                    if (!Assume(it->m_tx->GetWitnessHash() == wtxid)) continue;

                    // Mark this orphan as ready to be reconsidered.
                    auto mark_reconsidered_modifier = [](auto& ann) { ann.m_reconsider = true; };
                    m_orphans.get<ByWtxid>().modify(it, mark_reconsidered_modifier);

                    LogDebug(BCLog::TXPACKAGES, "added %s (wtxid=%s) to peer %d workset\n",
                             it->m_tx->GetHash().ToString(), it->m_tx->GetWitnessHash().ToString(), it->m_announcer);
                }
            }
        }
    }

    /** Constant */
    unsigned int MaxGlobalAnnouncements() const { return m_max_global_announcements; }
    /** Dynamic based on number of peers */
    unsigned int MaxPeerAnnouncements() const { return m_max_global_announcements / std::max<unsigned int>(m_peer_orphanage_info.size(), 1); }
    /** Constant */
    unsigned int ReservedPeerUsage() const { return m_reserved_usage_per_peer; }
    /** Dynamic based on number of peers */
    unsigned int MaxGlobalUsage() const { return m_reserved_usage_per_peer * std::max<unsigned int>(m_peer_orphanage_info.size(), 1); }

    /** Returns whether global announcement or usage limits have been exceeded. */
    bool NeedsTrim() const
    {
        return m_orphans.size() > MaxGlobalAnnouncements() || m_unique_orphan_bytes > MaxGlobalUsage();
    }

    /** If needs trim, evicts announcements by selecting the DoSiest peer and evicting its oldest announcement not up for
     * reconsideration. Does nothing if no global limits are exceeded. */
    void LimitOrphans()
    {
        if (!NeedsTrim()) return;

        const auto original_unique_txns{CountUniqueOrphans()};

        // These numbers cannot change within a single call to LimitOrphans because the size of m_peer_orphanage_info
        // does not change unless a peer is removed.
        const auto max_ann{MaxPeerAnnouncements()};
        const auto max_mem{ReservedPeerUsage()};

        // We have exceeded the global limit(s). Now, identify who is using too much and evict their orphans.
        // This eviction strategy effectively "reserves" an amount of announcements and space for each peer.
        // The reserved amount is protected from eviction, even if somebody is spamming the orphanage.
        std::vector<std::pair<NodeId, FeeFrac>> heap_peer_dos;
        heap_peer_dos.reserve(m_peer_orphanage_info.size());
        for (auto it = m_peer_orphanage_info.begin(); it != m_peer_orphanage_info.end(); ++it) {
            heap_peer_dos.push_back(std::make_pair(it->first, it->second.GetDosScore(max_ann, max_mem)));
        }

        auto compare_score = [](auto left, auto right) { return left.second < right.second; };
        std::make_heap(heap_peer_dos.begin(), heap_peer_dos.end(), compare_score);

        unsigned int num_erased{0};
        do {
            // Find the peer with the highest DoS score, which is a fraction of {usage, announcements} used over the
            // respective allowances. This metric causes us to naturally select peers who have exceeded their limits
            // (i.e. a DoS score > 1) before peers who haven't, and the loop should halt before we ever select peers who
            // haven't. We may choose the same peer as the last iteration of this loop.
            // Note: if ratios are the same, FeeFrac tiebreaks by denominator. In practice, since the CPU denominator is
            // always lower, this means that a peer with only high number of announcements will be targeted before a
            // peer using a lot of memory, even if they have the same ratios.
            std::pop_heap(heap_peer_dos.begin(), heap_peer_dos.end(), compare_score);
            const auto& [worst_peer, dos_score] = heap_peer_dos.back();
            heap_peer_dos.pop_back();

            // If needs trim, then at least one peer has a DoS score higher than 1.
            Assume(dos_score > FeeFrac(DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER, DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER));

            // Evict the oldest announcement from this peer that is not up for reconsideration.
            auto it_ann = m_orphans.get<ByPeer>().lower_bound(ByPeerView{worst_peer, false, 0});
            Assume(it_ann->m_announcer == worst_peer);
            Erase<ByPeer>(it_ann, /*cleanup_outpoints_map=*/CountWtxid(it_ann->m_tx->GetWitnessHash()) == 1);
            num_erased += 1;

            // Unless this peer is empty, put it back in the heap so we continue to consider evicting its orphans.
            // Calculate the DoS score again. It might still be the DoSiest peer.
            auto it_worst_peer = m_peer_orphanage_info.find(worst_peer);
            if (it_worst_peer != m_peer_orphanage_info.end() && it_worst_peer->second.m_count_announcements > 0) {
                heap_peer_dos.push_back(std::make_pair(worst_peer, it_worst_peer->second.GetDosScore(max_ann, max_mem)));
                std::push_heap(heap_peer_dos.begin(), heap_peer_dos.end(), compare_score);
            }
        } while (NeedsTrim());

        const auto remaining_unique_orphans{CountUniqueOrphans()};
        LogDebug(BCLog::TXPACKAGES, "orphanage overflow, removed %u tx (%u announcements)\n", original_unique_txns - remaining_unique_orphans, num_erased);
    }

    std::vector<TxOrphanage::OrphanTxBase> GetOrphanTransactions() const
    {
        std::vector<TxOrphanage::OrphanTxBase> result;
        result.reserve(m_unique_orphans);

        auto& index_by_wtxid = m_orphans.get<ByWtxid>();
        auto it = index_by_wtxid.begin();
        std::set<NodeId> this_orphan_announcers;
        while (it != index_by_wtxid.end()) {
            this_orphan_announcers.insert(it->m_announcer);
            // If this is the last entry, or the next entry has a different wtxid, build a OrphanTxBase.
            if (std::next(it) == index_by_wtxid.end() || std::next(it)->m_tx->GetWitnessHash() != it->m_tx->GetWitnessHash()) {
                result.emplace_back(TxOrphanage::OrphanTxBase{it->m_tx, this_orphan_announcers});
                this_orphan_announcers.clear();
            }

            ++it;
        }
        Assume(m_unique_orphans == result.size());

        return result;
    }
};
} // namespace node
#endif // BITCOIN_TXMEMPOOL_H
