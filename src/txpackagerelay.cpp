// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txpackagerelay.h>

#include <common/bloom.h>
#include <logging.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <txorphanage.h>
#include <txrequest.h>
#include <util/hasher.h>

namespace {
    /** How long to wait before requesting orphan ancpkginfo/parents from an additional peer.
     * Same as GETDATA_TX_INTERVAL. */
    static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};
}
class TxPackageTracker::Impl {
    struct RegistrationState {
        // All of the following bools will need to be true
        /** Whether this peer allows transaction relay from us. */
        bool m_txrelay{true};
        // Whether this peer sent a BIP339 wtxidrelay message.
        bool m_wtxid_relay{false};
        /** Whether this peer says they can do package relay. */
        bool m_sendpackages_received{false};
        /** Whether we sent a sendpackages message. */
        bool m_sendpackages_sent{false};

        /** Versions of package relay supported by this node.
         * This is a subset of PACKAGE_RELAY_SUPPORTED_VERSIONS. */
        std::vector<uint32_t> m_versions_in_common;

        bool CanRelayPackages() {
            return m_txrelay && m_wtxid_relay && m_sendpackages_sent && m_sendpackages_received;
        }
    };

    /** Represents AncPkgInfo for which we are missing transaction data. */
    struct PendingPackage {
        /** Who provided the ancpkginfo - this is the peer whose work queue to add this package when
         * all tx data is received. We expect to receive tx data from this peer. */
        NodeId m_pkginfo_provider;

        /** Total virtual size of the tx data we have seen so far (includes ORPHANAGE and ACCEPTED). */
        int64_t m_total_vsize;

        enum class Status : uint8_t {
            /** We still need the tx data and may or may not have requested it. */
            MISSING,
            /** We have the tx data in our orphanage. */
            ORPHANAGE,
            /** We already have the tx data in mempool or confirmed. */
            ACCEPTED,
        };
        /** Map from wtxid to status. */
        std::map<uint256, Status> m_txdata_status;

        // Package info without wtxids doesn't make sense.
        PendingPackage() = delete;
        PendingPackage(NodeId info, const std::vector<uint256> wtxids) :
            m_pkginfo_provider{info},
            m_total_vsize{0}
        {
            for (const auto& wtxid : wtxids) m_txdata_status.emplace(wtxid, Status::MISSING);
        }
        // Returns true if any tx data is still needed.
        bool MissingTxData() {
            return std::any_of(m_txdata_status.cbegin(), m_txdata_status.cend(),
                               [](const auto pair){return pair.second == Status::MISSING;});
        }
        // Returns true if total virtual size is exceeded.
        bool UpdateStatusAndCheckSize(const CTransactionRef& tx, int64_t max_vsize, Status status) {
            auto map_iter = m_txdata_status.find(tx->GetWitnessHash());
            if (map_iter == m_txdata_status.end()) return false;
            // Don't double-count transaction size; only increment if this is new.
            if (map_iter->second != Status::MISSING) {
                m_total_vsize += GetVirtualTransactionSize(*tx);
            }
            map_iter->second = status;
            return m_total_vsize > max_vsize;
        }
    };

    using PackageInfoRequestId = uint256;
    PackageInfoRequestId GetPackageInfoRequestId(NodeId nodeid, const uint256& wtxid, uint32_t version) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << wtxid << version).GetHash();
    }
    /** List of all ancestor package info we're currently requesting txdata for, indexed by the
     * wtxid of the representative tx (orphan). */
    std::map<PackageInfoRequestId, PendingPackage> pending_package_info;
    using PendingMap = decltype(pending_package_info);
    struct IteratorComparator {
        template<typename I>
        bool operator()(const I& a, const I& b) const { return &(*a) < &(*b); }
    };

    /** Map from a transaction for which we are missing txdata, indexed by wtxid, to the
     * PendingPackage(s) that need it. */
    std::map<uint256, std::set<PendingMap::iterator, IteratorComparator>> missing_txdata;

    struct PeerInfo {
        // What package versions we agreed to relay.
        std::vector<uint32_t> m_versions_supported;
        std::set<PendingMap::iterator, IteratorComparator> m_package_info_provided;

        /** Packages we need to validate. */
        std::deque<std::vector<CTransactionRef>> m_package_validation_queue;
    };

    TxOrphanage& orphanage_ref;

    /** Stores relevant information about the peer prior to verack. Upon completion of version
     * handshake, we use this information to decide whether we relay packages with this peer. */
    std::map<NodeId, RegistrationState> registration_states;

    /** Information for each peer we relay packages with. Membership in this map is equivalent to
     * whether or not we relay packages with a peer. */
    std::map<NodeId, PeerInfo> info_per_peer;

    /** Tracks orphans for which we need to request ancestor information. All hashes stored are
     * wtxids, i.e., the wtxid of the orphan. However, the is_wtxid field is used to indicate
     * whether we would request the ancestor information by wtxid (via package relay) or by txid
     * (via prevouts of the missing inputs). */
    TxRequestTracker orphan_request_tracker;
    /** Cache of package info requests sent. Used to identify unsolicited package info messages. */
    CRollingBloomFilter packageinfo_requested{50000, 0.000001};

public:

    Impl(TxOrphanage& orphanage) : orphanage_ref{orphanage} {}

    void ReceivedVersion(NodeId nodeid)
    {
        Assume(registration_states.find(nodeid) == registration_states.end());
        registration_states.insert(std::make_pair(nodeid, RegistrationState{}));
    }

    void ReceivedTxRelayInfo(NodeId nodeid, bool txrelay)
    {
        const auto& it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_txrelay = txrelay;
    }

    void ReceivedWtxidRelay(NodeId nodeid)
    {
        const auto& it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_wtxid_relay = true;
    }

    void ReceivedSendpackages(NodeId nodeid, uint32_t version)
    {
        const auto& it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_sendpackages_received = true;
        // Ignore versions we don't understand.
        if (std::count(PACKAGE_RELAY_SUPPORTED_VERSIONS.cbegin(), PACKAGE_RELAY_SUPPORTED_VERSIONS.cend(), version)) {
            it->second.m_versions_in_common.push_back(version);
        }
    }
    void SentSendpackages(NodeId nodeid)
    {
        const auto& it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_sendpackages_sent = true;
    }

    bool ReceivedVerack(NodeId nodeid)
    {
        const auto& it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        const bool final_state = it->second.CanRelayPackages();
        if (final_state) {
            auto [peerinfo_it, success] = info_per_peer.insert(std::make_pair(nodeid, PeerInfo{}));
            Assume(success);
            peerinfo_it->second.m_versions_supported = it->second.m_versions_in_common;
        }
        registration_states.erase(it);
        return final_state;
    }

    void DisconnectedPeer(NodeId nodeid)
    {
        if (auto it{registration_states.find(nodeid)}; it != registration_states.end()) {
            registration_states.erase(it);
        }
        if (auto it{info_per_peer.find(nodeid)}; it != info_per_peer.end()) {
            info_per_peer.erase(it);
        }
        orphan_request_tracker.DisconnectedPeer(nodeid);
    }
    void AddOrphanTx(NodeId nodeid, const uint256& wtxid, bool is_preferred, std::chrono::microseconds delay)
    {
        auto it_peer_info = info_per_peer.find(nodeid);
        if (it_peer_info != info_per_peer.end()) {
            // Package relay peer: is_wtxid=true because we will be requesting via ancpkginfo.
            orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Wtxid(wtxid), is_preferred, delay);
        } else {
            // Even though this stores the orphan wtxid, is_wtxid=false because we will be requesting the parents via txid.
            orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Txid(wtxid), is_preferred, delay);
        }
    }
    size_t CountOrphans(NodeId nodeid) const
    {
        return orphan_request_tracker.Count(nodeid);
    }

    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid)
    {
        std::vector<std::pair<NodeId, GenTxid>> expired;
        const auto current_time{GetTime<std::chrono::seconds>()};
        auto tracker_requestable = orphan_request_tracker.GetRequestable(nodeid, current_time, &expired);
        for (const auto& entry : expired) {
            LogPrint(BCLog::NET, "timeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "ancpkginfo" : "orphan parent",
                entry.second.GetHash().ToString(), entry.first);
        }
        std::vector<GenTxid> results;
        for (const auto& gtxid : tracker_requestable) {
            if (gtxid.IsWtxid()) {
                assert(info_per_peer.find(nodeid) != info_per_peer.end());
                // Add the orphan's wtxid as-is.
                LogPrint(BCLog::NET, "resolving orphan %s, requesting by ancpkginfo from peer=%d", gtxid.GetHash().ToString(), nodeid);
                results.emplace_back(gtxid);
                packageinfo_requested.insert(GetPackageInfoRequestId(nodeid, gtxid.GetHash(), RECEIVER_INIT_ANCESTOR_PACKAGES));
                orphan_request_tracker.RequestedTx(nodeid, gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
            } else {
                assert(info_per_peer.find(nodeid) == info_per_peer.end());
                LogPrint(BCLog::NET, "resolving orphan %s, requesting by txids of parents from peer=%d", gtxid.GetHash().ToString(), nodeid);
                const auto ptx = orphanage_ref.GetTx(gtxid.GetHash());
                if (!ptx) {
                    // We can't request ancpkginfo and we have no way of knowing what the missing
                    // parents are (it could also be that the orphan has already been resolved).
                    // Give up.
                    orphan_request_tracker.ForgetTxHash(gtxid.GetHash());
                    LogPrint(BCLog::NET, "forgetting orphan %s from peer=%d\n", gtxid.GetHash().ToString(), nodeid);
                    continue;
                }
                // Add the orphan's parents. Net processing will filter out what we already have.
                // Deduplicate parent txids, so that we don't have to loop over
                // the same parent txid more than once down below.
                std::vector<uint256> unique_parents;
                unique_parents.reserve(ptx->vin.size());
                for (const auto& txin : ptx->vin) {
                    // We start with all parents, and then remove duplicates below.
                    unique_parents.push_back(txin.prevout.hash);
                }
                std::sort(unique_parents.begin(), unique_parents.end());
                unique_parents.erase(std::unique(unique_parents.begin(), unique_parents.end()), unique_parents.end());
                for (const auto& txid : unique_parents) {
                    results.emplace_back(GenTxid::Txid(txid));
                }
                // Mark the orphan as requested
                orphan_request_tracker.RequestedTx(nodeid, gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
            }
        }
        LogPrintf("Requesting %u items from peer=%d", results.size(), nodeid);
        return results;
    }
    void Finalize(const GenTxid& gtxid)
    {
        orphan_request_tracker.ForgetTxHash(gtxid.GetHash());
    }
    bool PkgInfoAllowed(NodeId nodeid, const uint256& wtxid, uint32_t version)
    {
        if (info_per_peer.find(nodeid) == info_per_peer.end()) {
            return false;
        }
        auto peer_info = info_per_peer.find(nodeid)->second;
        const auto packageid{GetPackageInfoRequestId(nodeid, wtxid, version)};
        if (!packageinfo_requested.contains(packageid)) {
            return false;
        }
        orphan_request_tracker.ReceivedResponse(nodeid, wtxid);
        // They sent a duplicate?
        if (pending_package_info.count(packageid) > 0) return false;
        return true;
    }
    bool ReceivedAncPkgInfoResponse(NodeId nodeid, const std::vector<uint256>& info,
                                    const std::vector<uint256>& needed, int64_t max_vsize)
    {
        if (info_per_peer.find(nodeid) == info_per_peer.end()) {
            return true;
        }
        auto peer_info = info_per_peer.find(nodeid)->second;
        const auto packageid{GetPackageInfoRequestId(nodeid, info.back(), RECEIVER_INIT_ANCESTOR_PACKAGES)};
        PendingPackage pending_package{nodeid, info};
        for (const auto& wtxid : info) {
            if (orphanage_ref.HaveTx(GenTxid::Wtxid(wtxid))) {
                if (pending_package.UpdateStatusAndCheckSize(orphanage_ref.GetTx(wtxid), max_vsize,
                                                             PendingPackage::Status::ORPHANAGE)) {
                    // Exceeds maximum total package virtual size
                    return true; 
                }
            }
        }
        // This package info seems ok so far.
        const auto [it, success] = pending_package_info.emplace(packageid, pending_package);
        Assume(success);
        for (const auto& wtxid : info) {
            // Protect orphan from eviction while we wait for tx data for the rest of the package.
            // Note this is bounded by MAX_PACKAGE_SIZE and the fact that we only relay one in-flight package per peer.
            if (orphanage_ref.HaveTx(GenTxid::Wtxid(wtxid))) {
                orphanage_ref.ProtectOrphan(wtxid);
            } else {
                auto& pending_set = missing_txdata.try_emplace(wtxid).first->second;
                pending_set.insert(it);
            }
        }
        peer_info.m_package_info_provided.emplace(it);
        return false;
    }
};

TxPackageTracker::TxPackageTracker(TxOrphanage& orphanage) : m_impl{std::make_unique<TxPackageTracker::Impl>(orphanage)} {}
TxPackageTracker::~TxPackageTracker() = default;

void TxPackageTracker::ReceivedVersion(NodeId nodeid) { m_impl->ReceivedVersion(nodeid); }
void TxPackageTracker::ReceivedTxRelayInfo(NodeId nodeid, bool txrelay) { m_impl->ReceivedTxRelayInfo(nodeid, txrelay); }
void TxPackageTracker::ReceivedWtxidRelay(NodeId nodeid) { m_impl->ReceivedWtxidRelay(nodeid); }
void TxPackageTracker::ReceivedSendpackages(NodeId nodeid, uint32_t version) { m_impl->ReceivedSendpackages(nodeid, version); }
void TxPackageTracker::SentSendpackages(NodeId nodeid) { m_impl->SentSendpackages(nodeid); }
bool TxPackageTracker::ReceivedVerack(NodeId nodeid) { return m_impl->ReceivedVerack(nodeid); }
void TxPackageTracker::DisconnectedPeer(NodeId nodeid) { m_impl->DisconnectedPeer(nodeid); }

void TxPackageTracker::AddOrphanTx(NodeId nodeid, const uint256& wtxid, bool is_preferred, std::chrono::microseconds expiry)
{
    m_impl->AddOrphanTx(nodeid, wtxid, is_preferred, expiry);
}
size_t TxPackageTracker::CountOrphans(NodeId nodeid) const
{
    return m_impl->CountOrphans(nodeid);
}
std::vector<GenTxid> TxPackageTracker::GetOrphanRequests(NodeId nodeid) const
{
    return m_impl->GetOrphanRequests(nodeid);
}
void TxPackageTracker::Finalize(const GenTxid& gtxid)
{
    m_impl->Finalize(gtxid);
}
bool TxPackageTracker::PkgInfoAllowed(NodeId nodeid, const uint256& wtxid, uint32_t version)
{
    return m_impl->PkgInfoAllowed(nodeid, wtxid, version);
}
bool TxPackageTracker::ReceivedAncPkgInfoResponse(NodeId nodeid, const std::vector<uint256>& info,
                                                  const std::vector<uint256>& needed, int64_t max_vsize)
{
    return m_impl->ReceivedAncPkgInfoResponse(nodeid, info, needed, max_vsize);
}
