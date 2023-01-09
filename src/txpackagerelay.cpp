// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txpackagerelay.h>

#include <common/bloom.h>
#include <logging.h>
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
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage& orphanage_ref;

    mutable Mutex m_mutex;
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
        std::set<uint32_t> m_versions_in_common;
        bool CanRelayPackages() {
            return m_txrelay && m_wtxid_relay && m_sendpackages_sent && m_sendpackages_received;
        }
    };
    /** Represents AncPkgInfo for which we are missing transaction data. */
    struct PackageToDownload {
        /** Who provided the ancpkginfo - this is the peer whose work queue to add this package when
         * all tx data is received. We expect to receive tx data from this peer. */
        const NodeId m_pkginfo_provider;

        /** Total virtual size of the tx data we have seen so far. This helps us limit how much
         * txdata worth of orphans we are protecting and quit early if a package exceeds what we
         * would accept. */
        int64_t m_total_vsize;

        /** When to stop trying to download this package if we haven't received tx data yet. */
        std::chrono::microseconds m_expiry;

        /** Representative wtxid, i.e. the orphan in an ancestor package. */
        const uint256 m_rep_wtxid;

        /** Map from wtxid to status (true indicates it is missing). This can be expanded to further
         * states such as "already in mempool/confirmed" in the future. */
        std::map<uint256, bool> m_txdata_status;

        // Package info without wtxids doesn't make sense.
        PackageToDownload() = delete;
        // Constructor if you already know size.
        PackageToDownload(NodeId nodeid,
                          int64_t total_size,
                          std::chrono::microseconds expiry,
                          const uint256& rep_wtxid,
                          const std::map<uint256, bool>& txdata_status) :
            m_pkginfo_provider{nodeid},
            m_total_vsize{total_size},
            m_expiry{expiry},
            m_rep_wtxid{rep_wtxid},
            m_txdata_status{txdata_status}
        {}
        // Returns true if any tx data is still needed.
        bool MissingTxData() {
            return std::any_of(m_txdata_status.cbegin(), m_txdata_status.cend(),
                               [](const auto pair){return pair.second;});
        }
        // Returns true if total virtual size is exceeded.
        bool UpdateStatusAndCheckSize(const CTransactionRef& tx, int64_t max_vsize) {
            auto map_iter = m_txdata_status.find(tx->GetWitnessHash());
            if (map_iter == m_txdata_status.end()) return false;
            // Don't double-count transaction size; only increment if this is new.
            if (!map_iter->second) {
                m_total_vsize += GetVirtualTransactionSize(*tx);
            }
            map_iter->second = false;
            return m_total_vsize > max_vsize;
        }
        bool HasTransactionIn(const std::set<uint256>& wtxidset) const {
            for (const auto& keyval : m_txdata_status) {
                if (wtxidset.count(keyval.first) > 0) return true;
            }
            return false;
        }
        /** Returns wtxid of representative transaction (i.e. the orphan in an ancestor package). */
        const uint256 RepresentativeWtxid() const { return m_rep_wtxid; }
        /** Combined hash of all wtxids in package. */
        const uint256 GetPackageHash() const {
            std::vector<uint256> all_wtxids;
            std::transform(m_txdata_status.cbegin(), m_txdata_status.cend(), std::back_inserter(all_wtxids),
                [](const auto& mappair) { return mappair.first; });
            return GetCombinedHash(all_wtxids);
        }
    };

    using PackageInfoRequestId = uint256;
    PackageInfoRequestId GetPackageInfoRequestId(NodeId nodeid, const uint256& wtxid, uint32_t version) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << wtxid << version).GetHash();
    }
    using PackageTxnsRequestId = uint256;
    PackageTxnsRequestId GetPackageTxnsRequestId(NodeId nodeid, const std::vector<uint256>& wtxids) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << GetCombinedHash(wtxids)).GetHash();
    }
    PackageTxnsRequestId GetPackageTxnsRequestId(NodeId nodeid, const std::vector<CTransactionRef>& pkgtxns) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << GetPackageHash(pkgtxns)).GetHash();
    }
    PackageTxnsRequestId GetPackageTxnsRequestId(NodeId nodeid, const uint256& combinedhash) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << combinedhash).GetHash();
    }
    /** List of all ancestor package info we're currently requesting txdata for, indexed by the
     * nodeid and getpkgtxns request we would have sent them. */
    std::map<PackageTxnsRequestId, PackageToDownload> pending_package_info GUARDED_BY(m_mutex);

    using PendingMap = decltype(pending_package_info);
    struct IteratorComparator {
        template<typename I>
        bool operator()(const I& a, const I& b) const { return &(*a) < &(*b); }
    };

    struct PeerInfo {
        // What package versions we agreed to relay.
        std::set<uint32_t> m_versions_supported;
        bool SupportsVersion(uint32_t version) { return m_versions_supported.count(version) > 0; }

        std::set<PendingMap::iterator, IteratorComparator> m_package_info_provided;
    };

    /** Stores relevant information about the peer prior to verack. Upon completion of version
     * handshake, we use this information to decide whether we relay packages with this peer. */
    std::map<NodeId, RegistrationState> registration_states GUARDED_BY(m_mutex);

    /** Information for each peer we relay packages with. Membership in this map is equivalent to
     * whether or not we relay packages with a peer. */
    std::map<NodeId, PeerInfo> info_per_peer GUARDED_BY(m_mutex);

    /** Tracks orphans for which we need to request ancestor information. All hashes stored are
     * wtxids, i.e., the wtxid of the orphan. However, the is_wtxid field is used to indicate
     * whether we would request the ancestor information by wtxid (via package relay) or by txid
     * (via prevouts of the missing inputs). */
    TxRequestTracker orphan_request_tracker GUARDED_BY(m_mutex);

    /** Cache of package info requests sent. Used to identify unsolicited package info messages. */
    CRollingBloomFilter packageinfo_requested GUARDED_BY(m_mutex){50000, 0.000001};

public:
    Impl(TxOrphanage& orphanage) : orphanage_ref{orphanage} {}
    void ReceivedVersion(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        Assume(registration_states.find(nodeid) == registration_states.end());
        registration_states.insert(std::make_pair(nodeid, RegistrationState{}));
    }
    void ReceivedTxRelayInfo(NodeId nodeid, bool txrelay) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        const auto it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_txrelay = txrelay;
    }
    void ReceivedWtxidRelay(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        const auto it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_wtxid_relay = true;
    }
    void ReceivedSendpackages(NodeId nodeid, uint32_t version) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        const auto it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_sendpackages_received = true;
        // Ignore versions we don't understand.
        if (std::count(PACKAGE_RELAY_SUPPORTED_VERSIONS.cbegin(), PACKAGE_RELAY_SUPPORTED_VERSIONS.cend(), version)) {
            it->second.m_versions_in_common.insert(version);
        }
    }
    void SentSendpackages(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        const auto it = registration_states.find(nodeid);
        Assume(it != registration_states.end());
        it->second.m_sendpackages_sent = true;
    }

    bool ReceivedVerack(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
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

    void DisconnectedPeer(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        if (auto it{registration_states.find(nodeid)}; it != registration_states.end()) {
            registration_states.erase(it);
        }
        if (auto it{info_per_peer.find(nodeid)}; it != info_per_peer.end()) {
            for (const auto& pkginfo_iter : it->second.m_package_info_provided) {
                if (pkginfo_iter != pending_package_info.end()) {
                    orphanage_ref.UndoProtectOrphan(pkginfo_iter->second.m_rep_wtxid);
                }
                it->second.m_package_info_provided.erase(pkginfo_iter);
                pending_package_info.erase(pkginfo_iter);
            }
            info_per_peer.erase(it);
        }
        orphan_request_tracker.DisconnectedPeer(nodeid);
    }
    void AddOrphanTx(NodeId nodeid, const uint256& wtxid, bool is_preferred, std::chrono::microseconds reqtime)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto it_peer_info = info_per_peer.find(nodeid);
        if (it_peer_info != info_per_peer.end() && it_peer_info->second.SupportsVersion(RECEIVER_INIT_ANCESTOR_PACKAGES)) {
            // Package relay peer: is_wtxid=true because we will be requesting via ancpkginfo.
            orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Wtxid(wtxid), is_preferred, reqtime);
        } else {
            // Even though this stores the orphan wtxid, is_wtxid=false because we will be requesting the parents via txid.
            orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Txid(wtxid), is_preferred, reqtime);
        }
    }
    size_t CountInFlight(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto count{orphan_request_tracker.CountInFlight(nodeid)};
        if (auto it{info_per_peer.find(nodeid)}; it != info_per_peer.end()) {
            count += it->second.m_package_info_provided.size();
        }
        return count;
    }
    size_t Count(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto count{orphan_request_tracker.Count(nodeid)};
        if (auto it{info_per_peer.find(nodeid)}; it != info_per_peer.end()) {
            count += it->second.m_package_info_provided.size();
        }
        return count;
    }

    void ExpirePackageToDownload(NodeId nodeid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        AssertLockHeld(m_mutex);
        auto peer_info_it = info_per_peer.find(nodeid);
        if (peer_info_it == info_per_peer.end()) return;
        std::set<PackageTxnsRequestId> to_expire;
        for (const auto& pkginfo_iter : peer_info_it->second.m_package_info_provided) {
            const auto& packageinfo = pkginfo_iter->second;
            if (packageinfo.m_expiry < current_time) {
                LogPrint(BCLog::NET, "expiring package info for tx %s from peer=%d",
                         packageinfo.RepresentativeWtxid().ToString(), nodeid);
                to_expire.insert(pkginfo_iter->first);
                orphanage_ref.UndoProtectOrphan(pkginfo_iter->second.m_rep_wtxid);
            }
        }
        for (const auto& packageid : to_expire) {
            auto pending_iter = pending_package_info.find(packageid);
            Assume(pending_iter != pending_package_info.end());
            if (pending_iter != pending_package_info.end()) {
                peer_info_it->second.m_package_info_provided.erase(pending_iter);
                pending_package_info.erase(pending_iter);
            }
        }
    }
    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        // Expire packages we were trying to download tx data for
        ExpirePackageToDownload(nodeid, current_time);
        std::vector<std::pair<NodeId, GenTxid>> expired;
        auto tracker_requestable = orphan_request_tracker.GetRequestable(nodeid, current_time, &expired);
        for (const auto& entry : expired) {
            LogPrint(BCLog::NET, "timeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "ancpkginfo" : "orphan parent",
                entry.second.GetHash().ToString(), entry.first);
        }
        // Get getdata requests we should send
        std::vector<GenTxid> results;
        for (const auto& gtxid : tracker_requestable) {
            if (gtxid.IsWtxid()) {
                Assume(info_per_peer.find(nodeid) != info_per_peer.end());
                // Add the orphan's wtxid as-is.
                LogPrint(BCLog::NET, "resolving orphan %s, requesting by ancpkginfo from peer=%d", gtxid.GetHash().ToString(), nodeid);
                results.emplace_back(gtxid);
                packageinfo_requested.insert(GetPackageInfoRequestId(nodeid, gtxid.GetHash(), RECEIVER_INIT_ANCESTOR_PACKAGES));
                orphan_request_tracker.RequestedTx(nodeid, gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
            } else {
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
        if (!results.empty()) LogPrintf("Requesting %u items from peer=%d", results.size(), nodeid);
        return results;
    }
    void FinalizeTransactions(const std::set<uint256>& valid, const std::set<uint256>& invalid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        // Do a linear search of all packages. This operation should not be expensive as we don't
        // expect to be relaying more than 1 package per peer. Nonetheless, process sets together
        // to be more efficient.
        std::set<PackageTxnsRequestId> to_erase;
        for (const auto& [packageid, packageinfo] : pending_package_info) {
            const auto& rep_wtxid = packageinfo.RepresentativeWtxid();
            if (valid.count(rep_wtxid) > 0 || invalid.count(rep_wtxid) > 0) {
                // We have already made a final decision on the transaction of interest.
                // There is no need to request more information from other peers.
                to_erase.insert(packageid);
                orphan_request_tracker.ForgetTxHash(rep_wtxid);
            } else if (packageinfo.HasTransactionIn(invalid)) {
                // This package info is known to contain an invalid transaction; don't continue
                // trying to download or validate it.
                to_erase.insert(packageid);
                // However, as it's possible for this information to be incorrect (e.g. a peer
                // purposefully trying to get us to reject the orphan by providing package info
                // containing an invalid transaction), don't prevent further orphan resolution
                // attempts with other peers.
            } else {
                // FIXME: Some packages may need less txdata now.
                // It's fine not to do this *for now* since we always request all missing txdata
                // from the same peer.
            }
        }
        for (const auto& packageid : to_erase) {
            auto pending_iter = pending_package_info.find(packageid);
            Assume(pending_iter != pending_package_info.end());
            if (pending_iter != pending_package_info.end()) {
                auto peer_info_it = info_per_peer.find(pending_iter->second.m_pkginfo_provider);
                Assume(peer_info_it != info_per_peer.end());
                if (peer_info_it != info_per_peer.end()) {
                    peer_info_it->second.m_package_info_provided.erase(pending_iter);
                }
                pending_package_info.erase(pending_iter);
            }
        }
    }
    void HandleNewBlock(const CBlock& block)
    {
        const auto wtxids_erased{orphanage_ref.EraseForBlock(block)};
        std::set<uint256> block_wtxids;
        std::set<uint256> conflicted_wtxids;
        for (const CTransactionRef& ptx : block.vtx) {
            block_wtxids.insert(ptx->GetWitnessHash());
        }
        for (const auto& wtxid : wtxids_erased) {
            if (block_wtxids.count(wtxid) == 0) {
                conflicted_wtxids.insert(wtxid);
            }
        }
        FinalizeTransactions(block_wtxids, conflicted_wtxids);
    }
    bool PkgInfoAllowed(NodeId nodeid, const uint256& wtxid, uint32_t version) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        if (info_per_peer.find(nodeid) == info_per_peer.end()) {
            return false;
        }
        auto peer_info = info_per_peer.find(nodeid)->second;
        const auto packageid{GetPackageInfoRequestId(nodeid, wtxid, version)};
        if (!packageinfo_requested.contains(packageid)) {
            return false;
        }
        orphan_request_tracker.ReceivedResponse(nodeid, wtxid);
        // They already responded to this request.
        for (const auto& pkginfo_iter : peer_info.m_package_info_provided) {
            if (wtxid == pkginfo_iter->second.m_rep_wtxid) return false;
        }
        return true;
    }
    bool ReceivedAncPkgInfo(NodeId nodeid, const uint256& rep_wtxid, const std::map<uint256, bool>& txdata_status,
                            const std::vector<uint256>& missing_wtxids, int64_t total_orphan_size,
                            std::chrono::microseconds expiry)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto peer_info_it = info_per_peer.find(nodeid);
        if (peer_info_it == info_per_peer.end()) return true;
        const auto pkgtxnsid{GetPackageTxnsRequestId(nodeid, missing_wtxids)};
        const auto [it, success] = pending_package_info.emplace(pkgtxnsid,
            PackageToDownload{nodeid, total_orphan_size, expiry, rep_wtxid, txdata_status});
        Assume(success);
        for (const auto& [wtxid, missing] : txdata_status) {
            if (orphanage_ref.HaveTx(GenTxid::Wtxid(wtxid))) {
                orphanage_ref.ProtectOrphan(wtxid);
                Assume(orphanage_ref.NumProtected() <= MAX_IN_FLIGHT_PACKAGES * info_per_peer.size());
            }
        }
        peer_info_it->second.m_package_info_provided.emplace(it);
        return false;
    }
    void ReceivedNotFound(NodeId nodeid, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto peer_info_it = info_per_peer.find(nodeid);
        if (peer_info_it == info_per_peer.end()) return;
        const auto pending_iter{pending_package_info.find(GetPackageTxnsRequestId(nodeid, hash))};
        if (pending_iter != pending_package_info.end()) {
            auto& pendingpackage{pending_iter->second};
            for (const auto& [wtxid, missing] : pendingpackage.m_txdata_status) {
                if (orphanage_ref.HaveTx(GenTxid::Wtxid(wtxid))) {
                    orphanage_ref.UndoProtectOrphan(wtxid);
                }
            }
            Assume(orphanage_ref.NumProtected() <= MAX_IN_FLIGHT_PACKAGES * info_per_peer.size());
            LogPrint(BCLog::NET, "received notfound for package (tx %s) from peer=%d", pendingpackage.RepresentativeWtxid().ToString(), nodeid);
        }
    }
    std::optional<PackageToValidate> ReceivedPkgTxns(NodeId nodeid, const std::vector<CTransactionRef>& package_txns)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto peer_info_it = info_per_peer.find(nodeid);
        if (peer_info_it == info_per_peer.end()) return std::nullopt;
        const auto pending_iter{pending_package_info.find(GetPackageTxnsRequestId(nodeid, package_txns))};
        if (pending_iter == pending_package_info.end()) {
            // For whatever reason, we've been sent a pkgtxns that doesn't correspond to a pending
            // package. It's possible we already admitted all the transactions, or this response
            // arrived past the request expiry. Drop it on the ground.
            return std::nullopt;
        }
        std::vector<CTransactionRef> unvalidated_txdata(package_txns.cbegin(), package_txns.cend());
        auto& pendingpackage{pending_iter->second};
        LogPrint(BCLog::NET, "received tx data for package (tx %s) from peer=%d", pendingpackage.RepresentativeWtxid().ToString(), nodeid);
        // Add the other orphanage transactions before updating pending packages map.
        for (const auto& [wtxid, _] : pendingpackage.m_txdata_status) {
            if (orphanage_ref.HaveTx(GenTxid::Wtxid(wtxid))) {
                unvalidated_txdata.push_back(orphanage_ref.GetTx(wtxid));
            }
        }
        // Only update this node's package info. We would have made a separate txdata request if for
        // other package that also requires this transaction.
        // update status and check if too many protected orphans
        for (const auto& tx : package_txns) {
            if (pendingpackage.UpdateStatusAndCheckSize(tx, MAX_PACKAGE_SIZE * 1000)) {
                pending_package_info.erase(pending_iter);
                return std::nullopt;
            }
        }
        Assume(!pendingpackage.MissingTxData()); // FIXME: is this possible when honest?
        return PackageToValidate{pendingpackage.m_pkginfo_provider, pendingpackage.RepresentativeWtxid(),
                                 pendingpackage.GetPackageHash(), unvalidated_txdata};
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
void TxPackageTracker::AddOrphanTx(NodeId nodeid, const uint256& wtxid, bool is_preferred, std::chrono::microseconds reqtime)
{
    m_impl->AddOrphanTx(nodeid, wtxid, is_preferred, reqtime);
}
size_t TxPackageTracker::CountInFlight(NodeId nodeid) const { return m_impl->CountInFlight(nodeid); }
size_t TxPackageTracker::Count(NodeId nodeid) const { return m_impl->Count(nodeid); }
std::vector<GenTxid> TxPackageTracker::GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time) {
    return m_impl->GetOrphanRequests(nodeid, current_time);
}
void TxPackageTracker::FinalizeTransactions(const std::set<uint256>& valid, const std::set<uint256>& invalid)
{
    m_impl->FinalizeTransactions(valid, invalid);
}
void TxPackageTracker::HandleNewBlock(const CBlock& block) { m_impl->HandleNewBlock(block); }
bool TxPackageTracker::PkgInfoAllowed(NodeId nodeid, const uint256& wtxid, uint32_t version)
{
    return m_impl->PkgInfoAllowed(nodeid, wtxid, version);
}
bool TxPackageTracker::ReceivedAncPkgInfo(NodeId nodeid, const uint256& rep_wtxid, const std::map<uint256, bool>& txdata_status,
                                          const std::vector<uint256>& missing_wtxids, int64_t total_orphan_size,
                                          std::chrono::microseconds expiry)
{
    return m_impl->ReceivedAncPkgInfo(nodeid, rep_wtxid, txdata_status, missing_wtxids, total_orphan_size, expiry);
}
void TxPackageTracker::ReceivedNotFound(NodeId nodeid, const uint256& hash) { m_impl->ReceivedNotFound(nodeid, hash); }
std::optional<TxPackageTracker::PackageToValidate> TxPackageTracker::ReceivedPkgTxns(NodeId nodeid,
    const std::vector<CTransactionRef>& package_txns)
{
    return m_impl->ReceivedPkgTxns(nodeid, package_txns);
}
