// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txpackagerelay.h>

#include <common/bloom.h>
#include <logging.h>
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
    using PackageInfoRequestId = uint256;
    PackageInfoRequestId GetPackageInfoRequestId(NodeId nodeid, const uint256& wtxid, uint32_t version) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << wtxid << version).GetHash();
    }

    struct PeerInfo {
        // What package versions we agreed to relay.
        std::set<uint32_t> m_versions_supported;
        bool SupportsVersion(uint32_t version) { return m_versions_supported.count(version) > 0; }
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
        return count;
    }
    size_t Count(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto count{orphan_request_tracker.Count(nodeid)};
        return count;
    }

    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        std::vector<std::pair<NodeId, GenTxid>> expired;
        auto tracker_requestable = orphan_request_tracker.GetRequestable(nodeid, current_time, &expired);
        for (const auto& entry : expired) {
            LogPrint(BCLog::NET, "timeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "ancpkginfo" : "orphan parent",
                entry.second.GetHash().ToString(), entry.first);
        }
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
        for (const auto& wtxid : valid) {
            orphan_request_tracker.ForgetTxHash(wtxid);
        }
        for (const auto& wtxid : invalid) {
            orphan_request_tracker.ForgetTxHash(wtxid);
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
        if (!packageinfo_requested.contains(GetPackageInfoRequestId(nodeid, wtxid, RECEIVER_INIT_ANCESTOR_PACKAGES))) {
            return false;
        }
        orphan_request_tracker.ReceivedResponse(nodeid, wtxid);
        return true;
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
