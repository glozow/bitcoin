// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackagetracker.h>

#include <common/bloom.h>
#include <logging.h>
#include <txorphanage.h>
#include <txrequest.h>
#include <util/hasher.h>

namespace node {
    /** How long to wait before requesting orphan ancpkginfo/parents from an additional peer.
     * Same as GETDATA_TX_INTERVAL. */
    static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};

class TxPackageTracker::Impl {
    /** Whether package relay is enabled. When false, the tracker does basic orphan handling. */
    const bool m_enable_package_relay;
    /** Maximum number of transactions in orphanage. */
    const unsigned int m_max_orphan_count;

    TxOrphanage m_orphanage;

    mutable Mutex m_mutex;
    struct RegistrationState {
        // All of the following bools will need to be true
        /** Whether this peer allows transaction relay from us. */
        bool m_txrelay{true};
        // Whether this peer sent a BIP339 wtxidrelay message.
        bool m_wtxid_relay{false};
        /** Whether this peer says they can do package relay. */
        bool m_sendpackages_received{false};
        /** Versions of package relay supported by this node.
         * This is a subset of PACKAGE_RELAY_SUPPORTED_VERSIONS. */
        std::set<uint32_t> m_versions_in_common;
        bool CanRelayPackages() {
            return m_txrelay && m_wtxid_relay && m_sendpackages_received;
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
    Impl(const TxPackageTracker::Options& opts) :
        m_enable_package_relay{opts.enable_package_relay},
        m_max_orphan_count{opts.max_orphan_count}
    {}
    /** (Batch) Update transactions for which we have made "final" decisions: transactions that have
     * confirmed in a block, conflicted due to a block, or added to the mempool already.
     * Should be called on new block: valid=block transactions, invalid=conflicts.
     * Should be called when tx is added to mempool.
     * Should not be called when a tx fails validation.
     * */
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
    void BlockConnected(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        const auto wtxids_erased{m_orphanage.EraseForBlock(block)};
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
    void ReceivedVersion(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        if (registration_states.find(nodeid) != registration_states.end()) return;
        registration_states.insert(std::make_pair(nodeid, RegistrationState{}));
    }
    void ReceivedSendpackages(NodeId nodeid, uint32_t version) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        const auto it = registration_states.find(nodeid);
        if (it == registration_states.end()) return;
        it->second.m_sendpackages_received = true;
        // Ignore versions we don't understand.
        if (std::count(PACKAGE_RELAY_SUPPORTED_VERSIONS.cbegin(), PACKAGE_RELAY_SUPPORTED_VERSIONS.cend(), version)) {
            it->second.m_versions_in_common.insert(version);
        }
    }

    bool ReceivedVerack(NodeId nodeid, bool txrelay, bool wtxidrelay) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        const auto& it = registration_states.find(nodeid);
        if (it == registration_states.end()) return false;
        it->second.m_txrelay = txrelay;
        it->second.m_wtxid_relay = wtxidrelay;
        const bool final_state = it->second.CanRelayPackages();
        if (final_state) {
            auto [peerinfo_it, success] = info_per_peer.insert(std::make_pair(nodeid, PeerInfo{}));
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
        m_orphanage.EraseForPeer(nodeid);
    }
    bool OrphanageHaveTx(const GenTxid& gtxid) const { return m_orphanage.HaveTx(gtxid); }
    void AddOrphanTx(NodeId nodeid, const std::pair<uint256, CTransactionRef>& tx, bool is_preferred,
                     std::chrono::microseconds reqtime)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        // Skip if already requested in the (recent-ish) past.
        if (packageinfo_requested.contains(GetPackageInfoRequestId(nodeid, tx.first, RECEIVER_INIT_ANCESTOR_PACKAGES))) return;
        auto it_peer_info = info_per_peer.find(nodeid);
        if (it_peer_info != info_per_peer.end() && it_peer_info->second.SupportsVersion(RECEIVER_INIT_ANCESTOR_PACKAGES)) {
            // Package relay peer: is_wtxid=true because we will be requesting via ancpkginfo.
            orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Wtxid(tx.first), is_preferred, reqtime);
        } else {
            // Even though this stores the orphan wtxid, is_wtxid=false because we will be requesting the parents via txid.
            orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Txid(tx.first), is_preferred, reqtime);
        }

        if (tx.second && m_orphanage.AddTx(tx.second, nodeid)) {
            // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789)
            m_orphanage.LimitOrphans(m_max_orphan_count);
        }
    }
    void TransactionAccepted(const CTransactionRef& tx)
    {
        m_orphanage.AddChildrenToWorkSet(*tx);
        m_orphanage.EraseTx(tx->GetWitnessHash());
        FinalizeTransactions({tx->GetWitnessHash()}, {});
    }
    void TransactionRejected(const uint256& wtxid)
    {
        m_orphanage.EraseTx(wtxid);
    }
    CTransactionRef GetTxToReconsider(NodeId nodeid)
    {
        return m_orphanage.GetTxToReconsider(nodeid);
    }
    bool HaveTxToReconsider(NodeId nodeid) { return m_orphanage.HaveTxToReconsider(nodeid); }
    size_t OrphanageSize()
    {
        m_orphanage.LimitOrphans(m_max_orphan_count);
        return m_orphanage.Size();
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
            LogPrint(BCLog::TXPACKAGES, "\nTimeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "ancpkginfo" : "orphan parent",
                entry.second.GetHash().ToString(), entry.first);
        }
        std::vector<GenTxid> results;
        for (const auto& gtxid : tracker_requestable) {
            if (gtxid.IsWtxid()) {
                Assume(info_per_peer.find(nodeid) != info_per_peer.end());
                // Add the orphan's wtxid as-is.
                LogPrint(BCLog::TXPACKAGES, "\nResolving orphan %s, requesting by ancpkginfo from peer=%d\n", gtxid.GetHash().ToString(), nodeid);
                results.emplace_back(gtxid);
                packageinfo_requested.insert(GetPackageInfoRequestId(nodeid, gtxid.GetHash(), RECEIVER_INIT_ANCESTOR_PACKAGES));
                orphan_request_tracker.RequestedTx(nodeid, gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
            } else {
                LogPrint(BCLog::TXPACKAGES, "\nResolving orphan %s, requesting by txids of parents from peer=%d\n", gtxid.GetHash().ToString(), nodeid);
                const auto ptx = m_orphanage.GetTx(gtxid.GetHash());
                if (!ptx) {
                    // We can't request ancpkginfo and we have no way of knowing what the missing
                    // parents are (it could also be that the orphan has already been resolved).
                    // Give up.
                    orphan_request_tracker.ForgetTxHash(gtxid.GetHash());
                    LogPrint(BCLog::TXPACKAGES, "\nForgetting orphan %s from peer=%d\n", gtxid.GetHash().ToString(), nodeid);
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
        if (!results.empty()) LogPrint(BCLog::TXPACKAGES, "\nRequesting %u items from peer=%d\n", results.size(), nodeid);
        return results;
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
    void ForgetPkgInfo(NodeId nodeid, const uint256& rep_wtxid, uint32_t pkginfo_version) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        if (pkginfo_version == RECEIVER_INIT_ANCESTOR_PACKAGES) {
            orphan_request_tracker.ReceivedResponse(nodeid, rep_wtxid);
        }
    }
};

TxPackageTracker::TxPackageTracker(const TxPackageTracker::Options& opts) : m_impl{std::make_unique<TxPackageTracker::Impl>(opts)} {}
TxPackageTracker::~TxPackageTracker() = default;

void TxPackageTracker::BlockConnected(const CBlock& block) { m_impl->BlockConnected(block); }
/** Peer has disconnected, tear down state. */
void TxPackageTracker::DisconnectedPeer(NodeId nodeid) { m_impl->DisconnectedPeer(nodeid); }
/** Returns whether a tx is present in the orphanage. */
bool TxPackageTracker::OrphanageHaveTx(const GenTxid& gtxid) const { return m_impl->OrphanageHaveTx(gtxid); }
void TxPackageTracker::AddOrphanTx(NodeId nodeid, const std::pair<uint256, CTransactionRef>& tx, bool is_preferred, std::chrono::microseconds reqtime)
{
    m_impl->AddOrphanTx(nodeid, tx, is_preferred, reqtime);
}
void TxPackageTracker::ReceivedVersion(NodeId nodeid) { m_impl->ReceivedVersion(nodeid); }
void TxPackageTracker::ReceivedSendpackages(NodeId nodeid, uint32_t version) { m_impl->ReceivedSendpackages(nodeid, version); }
bool TxPackageTracker::ReceivedVerack(NodeId nodeid, bool txrelay, bool wtxidrelay) {
    return m_impl->ReceivedVerack(nodeid, txrelay, wtxidrelay);
}
/** Transaction accepted to mempool. */
void TxPackageTracker::TransactionAccepted(const CTransactionRef& tx) { m_impl->TransactionAccepted(tx); }
/** Transaction rejected for non-missing-inputs reason. */
void TxPackageTracker::TransactionRejected(const uint256& wtxid) { m_impl->TransactionRejected(wtxid); }
/** Get tx from orphan that can be reconsidered. */
CTransactionRef TxPackageTracker::GetTxToReconsider(NodeId nodeid) { return m_impl->GetTxToReconsider(nodeid); }
/** Whether there are more orphans from this peer to consider. */
bool TxPackageTracker::HaveTxToReconsider(NodeId nodeid) const { return m_impl->HaveTxToReconsider(nodeid); }
/** Returns the number of transactions in the orphanage. */
size_t TxPackageTracker::OrphanageSize() const { return m_impl->OrphanageSize(); }
size_t TxPackageTracker::Count(NodeId nodeid) const { return m_impl->Count(nodeid); }
size_t TxPackageTracker::CountInFlight(NodeId nodeid) const { return m_impl->CountInFlight(nodeid); }
std::vector<GenTxid> TxPackageTracker::GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time) {
    return m_impl->GetOrphanRequests(nodeid, current_time);
}
bool TxPackageTracker::PkgInfoAllowed(NodeId nodeid, const uint256& wtxid, uint32_t version)
{
    return m_impl->PkgInfoAllowed(nodeid, wtxid, version);
}
void TxPackageTracker::ForgetPkgInfo(NodeId nodeid, const uint256& rep_wtxid, uint32_t pkginfo_version)
{
    m_impl->ForgetPkgInfo(nodeid, rep_wtxid, pkginfo_version);
}
} // namespace node
