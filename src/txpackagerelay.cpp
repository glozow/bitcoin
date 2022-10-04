// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txpackagerelay.h>

void TxPackageTracker::ReceivedVersion(NodeId nodeid)
{
    Assume(registration_states.find(nodeid) == registration_states.end());
    registration_states.insert(std::make_pair(nodeid, RegistrationState{}));
}

void TxPackageTracker::ReceivedTxRelayInfo(NodeId nodeid, bool txrelay)
{
    const auto& it = registration_states.find(nodeid);
    Assume(it != registration_states.end());
    it->second.m_txrelay = txrelay;
}

void TxPackageTracker::ReceivedWtxidRelay(NodeId nodeid)
{
    const auto& it = registration_states.find(nodeid);
    Assume(it != registration_states.end());
    it->second.m_wtxid_relay = true;
}

void TxPackageTracker::ReceivedSendpackages(NodeId nodeid, uint32_t version)
{
    const auto& it = registration_states.find(nodeid);
    Assume(it != registration_states.end());
    it->second.m_sendpackages_received = true;
    // Ignore versions we don't understand.
    if (std::count(PACKAGE_RELAY_SUPPORTED_VERSIONS.cbegin(), PACKAGE_RELAY_SUPPORTED_VERSIONS.cend(), version)) {
        it->second.m_versions_in_common.push_back(version);
    }
}
void TxPackageTracker::SentSendpackages(NodeId nodeid)
{
    const auto& it = registration_states.find(nodeid);
    Assume(it != registration_states.end());
    it->second.m_sendpackages_sent = true;
}

bool TxPackageTracker::ReceivedVerack(NodeId nodeid)
{
    const auto& it = registration_states.find(nodeid);
    Assume(it != registration_states.end());
    const bool final_state = it->second.CanRelayPackages();
    auto [peerinfo_it, success] = info_per_peer.insert(std::make_pair(nodeid, PeerInfo{}));
    Assume(success);
    peerinfo_it->second.m_versions_supported = it->second.m_versions_in_common;
    registration_states.erase(it);
    return final_state;
}

void TxPackageTracker::DisconnectedPeer(NodeId nodeid)
{
    if (auto it{registration_states.find(nodeid)}; it != registration_states.end()) {
        registration_states.erase(it); 
    }
    if (auto it{info_per_peer.find(nodeid)}; it != info_per_peer.end()) {
        // Delete all PackageInfo entries.
        for (auto info_it : it->second.m_package_info_vec) {
            map_package_info.erase(info_it);
        }
        info_per_peer.erase(it);
    }
}

void TxPackageTracker::ReceivedPackageInfo(NodeId nodeid, const std::vector<uint256>& wtxids, uint64_t id)
{
    Assume(map_package_info.count(id) == 0);
    const auto [info_it, success] = map_package_info.insert(std::make_pair(id, PackageInfo{wtxids}));
    assert(success);
    auto peer_it{info_per_peer.find(nodeid)};
    Assume(peer_it != info_per_peer.end());
    peer_it->second.m_package_info_vec.push_back(info_it);
}

void TxPackageTracker::AddOrphanTx(NodeId nodeid, const CTransactionRef& orphan_tx)
{
    auto it_peer_info = info_per_peer.find(nodeid);
    Assume(it_peer_info != info_per_peer.end());
    it_peer_info->second.m_ancpkginfo_to_request.insert(orphan_tx->GetWitnessHash());
}

std::vector<uint256> TxPackageTracker::GetRequestableAncPkgInfo(NodeId nodeid)
{
    auto it_peer_info = info_per_peer.find(nodeid);
    Assume(it_peer_info != info_per_peer.end());
    std::vector<uint256> requestable(it_peer_info->second.m_ancpkginfo_to_request.begin(),
                                     it_peer_info->second.m_ancpkginfo_to_request.end());
    it_peer_info->second.m_ancpkginfo_to_request.clear();
    return requestable;
}

void TxPackageTracker::RequestedAncPkgInfo(NodeId nodeid, const std::vector<uint256>& wtxids)
{
    auto it_peer_info = info_per_peer.find(nodeid);
    Assume(it_peer_info != info_per_peer.end());
    for (const auto& wtxid : wtxids) {
        Assume(it_peer_info->second.m_ancpkginfo_requested.count(wtxid) == 0);
        it_peer_info->second.m_ancpkginfo_requested.insert(wtxid);
    }
}

bool TxPackageTracker::GotPkgInfoResponse(NodeId nodeid, const uint256& wtxid, bool notfound)
{
    auto it_peer_info = info_per_peer.find(nodeid);
    Assume(it_peer_info != info_per_peer.end());
    auto it = it_peer_info->second.m_ancpkginfo_requested.find(wtxid);
    if (it == it_peer_info->second.m_ancpkginfo_requested.end()) return false;
    it_peer_info->second.m_ancpkginfo_requested.erase(it);
    // FIXME: handle notfound. For example, find another peer, or fall back to requesting by txid?
    return true;
}
