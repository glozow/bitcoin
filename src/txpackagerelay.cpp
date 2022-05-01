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
        info_per_peer.erase(it);
    }
}
