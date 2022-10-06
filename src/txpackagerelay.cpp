// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txpackagerelay.h>

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

    struct PeerInfo {
        // What package versions we agreed to relay.
        std::vector<uint32_t> m_versions_supported;
    };

    TxOrphanage& orphanage_ref;

    /** Stores relevant information about the peer prior to verack. Upon completion of version
     * handshake, we use this information to decide whether we relay packages with this peer. */
    std::map<NodeId, RegistrationState> registration_states;

    /** Information for each peer we relay packages with. Membership in this map is equivalent to
     * whether or not we relay packages with a peer. */
    std::map<NodeId, PeerInfo> info_per_peer;

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
