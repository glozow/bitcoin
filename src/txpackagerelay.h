// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TX_PKG_RELAY_H
#define BITCOIN_TX_PKG_RELAY_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};
static constexpr uint32_t RECEIVER_INIT_ANCESTOR_PACKAGES{0};
static std::vector<uint32_t> PACKAGE_RELAY_SUPPORTED_VERSIONS = {
    RECEIVER_INIT_ANCESTOR_PACKAGES,
};

class TxPackageTracker {
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

    /** Stores relevant information about the peer prior to verack. Upon completion of version
     * handshake, we use this information to decide whether we relay packages with this peer. */
    std::map<NodeId, RegistrationState> registration_states;

    /** Information for each peer we relay packages with. Membership in this map is equivalent to
     * whether or not we relay packages with a peer. */
    std::map<NodeId, PeerInfo> info_per_peer;

public:
    std::vector<uint32_t> GetVersions() { return PACKAGE_RELAY_SUPPORTED_VERSIONS; }

    // We expect this to be called only once
    void ReceivedVersion(NodeId nodeid);
    // Can call this for fRelay
    void ReceivedTxRelayInfo(NodeId nodeid, bool txrelay);
    void ReceivedWtxidRelay(NodeId nodeid);
    void ReceivedSendpackages(NodeId nodeid, uint32_t version);
    // Sent sendpackages messages for each version in PACKAGE_RELAY_SUPPORTED_VERSIONS
    void SentSendpackages(NodeId nodeid);

    // Finalize the registration state.
    bool ReceivedVerack(NodeId nodeid);

    // Tear down all state
    void DisconnectedPeer(NodeId nodeid);
};

#endif // BITCOIN_TX_PKG_RELAY_H
