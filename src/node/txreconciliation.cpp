// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>

#include <unordered_map>
#include <variant>

namespace {

/** Static salt component used to compute short txids for sketch construction, see BIP-330. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";
/**
 * Salt (specified by BIP-330) constructed from contributions from both peers. It is used
 * to compute transaction short IDs, which are then used to construct a sketch representing a set
 * of transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t salt1, uint64_t salt2)
{
    // According to BIP-330, salts should be combined in ascending order.
    static auto RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);
    return (RECON_SALT_HASHER << std::min(salt1, salt2) << std::max(salt1, salt2)).GetSHA256();
}

/**
 * Keeps track of reconciliation-related per-peer state.
 */
class ReconciliationState
{
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl
{
    mutable Mutex m_mutex;

    /**
     * Keeps track of reconciliation states of eligible peers.
     * For pre-registered peers, the locally generated salt is stored.
     * For registered peers, the locally generated salt is forgotten, and the state (including
     * "full" salt) is stored instead.
     */
    std::unordered_map<NodeId, std::variant<uint64_t, ReconciliationState>> m_states GUARDED_BY(m_mutex);

public:
    // Local protocol version
    // Made public to supress -Wunused-private-field. Should be made private when becomes used.
    const uint32_t m_recon_version;

    explicit Impl(uint32_t recon_version) : m_recon_version(recon_version) {}

    uint64_t PreRegisterPeer(NodeId peer_id)
    {
        // We do not support reconciliation salt/version updates.
        LOCK(m_mutex);
        assert(m_states.find(peer_id) == m_states.end());

        LogPrint(BCLog::TXRECON, "Pre-register peer=%d.\n", peer_id);
        uint64_t local_recon_salt{GetRand(UINT64_MAX)};

        // We do this exactly once per peer (which are unique by NodeId, see GetNewNodeId) so it's
        // safe to assume we don't have this record yet.
        assert(m_states.emplace(peer_id, local_recon_salt).second);
        return local_recon_salt;
    }

    void ForgetPeer(NodeId peer_id)
    {
        LOCK(m_mutex);
        if (m_states.erase(peer_id)) {
            LogPrint(BCLog::TXRECON, "Forget reconciliation state of peer=%d.\n", peer_id);
        }
    }
};

TxReconciliationTracker::TxReconciliationTracker(uint32_t recon_version) : m_impl{std::make_unique<TxReconciliationTracker::Impl>(recon_version)} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

uint64_t TxReconciliationTracker::PreRegisterPeer(NodeId peer_id)
{
    return m_impl->PreRegisterPeer(peer_id);
}

void TxReconciliationTracker::ForgetPeer(NodeId peer_id)
{
    m_impl->ForgetPeer(peer_id);
}
