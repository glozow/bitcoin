// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <node/txdownload_impl.h>

#include <cstdint>
#include <map>
#include <vector>

class TxOrphanage;
class TxRequestTracker;
class CBlockIndex;
enum class ChainstateRole;
namespace node {

class TxDownloadManager {
    const std::unique_ptr<TxDownloadImpl> m_impl;

public:
    explicit TxDownloadManager(const TxDownloadOptions& options) : m_impl{std::make_unique<TxDownloadImpl>(options)} {}

    // Get references to internal data structures. Outside access to these data structures should be
    // temporary and removed later once logic has been moved internally.
    TxOrphanage& GetOrphanageRef() { return m_impl->m_orphanage; }
    TxRequestTracker& GetTxRequestRef() { return m_impl->m_txrequest; }
    CRollingBloomFilter& GetRecentRejectsRef() { return m_impl->m_recent_rejects; }
    CRollingBloomFilter& GetRecentRejectsReconsiderableRef() { return m_impl->m_recent_rejects_reconsiderable; }
    CRollingBloomFilter& GetRecentConfirmedRef() { return m_impl->m_recent_confirmed_transactions; }

    // Responses to chain events. TxDownloadManager is not an actual client of ValidationInterface, these are called through PeerManager.
    void UpdatedBlockTipSync() { return m_impl->UpdatedBlockTipSync(); }
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock) {
        return m_impl->BlockConnected(pblock);
    }
    void BlockDisconnected() {
        return m_impl->BlockDisconnected();
    }

    /** Check whether we already have this gtxid in:
     *  - mempool
     *  - orphanage
     *  - m_recent_rejects
     *  - m_recent_rejects_reconsiderable (if include_reconsiderable = true)
     *  - m_recent_confirmed_transactions
     *  */
    bool AlreadyHaveTx(const GenTxid& gtxid, bool include_reconsiderable) { return m_impl->AlreadyHaveTx(gtxid, include_reconsiderable); }

    /** Creates a new PeerInfo. Saves the connection info to calculate tx announcement delays later. */
    void ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info) { m_impl->ConnectedPeer(nodeid, info); }
    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId nodeid) { m_impl->DisconnectedPeer(nodeid); }

    /** New inv has been received. May be added as a candidate to txrequest. */
    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
        { return m_impl->ReceivedTxInv(peer, gtxid, now); }

    /** Get getdata requests to send. */
    std::vector<GenTxid> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time) {
        return m_impl->GetRequestsToSend(nodeid, current_time);
    }

    /** Should be called when a notfound for a tx has been received. */
    void ReceivedNotFound(NodeId nodeid, const std::vector<uint256>& txhashes) { m_impl->ReceivedNotFound(nodeid, txhashes); }

    /** Respond to successful transaction submission to mempool */
    void MempoolAcceptedTx(const CTransactionRef& tx) { m_impl->MempoolAcceptedTx(tx); }
    bool MempoolRejectedTx(const CTransactionRef& ptx, const TxValidationState& state) {
        return m_impl->MempoolRejectedTx(ptx, state);
    }
    void MempoolRejectedPackage(const Package& package) { m_impl->MempoolRejectedPackage(package); }

    /** Look for a child of this transaction in the orphanage to form a 1-parent-1-child package,
     * skipping any combinations that have already been tried. Return the resulting package along with
     * the senders of its respective transactions, or std::nullopt if no package is found. */
    std::optional<PackageToValidate> Find1P1CPackage(const CTransactionRef& ptx, NodeId nodeid) {
        return m_impl->Find1P1CPackage(ptx, nodeid);
    }
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
