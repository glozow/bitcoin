// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackagetracker.h>

#include <txorphanage.h>
#include <txrequest.h>

namespace node {
class TxPackageTracker::Impl {
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;
    /** Tracks candidates for requesting and downloading transaction data. */
    TxRequestTracker m_txrequest;
public:
    Impl() = default;

    // Orphanage Wrapper Functions
    bool OrphanageAddTx(const CTransactionRef& tx, NodeId peer) { return m_orphanage.AddTx(tx, peer); }
    bool OrphanageHaveTx(const GenTxid& gtxid) { return m_orphanage.HaveTx(gtxid); }
    CTransactionRef OrphanageGetTxToReconsider(NodeId peer) { return m_orphanage.GetTxToReconsider(peer); }
    int OrphanageEraseTx(const uint256& wtxid) { return m_orphanage.EraseTx(wtxid); }
    void OrphanageEraseForPeer(NodeId peer) {
        m_orphanage.EraseForPeer(peer);
    }
    void OrphanageEraseForBlock(const CBlock& block) {
        m_orphanage.EraseForBlock(block);
    }
    void OrphanageLimitOrphans(unsigned int max_orphans) { m_orphanage.LimitOrphans(max_orphans); }
    void OrphanageAddChildrenToWorkSet(const CTransaction& tx) { m_orphanage.AddChildrenToWorkSet(tx); }
    bool OrphanageHaveTxToReconsider(NodeId peer) { return m_orphanage.HaveTxToReconsider(peer); }
    size_t OrphanageSize() { return m_orphanage.Size(); }
    void TxRequestReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred, std::chrono::microseconds reqtime)
    {
        m_txrequest.ReceivedInv(peer, gtxid, preferred, reqtime);
    }
    void TxRequestDisconnectedPeer(NodeId peer)
    {
        m_txrequest.DisconnectedPeer(peer);
    }

    void TxRequestForgetTxHash(const uint256& txhash)
    {
        m_txrequest.ForgetTxHash(txhash);
    }

    std::vector<GenTxid> TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
        std::vector<std::pair<NodeId, GenTxid>>* expired)
    {
        return m_txrequest.GetRequestable(peer, now, expired);
    }

    void TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
    {
        m_txrequest.RequestedTx(peer, txhash, expiry);
    }

    void TxRequestReceivedResponse(NodeId peer, const uint256& txhash)
    {
        m_txrequest.ReceivedResponse(peer, txhash);
    }

    /** Count how many REQUESTED announcements a peer has. */
    size_t TxRequestCountInFlight(NodeId peer) const
    {
        return m_txrequest.CountInFlight(peer);
    }

    /** Count how many CANDIDATE announcements a peer has. */
    size_t TxRequestCountCandidates(NodeId peer) const
    {
        return m_txrequest.CountCandidates(peer);
    }

    /** Count how many announcements a peer has (REQUESTED, CANDIDATE, and COMPLETED combined). */
    size_t TxRequestCount(NodeId peer) const
    {
        return m_txrequest.Count(peer);
    }

    /** Count how many announcements are being tracked in total across all peers and transaction hashes. */
    size_t TxRequestSize() const
    {
        return m_txrequest.Size();
    }
};

TxPackageTracker::TxPackageTracker() : m_impl{std::make_unique<TxPackageTracker::Impl>()} {}
TxPackageTracker::~TxPackageTracker() = default;

bool TxPackageTracker::OrphanageAddTx(const CTransactionRef& tx, NodeId peer) { return m_impl->OrphanageAddTx(tx, peer); }
bool TxPackageTracker::OrphanageHaveTx(const GenTxid& gtxid) { return m_impl->OrphanageHaveTx(gtxid); }
CTransactionRef TxPackageTracker::OrphanageGetTxToReconsider(NodeId peer) { return m_impl->OrphanageGetTxToReconsider(peer); }
int TxPackageTracker::OrphanageEraseTx(const uint256& txid) { return m_impl->OrphanageEraseTx(txid); }
void TxPackageTracker::OrphanageEraseForPeer(NodeId peer) { m_impl->OrphanageEraseForPeer(peer); }
void TxPackageTracker::OrphanageEraseForBlock(const CBlock& block) { m_impl->OrphanageEraseForBlock(block); }
void TxPackageTracker::OrphanageLimitOrphans(unsigned int max_orphans) { m_impl->OrphanageLimitOrphans(max_orphans); }
void TxPackageTracker::OrphanageAddChildrenToWorkSet(const CTransaction& tx) { m_impl->OrphanageAddChildrenToWorkSet(tx); }
bool TxPackageTracker::OrphanageHaveTxToReconsider(NodeId peer) { return m_impl->OrphanageHaveTxToReconsider(peer); }
size_t TxPackageTracker::OrphanageSize() { return m_impl->OrphanageSize(); }
void TxPackageTracker::TxRequestReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred, std::chrono::microseconds reqtime)
    { return m_impl->TxRequestReceivedInv(peer, gtxid, preferred, reqtime); }
void TxPackageTracker::TxRequestDisconnectedPeer(NodeId peer) { m_impl->TxRequestDisconnectedPeer(peer); }
void TxPackageTracker::TxRequestForgetTxHash(const uint256& txhash) { m_impl->TxRequestForgetTxHash(txhash); }
std::vector<GenTxid> TxPackageTracker::TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
    std::vector<std::pair<NodeId, GenTxid>>* expired) { return m_impl->TxRequestGetRequestable(peer, now, expired); }
void TxPackageTracker::TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
    { m_impl->TxRequestRequestedTx(peer, txhash, expiry); }
void TxPackageTracker::TxRequestReceivedResponse(NodeId peer, const uint256& txhash) { m_impl->TxRequestReceivedResponse(peer, txhash); }
size_t TxPackageTracker::TxRequestCountInFlight(NodeId peer) const { return m_impl->TxRequestCountInFlight(peer); }
size_t TxPackageTracker::TxRequestCountCandidates(NodeId peer) const { return m_impl->TxRequestCountCandidates(peer); }
size_t TxPackageTracker::TxRequestCount(NodeId peer) const { return m_impl->TxRequestCount(peer); }
size_t TxPackageTracker::TxRequestSize() const { return m_impl->TxRequestSize(); }
} // namespace node
