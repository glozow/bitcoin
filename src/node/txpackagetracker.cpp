// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackagetracker.h>

#include <txorphanage.h>

namespace node {
class TxPackageTracker::Impl {
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;
public:
    Impl() = default;

    // Orphanage Wrapper Functions
    bool OrphanageAddTx(const CTransactionRef& tx, NodeId peer) { return m_orphanage.AddTx(tx, peer); }
    bool OrphanageHaveTx(const GenTxid& gtxid) { return m_orphanage.HaveTx(gtxid); }
    CTransactionRef GetTxToReconsider(NodeId peer) { return m_orphanage.GetTxToReconsider(peer); }
    void DisconnectedPeer(NodeId peer) {
        m_orphanage.EraseForPeer(peer);
    }
    void BlockConnected(const CBlock& block) { m_orphanage.EraseForBlock(block); }
    void LimitOrphans(unsigned int max_orphans) { m_orphanage.LimitOrphans(max_orphans); }
    bool HaveTxToReconsider(NodeId peer) { return m_orphanage.HaveTxToReconsider(peer); }
    size_t OrphanageSize() { return m_orphanage.Size(); }
    void MempoolAcceptedTx(const CTransactionRef& ptx)
    {
        m_orphanage.AddChildrenToWorkSet(*ptx);
        m_orphanage.EraseTx(ptx->GetWitnessHash());
    }
    void MempoolRejectedTx(const uint256& wtxid)
    {
        m_orphanage.EraseTx(wtxid);
    }
};

TxPackageTracker::TxPackageTracker() : m_impl{std::make_unique<TxPackageTracker::Impl>()} {}
TxPackageTracker::~TxPackageTracker() = default;

bool TxPackageTracker::OrphanageAddTx(const CTransactionRef& tx, NodeId peer) { return m_impl->OrphanageAddTx(tx, peer); }
bool TxPackageTracker::OrphanageHaveTx(const GenTxid& gtxid) { return m_impl->OrphanageHaveTx(gtxid); }
CTransactionRef TxPackageTracker::GetTxToReconsider(NodeId peer) { return m_impl->GetTxToReconsider(peer); }
void TxPackageTracker::DisconnectedPeer(NodeId peer) { m_impl->DisconnectedPeer(peer); }
void TxPackageTracker::BlockConnected(const CBlock& block) { m_impl->BlockConnected(block); }
void TxPackageTracker::LimitOrphans(unsigned int max_orphans) { m_impl->LimitOrphans(max_orphans); }
bool TxPackageTracker::HaveTxToReconsider(NodeId peer) { return m_impl->HaveTxToReconsider(peer); }
size_t TxPackageTracker::OrphanageSize() { return m_impl->OrphanageSize(); }
void TxPackageTracker::MempoolAcceptedTx(const CTransactionRef& ptx) { return m_impl->MempoolAcceptedTx(ptx); }
void TxPackageTracker::MempoolRejectedTx(const uint256& wtxid) { return m_impl->MempoolRejectedTx(wtxid); }
} // namespace node
