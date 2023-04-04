// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackagetracker.h>

#include <txorphanage.h>

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

public:
    Impl(const TxPackageTracker::Options& opts) :
        m_enable_package_relay{opts.enable_package_relay},
        m_max_orphan_count{opts.max_orphan_count}
    {}
    void BlockConnected(const CBlock& block)
    {
        auto conflicted_wtxids{m_orphanage.EraseForBlock(block)};
    }
    void DisconnectedPeer(NodeId nodeid)
    {
        m_orphanage.EraseForPeer(nodeid);
    }
    bool OrphanageHaveTx(const GenTxid& gtxid) const { return m_orphanage.HaveTx(gtxid); }
    bool AddOrphanTx(const CTransactionRef& tx, NodeId peer)
    {
        const bool added = m_orphanage.AddTx(tx, peer);
        // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789)
        if (added) m_orphanage.LimitOrphans(m_max_orphan_count);
        return added && m_orphanage.HaveTx(GenTxid::Wtxid(tx->GetWitnessHash()));
    }
    void TransactionAccepted(const CTransactionRef& tx)
    {
        m_orphanage.AddChildrenToWorkSet(*tx);
        m_orphanage.EraseTx(tx->GetWitnessHash());
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
    size_t OrphanageSize() {
        m_orphanage.LimitOrphans(m_max_orphan_count);
        return m_orphanage.Size();
    }
};

TxPackageTracker::TxPackageTracker(const TxPackageTracker::Options& opts) : m_impl{std::make_unique<TxPackageTracker::Impl>(opts)} {}
TxPackageTracker::~TxPackageTracker() = default;

void TxPackageTracker::BlockConnected(const CBlock& block) { m_impl->BlockConnected(block); }
/** Peer has disconnected, tear down state. */
void TxPackageTracker::DisconnectedPeer(NodeId nodeid) { m_impl->DisconnectedPeer(nodeid); }
/** Returns whether a tx is present in the orphanage. */
bool TxPackageTracker::OrphanageHaveTx(const GenTxid& gtxid) const { return m_impl->OrphanageHaveTx(gtxid); }
bool TxPackageTracker::AddOrphanTx(const CTransactionRef& tx, NodeId peer) { return m_impl->AddOrphanTx(tx, peer); }
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

} // namespace node
