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
    /** How long to wait before requesting orphan ancpkginfo/parents from an additional peer. */
    static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};

class TxPackageTracker::Impl {
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;

    mutable Mutex m_mutex;

    /** Tracks orphans for which we need to request ancestor information. All hashes stored are
     * wtxids, i.e., the wtxid of the orphan. */
    TxRequestTracker m_orphan_request_tracker GUARDED_BY(m_mutex);

public:
    Impl() = default;

    // Orphanage Wrapper Functions
    bool OrphanageHaveTx(const GenTxid& gtxid) { return m_orphanage.HaveTx(gtxid); }
    CTransactionRef GetTxToReconsider(NodeId peer) { return m_orphanage.GetTxToReconsider(peer); }
    void DisconnectedPeer(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        m_orphan_request_tracker.DisconnectedPeer(nodeid);
        m_orphanage.EraseForPeer(nodeid);
    }
    void BlockConnected(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        const auto wtxids_erased{m_orphanage.EraseForBlock(block)};
        std::set<uint256> block_wtxids;
        for (const CTransactionRef& ptx : block.vtx) {
            block_wtxids.insert(ptx->GetWitnessHash());
        }
        for (const auto& wtxid : wtxids_erased) {
            if (block_wtxids.count(wtxid) == 0) {
                LogPrint(BCLog::TXPACKAGES, "Forgetting orphan request %s, conflicted with block\n", wtxid.ToString());
                m_orphan_request_tracker.ForgetTxHash(wtxid);
            }
        }
        for (const auto& wtxid : block_wtxids) {
            LogPrint(BCLog::TXPACKAGES, "Forgetting orphan request %s, included in a block\n", wtxid.ToString());
            m_orphan_request_tracker.ForgetTxHash(wtxid);
        }
    }
    void LimitOrphans(unsigned int max_orphans) { m_orphanage.LimitOrphans(max_orphans); }
    bool HaveTxToReconsider(NodeId peer) { return m_orphanage.HaveTxToReconsider(peer); }
    size_t OrphanageSize() { return m_orphanage.Size(); }
    void MempoolAcceptedTx(const CTransactionRef& ptx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_orphanage.AddChildrenToWorkSet(*ptx);
        m_orphanage.EraseTx(ptx->GetWitnessHash());
        m_orphan_request_tracker.ForgetTxHash(ptx->GetWitnessHash());
    }
    void MempoolRejectedTx(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        LogPrint(BCLog::TXPACKAGES, "Forgetting orphan request %s, rejected from mempool\n", wtxid.ToString());
        m_orphanage.EraseTx(wtxid);
        m_orphan_request_tracker.ForgetTxHash(wtxid);
    }
    void AddOrphanTx(NodeId nodeid, const uint256& wtxid, const CTransactionRef& tx, bool is_preferred, std::chrono::microseconds reqtime)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        // Skip if we weren't provided the tx and can't find the wtxid in the orphanage.
        if (tx == nullptr && !m_orphanage.HaveTx(GenTxid::Wtxid(wtxid))) return;

        // Even though this stores the orphan wtxid, GenTxid::Txid instead of Wtxid because we will be requesting the parents via txid.
        m_orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Txid(wtxid), is_preferred, reqtime);

        if (tx != nullptr) {
            m_orphanage.AddTx(tx, nodeid);
        } else {
            m_orphanage.AddTx(m_orphanage.GetTx(wtxid), nodeid);
        }
    }
    size_t CountInFlight(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto count{m_orphan_request_tracker.CountInFlight(nodeid)};
        return count;
    }
    size_t Count(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto count{m_orphan_request_tracker.Count(nodeid)};
        return count;
    }

    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        std::vector<std::pair<NodeId, GenTxid>> expired;
        auto tracker_requestable = m_orphan_request_tracker.GetRequestable(nodeid, current_time, &expired);
        for (const auto& entry : expired) {
            LogPrint(BCLog::TXPACKAGES, "Timeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "ancpkginfo" : "orphan parent",
                entry.second.GetHash().ToString(), entry.first);
        }
        std::vector<GenTxid> results;
        for (const auto& gtxid : tracker_requestable) {
            const auto ptx = m_orphanage.GetTx(gtxid.GetHash());
            if (!ptx) {
                // We can't request ancpkginfo and we have no way of knowing what the missing
                // parents are (it could also be that the orphan has already been resolved).
                // Give up.
                m_orphan_request_tracker.ForgetTxHash(gtxid.GetHash());
                LogPrint(BCLog::TXPACKAGES, "Forgetting orphan request %s from peer=%d, tx evicted from orphanage\n", gtxid.GetHash().ToString(), nodeid);
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
            LogPrint(BCLog::TXPACKAGES, "Orphan %s can be requested from peer=%d via parent txid requests\n", gtxid.GetHash().ToString(), nodeid);
            // Mark the orphan as requested
            m_orphan_request_tracker.RequestedTx(nodeid, gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
        }
        return results;
    }
};

TxPackageTracker::TxPackageTracker() : m_impl{std::make_unique<TxPackageTracker::Impl>()} {}
TxPackageTracker::~TxPackageTracker() = default;

bool TxPackageTracker::OrphanageHaveTx(const GenTxid& gtxid) { return m_impl->OrphanageHaveTx(gtxid); }
CTransactionRef TxPackageTracker::GetTxToReconsider(NodeId peer) { return m_impl->GetTxToReconsider(peer); }
void TxPackageTracker::DisconnectedPeer(NodeId peer) { m_impl->DisconnectedPeer(peer); }
void TxPackageTracker::BlockConnected(const CBlock& block) { m_impl->BlockConnected(block); }
void TxPackageTracker::LimitOrphans(unsigned int max_orphans) { m_impl->LimitOrphans(max_orphans); }
bool TxPackageTracker::HaveTxToReconsider(NodeId peer) { return m_impl->HaveTxToReconsider(peer); }
size_t TxPackageTracker::OrphanageSize() { return m_impl->OrphanageSize(); }
void TxPackageTracker::MempoolAcceptedTx(const CTransactionRef& ptx) { return m_impl->MempoolAcceptedTx(ptx); }
void TxPackageTracker::MempoolRejectedTx(const uint256& wtxid) { return m_impl->MempoolRejectedTx(wtxid); }
void TxPackageTracker::AddOrphanTx(NodeId nodeid, const uint256& wtxid, const CTransactionRef& tx, bool is_preferred, std::chrono::microseconds reqtime)
{
    m_impl->AddOrphanTx(nodeid, wtxid, tx, is_preferred, reqtime);
}
size_t TxPackageTracker::CountInFlight(NodeId nodeid) const { return m_impl->CountInFlight(nodeid); }
size_t TxPackageTracker::Count(NodeId nodeid) const { return m_impl->Count(nodeid); }
std::vector<GenTxid> TxPackageTracker::GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time) {
    return m_impl->GetOrphanRequests(nodeid, current_time);
}
} // namespace node
