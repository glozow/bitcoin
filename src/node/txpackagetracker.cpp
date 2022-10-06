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
    /** How long to wait before requesting orphan ancpkginfo/parents from an additional peer.
     * Same as GETDATA_TX_INTERVAL. */
    static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};

class TxPackageTracker::Impl {
    /** Whether package relay is enabled. When false, the tracker does basic orphan handling. */
    const bool m_enable_package_relay;
    /** Maximum number of transactions in orphanage. */
    const unsigned int m_max_orphan_count;

    TxOrphanage m_orphanage;

    mutable Mutex m_mutex;

    /** Tracks orphans for which we need to request ancestor information. All hashes stored are
     * wtxids, i.e., the wtxid of the orphan. However, the is_wtxid field is used to indicate
     * whether we would request the ancestor information by wtxid (via package relay) or by txid
     * (via prevouts of the missing inputs). */
    TxRequestTracker orphan_request_tracker GUARDED_BY(m_mutex);

public:
    Impl(const TxPackageTracker::Options& opts) :
        m_enable_package_relay{opts.enable_package_relay},
        m_max_orphan_count{opts.max_orphan_count}
    {}
    /** (Batch) Update transactions for which we have made "final" decisions: transactions that have
     * confirmed in a block, conflicted due to a block, or added to the mempool already.
     * Should be called on new block: valid=block transactions, invalid=conflicts.
     * Should be called when tx is added to mempool.
     * Should not be called when a tx fails validation.
     * */
    void FinalizeTransactions(const std::set<uint256>& valid, const std::set<uint256>& invalid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        for (const auto& wtxid : valid) {
            orphan_request_tracker.ForgetTxHash(wtxid);
        }
        for (const auto& wtxid : invalid) {
            orphan_request_tracker.ForgetTxHash(wtxid);
        }
    }
    void BlockConnected(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        const auto wtxids_erased{m_orphanage.EraseForBlock(block)};
        std::set<uint256> block_wtxids;
        std::set<uint256> conflicted_wtxids;
        for (const CTransactionRef& ptx : block.vtx) {
            block_wtxids.insert(ptx->GetWitnessHash());
        }
        for (const auto& wtxid : wtxids_erased) {
            if (block_wtxids.count(wtxid) == 0) {
                conflicted_wtxids.insert(wtxid);
            }
        }
        FinalizeTransactions(block_wtxids, conflicted_wtxids);
    }
    void DisconnectedPeer(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        orphan_request_tracker.DisconnectedPeer(nodeid);
        m_orphanage.EraseForPeer(nodeid);
    }
    bool OrphanageHaveTx(const GenTxid& gtxid) const { return m_orphanage.HaveTx(gtxid); }
    void AddOrphanTx(NodeId nodeid, const CTransactionRef& tx, bool is_preferred, std::chrono::microseconds reqtime)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        // Even though this stores the orphan wtxid, is_wtxid=false because we will be requesting the parents via txid.
        orphan_request_tracker.ReceivedInv(nodeid, GenTxid::Txid(tx->GetWitnessHash()), is_preferred, reqtime);
        if (m_orphanage.AddTx(tx, nodeid)) {
            // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789)
            m_orphanage.LimitOrphans(m_max_orphan_count);
        }
    }
    void TransactionAccepted(const CTransactionRef& tx)
    {
        m_orphanage.AddChildrenToWorkSet(*tx);
        m_orphanage.EraseTx(tx->GetWitnessHash());
        FinalizeTransactions({tx->GetWitnessHash()}, {});
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
    size_t OrphanageSize()
    {
        m_orphanage.LimitOrphans(m_max_orphan_count);
        return m_orphanage.Size();
    }
    size_t CountInFlight(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto count{orphan_request_tracker.CountInFlight(nodeid)};
        return count;
    }
    size_t Count(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        auto count{orphan_request_tracker.Count(nodeid)};
        return count;
    }

    std::vector<GenTxid> GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(m_mutex);
        LOCK(m_mutex);
        std::vector<std::pair<NodeId, GenTxid>> expired;
        auto tracker_requestable = orphan_request_tracker.GetRequestable(nodeid, current_time, &expired);
        for (const auto& entry : expired) {
            LogPrint(BCLog::TXPACKAGES, "\nTimeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "ancpkginfo" : "orphan parent",
                entry.second.GetHash().ToString(), entry.first);
        }
        std::vector<GenTxid> results;
        for (const auto& gtxid : tracker_requestable) {
            LogPrint(BCLog::TXPACKAGES, "\nResolving orphan %s, requesting by txids of parents from peer=%d\n", gtxid.GetHash().ToString(), nodeid);
            const auto ptx = m_orphanage.GetTx(gtxid.GetHash());
            if (!ptx) {
                // We can't request ancpkginfo and we have no way of knowing what the missing
                // parents are (it could also be that the orphan has already been resolved).
                // Give up.
                orphan_request_tracker.ForgetTxHash(gtxid.GetHash());
                LogPrint(BCLog::TXPACKAGES, "\nForgetting orphan %s from peer=%d\n", gtxid.GetHash().ToString(), nodeid);
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
            // Mark the orphan as requested
            orphan_request_tracker.RequestedTx(nodeid, gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
        }
        if (!results.empty()) LogPrint(BCLog::TXPACKAGES, "\nRequesting %u items from peer=%d\n", results.size(), nodeid);
        return results;
    }
};

TxPackageTracker::TxPackageTracker(const TxPackageTracker::Options& opts) : m_impl{std::make_unique<TxPackageTracker::Impl>(opts)} {}
TxPackageTracker::~TxPackageTracker() = default;

void TxPackageTracker::BlockConnected(const CBlock& block) { m_impl->BlockConnected(block); }
/** Peer has disconnected, tear down state. */
void TxPackageTracker::DisconnectedPeer(NodeId nodeid) { m_impl->DisconnectedPeer(nodeid); }
/** Returns whether a tx is present in the orphanage. */
bool TxPackageTracker::OrphanageHaveTx(const GenTxid& gtxid) const { return m_impl->OrphanageHaveTx(gtxid); }
void TxPackageTracker::AddOrphanTx(NodeId nodeid, const CTransactionRef& tx, bool is_preferred, std::chrono::microseconds reqtime)
{
    m_impl->AddOrphanTx(nodeid, tx, is_preferred, reqtime);
}
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
size_t TxPackageTracker::Count(NodeId nodeid) const { return m_impl->Count(nodeid); }
size_t TxPackageTracker::CountInFlight(NodeId nodeid) const { return m_impl->CountInFlight(nodeid); }
std::vector<GenTxid> TxPackageTracker::GetOrphanRequests(NodeId nodeid, std::chrono::microseconds current_time) {
    return m_impl->GetOrphanRequests(nodeid, current_time);
}
} // namespace node
