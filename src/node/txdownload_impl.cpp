// Copyright (c) 2023
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownload_impl.h>

namespace node {
/** How long to wait before requesting orphan ancpkginfo/parents from an additional peer. */
static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};

TxOrphanage& TxDownloadImpl::GetOrphanageRef() EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex) { return m_orphanage; }
TxRequestTracker& TxDownloadImpl::GetTxRequestRef() EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex) { return m_txrequest; }

void TxDownloadImpl::ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    Assume(m_peer_info.count(nodeid) == 0);
    m_peer_info.emplace(nodeid, PeerInfo(info));
    if (info.m_wtxid_relay) m_num_wtxid_peers += 1;
}
void TxDownloadImpl::DisconnectedPeer(NodeId nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    m_orphanage.EraseForPeer(nodeid);
    m_txrequest.DisconnectedPeer(nodeid);
    m_orphan_resolution_tracker.DisconnectedPeer(nodeid);
}

void TxDownloadImpl::BlockConnected(const CBlock& block, const uint256& tiphash)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    const auto erased_wtxids = m_orphanage.EraseForBlock(block);
    for (const auto& ptx : block.vtx) {
        m_txrequest.ForgetTxHash(ptx->GetHash());
        m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
        m_recent_confirmed_transactions.insert(ptx->GetHash());
        // All hashes in m_orphan_resolution_tracker are wtxids.
        m_orphan_resolution_tracker.ForgetTxHash(ptx->GetWitnessHash());
        if (ptx->GetHash() != ptx->GetWitnessHash()) {
            m_recent_confirmed_transactions.insert(ptx->GetWitnessHash());
        }
    }

    // Stop trying to resolve orphans that were conflicted by the block.
    for (const auto& wtxid : erased_wtxids) {
        m_orphan_resolution_tracker.ForgetTxHash(wtxid);
    }

    if (tiphash != hashRecentRejectsChainTip) {
        // If the chain tip has changed previously rejected transactions
        // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
        // or a double-spend. Reset the rejects filter and give those
        // txs a second chance.
        hashRecentRejectsChainTip = tiphash;
        m_recent_rejects.reset();
    }
}

void TxDownloadImpl::BlockDisconnected()
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    // To avoid relay problems with transactions that were previously
    // confirmed, clear our filter of recently confirmed transactions whenever
    // there's a reorg.
    // This means that in a 1-block reorg (where 1 block is disconnected and
    // then another block reconnected), our filter will drop to having only one
    // block's worth of transactions in it, but that should be fine, since
    // presumably the most common case of relaying a confirmed transaction
    // should be just after a new block containing it is found.
    m_recent_confirmed_transactions.reset();
}

void TxDownloadImpl::MempoolAcceptedTx(const CTransactionRef& tx)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    m_orphanage.AddChildrenToWorkSet(*tx);
    // As this version of the transaction was acceptable, we can forget about any requests for it.
    // No-op if the tx is not in txrequest.
    m_txrequest.ForgetTxHash(tx->GetHash());
    m_txrequest.ForgetTxHash(tx->GetWitnessHash());
    // If it came from the orphanage, remove it. No-op if the tx is not in txorphanage.
    m_orphanage.EraseTx(tx->GetWitnessHash());
    m_orphan_resolution_tracker.ForgetTxHash(tx->GetWitnessHash());
}

bool TxDownloadImpl::MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    switch (result) {
    case TxValidationResult::TX_RESULT_UNSET:
    case TxValidationResult::TX_NO_MEMPOOL:
    {
        // This function should only be called when a transaction fails validation.
        Assume(false);
        return false;
    }
    case TxValidationResult::TX_WITNESS_STRIPPED:
    {
        // Do not add txids of witness transactions or witness-stripped
        // transactions to the filter, as they can have been malleated;
        // adding such txids to the reject filter would potentially
        // interfere with relay of valid transactions from peers that
        // do not support wtxid-based relay. See
        // https://github.com/bitcoin/bitcoin/issues/8279 for details.
        // We can remove this restriction (and always add wtxids to
        // the filter even for witness stripped transactions) once
        // wtxid-based relay is broadly deployed.
        // See also comments in https://github.com/bitcoin/bitcoin/pull/18044#discussion_r443419034
        // for concerns around weakening security of unupgraded nodes
        // if we start doing this too early.
        return false;
    }
    case TxValidationResult::TX_MISSING_INPUTS:
    {
        if (std::any_of(tx->vin.cbegin(), tx->vin.cend(),
            [&](const auto& input) EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
            { return m_recent_rejects.contains(input.prevout.hash); })) {
            LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s (wtxid=%s)\n",
                     tx->GetHash().ToString(),
                     tx->GetWitnessHash().ToString());
            // We will continue to reject this tx since it has rejected
            // parents so avoid re-requesting it from other peers.
            // Here we add both the txid and the wtxid, as we know that
            // regardless of what witness is provided, we will not accept
            // this, so we don't need to allow for redownload of this txid
            // from any of our non-wtxidrelay peers.
            m_recent_rejects.insert(tx->GetHash());
            m_recent_rejects.insert(tx->GetWitnessHash());
            m_txrequest.ForgetTxHash(tx->GetHash());
            m_txrequest.ForgetTxHash(tx->GetWitnessHash());
            return false;
        }
        return true;
    }
    case TxValidationResult::TX_INPUTS_NOT_STANDARD:
    {
        // If the transaction failed for TX_INPUTS_NOT_STANDARD,
        // then we know that the witness was irrelevant to the policy
        // failure, since this check depends only on the txid
        // (the scriptPubKey being spent is covered by the txid).
        // Add the txid to the reject filter to prevent repeated
        // processing of this transaction in the event that child
        // transactions are later received (resulting in
        // parent-fetching by txid via the orphan-handling logic).
        if (tx->GetWitnessHash() != tx->GetHash()) {
            m_recent_rejects.insert(tx->GetHash());
            m_txrequest.ForgetTxHash(tx->GetHash());
        }
        break;
    }
    case TxValidationResult::TX_UNKNOWN:
    {
        // Don't cache failure. This tx could be valid.
        break;
    }
    case TxValidationResult::TX_SINGLE_FAILURE:
    case TxValidationResult::TX_CONSENSUS:
    case TxValidationResult::TX_RECENT_CONSENSUS_CHANGE:
    case TxValidationResult::TX_NOT_STANDARD:
    case TxValidationResult::TX_PREMATURE_SPEND:
    case TxValidationResult::TX_WITNESS_MUTATED:
    case TxValidationResult::TX_CONFLICT:
    case TxValidationResult::TX_MEMPOOL_POLICY:
    {
        // We can add the wtxid of this transaction to our reject filter.
        m_recent_rejects.insert(tx->GetWitnessHash());
        break;
    }
    }
    // Forget requests for this wtxid, but not for the txid, as another version of
    // transaction may be valid. No-op if the tx is not in txrequest.
    m_txrequest.ForgetTxHash(tx->GetWitnessHash());
    // If it came from the orphanage, remove it (this doesn't happen if the transaction was missing
    // inputs). No-op if the tx is not in the orphanage.
    m_orphanage.EraseTx(tx->GetWitnessHash());
    m_orphan_resolution_tracker.ForgetTxHash(tx->GetWitnessHash());
    return false;
}

bool TxDownloadImpl::AlreadyHaveTxLocked(const GenTxid& gtxid) const
    EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
{
    const uint256& hash = gtxid.GetHash();

    if (m_orphanage.HaveTx(gtxid)) return true;

    if (m_recent_confirmed_transactions.contains(hash)) return true;

    return m_recent_rejects.contains(hash) || m_opts.m_mempool_ref.exists(gtxid);
}
bool TxDownloadImpl::AlreadyHaveTx(const GenTxid& gtxid) const
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    return AlreadyHaveTxLocked(gtxid);
}

void TxDownloadImpl::AddTxAnnouncement(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
    EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
{
    if (!Assume(m_peer_info.count(peer) > 0)) return;
    if (m_orphanage.HaveTx(gtxid)) AddOrphanAnnouncer(peer, gtxid.GetHash(), now);
    if (AlreadyHaveTxLocked(gtxid)) return;
    const auto& info = m_peer_info.at(peer).m_connection_info;
    if (!info.m_relay_permissions && m_txrequest.Count(peer) >= MAX_PEER_TX_ANNOUNCEMENTS) {
        // Too many queued announcements for this peer
        return;
    }
    // Decide the TxRequestTracker parameters for this announcement:
    // - "preferred": if fPreferredDownload is set (= outbound, or NetPermissionFlags::NoBan permission)
    // - "reqtime": current time plus delays for:
    //   - NONPREF_PEER_TX_DELAY for announcements from non-preferred connections
    //   - TXID_RELAY_DELAY for txid announcements while wtxid peers are available
    //   - OVERLOADED_PEER_TX_DELAY for announcements from peers which have at least
    //     MAX_PEER_TX_REQUEST_IN_FLIGHT requests in flight (and don't have NetPermissionFlags::Relay).
    auto delay{0us};
    if (!info.m_preferred) delay += NONPREF_PEER_TX_DELAY;
    if (!gtxid.IsWtxid() && m_num_wtxid_peers > 0) delay += TXID_RELAY_DELAY;
    const bool overloaded = !info.m_relay_permissions && m_txrequest.CountInFlight(peer) >= MAX_PEER_TX_REQUEST_IN_FLIGHT;
    if (overloaded) delay += OVERLOADED_PEER_TX_DELAY;

    m_txrequest.ReceivedInv(peer, gtxid, info.m_preferred, now + delay);
}

void TxDownloadImpl::ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    AddTxAnnouncement(peer, gtxid, now);
}

std::vector<GenTxid> TxDownloadImpl::GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    // First process orphan resolution so that the tx requests can be sent asap
    std::vector<std::pair<NodeId, GenTxid>> expired_orphan_resolution;
    const auto orphans_ready = m_orphan_resolution_tracker.GetRequestable(nodeid, current_time, &expired_orphan_resolution);
    // Expire orphan resolution attempts
    for (const auto& [nodeid, orphan_gtxid] : expired_orphan_resolution) {
        LogPrintf("timeout of in-flight orphan resolution %s for peer=%d\n", orphan_gtxid.GetHash().ToString(), nodeid);
        // All txhashes in m_orphan_resolution_tracker are wtxids.
        Assume(orphan_gtxid.IsWtxid());
        m_orphanage.EraseOrphanOfPeer(orphan_gtxid.GetHash(), nodeid);
    }
    for (const auto& orphan_gtxid : orphans_ready) {
        Assume(orphan_gtxid.IsWtxid());
        const auto parent_txids{m_orphanage.GetParentTxids(orphan_gtxid.GetHash())};
        if (parent_txids.has_value()) {
            if (!Assume(m_peer_info.count(nodeid) > 0)) continue;
            const auto& info = m_peer_info.at(nodeid).m_connection_info;
            for (const auto& txid : *parent_txids) {
                // Schedule with no delay. It should be requested immediately
                // unless there is already a request out for this transaction.
                m_txrequest.ReceivedInv(nodeid, GenTxid::Txid(txid), info.m_preferred, current_time);
                LogPrint(BCLog::TXPACKAGES, "scheduled parent request %s from peer=%d for orphan %s\n",
                         txid.ToString(), nodeid, orphan_gtxid.GetHash().ToString());
            }
            m_orphan_resolution_tracker.RequestedTx(nodeid, orphan_gtxid.GetHash(),
                                                    current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
        } else {
            LogPrint(BCLog::TXPACKAGES, "couldn't find parent txids to resolve orphan %s with peer=%d\n",
                     nodeid, orphan_gtxid.GetHash().ToString());
            m_orphan_resolution_tracker.ForgetTxHash(orphan_gtxid.GetHash());
        }
    }

    // Now process txrequest
    std::vector<GenTxid> requests;
    std::vector<std::pair<NodeId, GenTxid>> expired;
    auto requestable = m_txrequest.GetRequestable(nodeid, current_time, &expired);
    for (const auto& entry : expired) {
        LogPrint(BCLog::NET, "timeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "wtx" : "tx",
            entry.second.GetHash().ToString(), entry.first);
    }
    for (const GenTxid& gtxid : requestable) {
        if (!AlreadyHaveTxLocked(gtxid)) {
            LogPrint(BCLog::NET, "Requesting %s %s peer=%d\n", gtxid.IsWtxid() ? "wtx" : "tx",
                gtxid.GetHash().ToString(), nodeid);
            requests.emplace_back(gtxid);
            m_txrequest.RequestedTx(nodeid, gtxid.GetHash(), current_time + GETDATA_TX_INTERVAL);
        } else {
            // We have already seen this transaction, no need to download. This is just a belt-and-suspenders, as
            // this should already be called whenever a transaction becomes AlreadyHaveTx().
            m_txrequest.ForgetTxHash(gtxid.GetHash());
        }
    }
    return requests;
}

bool TxDownloadImpl::ReceivedTx(NodeId nodeid, const CTransactionRef& ptx)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    m_txrequest.ReceivedResponse(nodeid, ptx->GetHash());
    if (ptx->HasWitness()) m_txrequest.ReceivedResponse(nodeid, ptx->GetWitnessHash());
    return AlreadyHaveTxLocked(GenTxid::Wtxid(ptx->GetWitnessHash()));
}

void TxDownloadImpl::ReceivedNotFound(NodeId nodeid, const std::vector<uint256>& txhashes)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    for (const auto& txhash: txhashes) {
        // If we receive a NOTFOUND message for a tx we requested, mark the announcement for it as
        // completed in TxRequestTracker.
        m_txrequest.ReceivedResponse(nodeid, txhash);
    }
}

void TxDownloadImpl::AddOrphanAnnouncer(NodeId nodeid, const uint256& orphan_wtxid, std::chrono::microseconds now)
{
    if (!Assume(m_peer_info.count(nodeid) > 0)) return;
    const auto& info = m_peer_info.at(nodeid).m_connection_info;
    // This mirrors the delaying and dropping behavior in ReceivedTxInv in order to preserve
    // existing behavior.
    // TODO: add delays and limits based on the amount of orphan resolution we are already doing
    // with this peer, how much they are using the orphanage, etc.
    if (!info.m_relay_permissions && m_orphan_resolution_tracker.Count(nodeid) >= MAX_PEER_TX_ANNOUNCEMENTS) {
        // Too many queued orphan resolutions with this peer
        return;
    }

    auto delay{0us};
    if (!info.m_preferred) delay += NONPREF_PEER_TX_DELAY;
    // The orphan wtxid is used, but resolution entails requesting the parents by txid.
    if (m_num_wtxid_peers > 0) delay += TXID_RELAY_DELAY;
    const bool overloaded = !info.m_relay_permissions && m_txrequest.CountInFlight(nodeid) >= MAX_PEER_TX_REQUEST_IN_FLIGHT;
    if (overloaded) delay += OVERLOADED_PEER_TX_DELAY;

    LogPrint(BCLog::TXPACKAGES, "adding peer=%d as a candidate for resolving orphan %s\n", nodeid, orphan_wtxid.ToString());
    m_orphanage.AddAnnouncer(orphan_wtxid, nodeid);
    m_orphan_resolution_tracker.ReceivedInv(nodeid, GenTxid::Wtxid(orphan_wtxid), info.m_preferred, now + delay);
}

std::pair<bool, std::vector<uint256>> TxDownloadImpl::NewOrphanTx(const CTransactionRef& tx,
    NodeId nodeid, std::chrono::microseconds current_time)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    const auto& wtxid = tx->GetWitnessHash();
    const bool already_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(wtxid))};
    // Deduplicate parent txids, so that we don't have to loop over
    // the same parent txid more than once down below.
    std::vector<uint256> unique_parents;
    if (already_in_orphanage) {
        unique_parents = m_orphanage.GetParentTxids(wtxid).value_or(std::vector<uint256>{});
    } else {
        unique_parents.reserve(tx->vin.size());
        for (const CTxIn& txin : tx->vin) {
            // We start with all parents, and then remove duplicates below.
            unique_parents.push_back(txin.prevout.hash);
        }
        std::sort(unique_parents.begin(), unique_parents.end());
        unique_parents.erase(std::unique(unique_parents.begin(), unique_parents.end()), unique_parents.end());

        unique_parents.erase(std::remove_if(unique_parents.begin(), unique_parents.end(),
            [&](const auto& txid) EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
            { return AlreadyHaveTxLocked(GenTxid::Txid(txid)); }),
            unique_parents.end());
    }

    m_orphanage.AddTx(tx, nodeid, unique_parents);

    // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789).
    // This may decide to evict the new orphan.
    m_orphanage.LimitOrphans(m_opts.m_max_orphan_txs);

    const bool still_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(wtxid))};
    if (still_in_orphanage) {
        // Everyone who announced the orphan is a candidate for orphan resolution.
        AddOrphanAnnouncer(nodeid, wtxid, current_time);
        for (const auto candidate : m_txrequest.GetCandidatePeers(wtxid)) {
            AddOrphanAnnouncer(candidate, wtxid, current_time);
        }
        for (const auto candidate : m_txrequest.GetCandidatePeers(tx->GetHash())) {
            // Wtxid is correct. We want to track the orphan as 1 transaction identified
            // by its wtxid.
            AddOrphanAnnouncer(candidate, wtxid, current_time);
        }
    }
    // Once added to the orphan pool, a tx is considered AlreadyHave, and we shouldn't request it
    // anymore. This must be done after adding orphan announcers otherwise we will not be able to
    // retrieve the candidate peers.
    m_txrequest.ForgetTxHash(tx->GetHash());
    m_txrequest.ForgetTxHash(wtxid);
    return {!already_in_orphanage && still_in_orphanage,  unique_parents};
}

bool TxDownloadImpl::HaveMoreWork(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    return m_orphanage.HaveTxToReconsider(nodeid);
}

CTransactionRef TxDownloadImpl::GetTxToReconsider(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    return m_orphanage.GetTxToReconsider(nodeid);
}

void TxDownloadImpl::CheckIsEmpty() const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    assert(m_orphanage.Size() == 0);
    Assume(m_orphanage.TotalOrphanBytes() == 0);
    assert(m_txrequest.Size() == 0);
    Assume(m_orphan_resolution_tracker.Size() == 0);
}

void TxDownloadImpl::CheckIsEmpty(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    Assume(m_orphanage.BytesFromPeer(nodeid) == 0);
    assert(m_txrequest.Count(nodeid) == 0);
    Assume(m_orphan_resolution_tracker.Count(nodeid) == 0);
}
} // namespace node
