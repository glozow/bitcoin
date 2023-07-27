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
    // If already connected (shouldn't happen in practice), exit early.
    if (m_peer_info.count(nodeid) > 0) return;

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

    if (m_peer_info.count(nodeid) > 0) {
        if (m_peer_info.at(nodeid).m_connection_info.m_wtxid_relay) m_num_wtxid_peers -= 1;
        m_peer_info.erase(nodeid);
    }
}

void TxDownloadImpl::UpdatedBlockTipSync() EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    // If the chain tip has changed previously rejected transactions
    // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
    // or a double-spend. Reset the rejects filter and give those
    // txs a second chance.
    m_recent_rejects.reset();
}

void TxDownloadImpl::BlockConnected(const CBlock& block, const uint256& tiphash)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    for (const auto& ptx : block.vtx) {
        m_txrequest.ForgetTxHash(ptx->GetHash());
        m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
        m_recent_confirmed_transactions.insert(ptx->GetHash().ToUint256());
        if (ptx->HasWitness()) {
            m_recent_confirmed_transactions.insert(ptx->GetWitnessHash().ToUint256());
        }
    }
    // Orphanage may include transactions conflicted by this block. There should not be any
    // transactions in m_orphan_resolution_tracker that aren't in orphanage, so this should include
    // all of the relevant orphans we were working on.
    for (const auto& erased_wtxid : m_orphanage.EraseForBlock(block)) {
        // All hashes in m_orphan_resolution_tracker are wtxids.
        m_orphan_resolution_tracker.ForgetTxHash(erased_wtxid);
    }

    // Stop trying to resolve orphans that were conflicted by the block.
    for (const auto& wtxid : m_orphanage.EraseForBlock(block)) {
        m_orphan_resolution_tracker.ForgetTxHash(wtxid);
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
    m_txrequest.ForgetTxHash(tx->GetHash().ToUint256());
    m_txrequest.ForgetTxHash(tx->GetWitnessHash().ToUint256());
    // If it came from the orphanage, remove it. No-op if the tx is not in txorphanage.
    m_orphanage.EraseTx(tx->GetWitnessHash());
    m_orphan_resolution_tracker.ForgetTxHash(tx->GetWitnessHash());
}

InvalidTxTask TxDownloadImpl::MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);

    InvalidTxTask task = InvalidTxTask::NONE;

    switch (result) {
    case TxValidationResult::TX_RESULT_UNSET:
    case TxValidationResult::TX_NO_MEMPOOL:
    {
        // This function should only be called when a transaction fails validation.
        Assume(false);
        return InvalidTxTask::NONE;
    }
    case TxValidationResult::TX_UNKNOWN:
    {
        // Transaction was not validated; we don't know that it is invalid. Do not add it to any
        // rejection caches or forget about it yet.
        return InvalidTxTask::NONE;
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
        return InvalidTxTask::NONE;
    }
    case TxValidationResult::TX_RECONSIDERABLE:
    {
       // Transaction failed for fee-related reasons but can be reconsidered if part of a package.
       m_recent_rejects_reconsiderable.insert(tx->GetWitnessHash().ToUint256());
       task = InvalidTxTask::TRY_CPFP;
       break;
    }
    case TxValidationResult::TX_MISSING_INPUTS:
    {
        if (std::any_of(tx->vin.cbegin(), tx->vin.cend(),
            [&](const auto& input) EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
            { return m_recent_rejects.contains(input.prevout.hash.ToUint256()); })) {
            LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s (wtxid=%s)\n",
                     tx->GetHash().ToString(),
                     tx->GetWitnessHash().ToString());
            // We will continue to reject this tx since it has rejected
            // parents so avoid re-requesting it from other peers.
            // Here we add both the txid and the wtxid, as we know that
            // regardless of what witness is provided, we will not accept
            // this, so we don't need to allow for redownload of this txid
            // from any of our non-wtxidrelay peers.
            m_recent_rejects.insert(tx->GetHash().ToUint256());
            m_recent_rejects.insert(tx->GetWitnessHash().ToUint256());
            m_txrequest.ForgetTxHash(tx->GetHash().ToUint256());
            m_txrequest.ForgetTxHash(tx->GetWitnessHash().ToUint256());
            return InvalidTxTask::NONE;
        }
        return InvalidTxTask::ADD_ORPHAN;
    }
    case TxValidationResult::TX_INPUTS_NOT_STANDARD:
    {
        // We can add the wtxid of this transaction to our reject filter.
        m_recent_rejects.insert(tx->GetWitnessHash().ToUint256());
        // If the transaction failed for TX_INPUTS_NOT_STANDARD,
        // then we know that the witness was irrelevant to the policy
        // failure, since this check depends only on the txid
        // (the scriptPubKey being spent is covered by the txid).
        // Add the txid to the reject filter to prevent repeated
        // processing of this transaction in the event that child
        // transactions are later received (resulting in
        // parent-fetching by txid via the orphan-handling logic).
        if (tx->HasWitness()) {
            m_recent_rejects.insert(tx->GetHash().ToUint256());
            m_txrequest.ForgetTxHash(tx->GetHash());
        }
        break;
    }
    case TxValidationResult::TX_CONSENSUS:
    case TxValidationResult::TX_RECENT_CONSENSUS_CHANGE:
    case TxValidationResult::TX_NOT_STANDARD:
    case TxValidationResult::TX_PREMATURE_SPEND:
    case TxValidationResult::TX_WITNESS_MUTATED:
    case TxValidationResult::TX_CONFLICT:
    case TxValidationResult::TX_MEMPOOL_POLICY:
    {
        // We can add the wtxid of this transaction to our reject filter.
        m_recent_rejects.insert(tx->GetWitnessHash().ToUint256());
        break;
    }
    }
    // Forget requests for this wtxid, but not for the txid, as another version of
    // transaction may be valid. No-op if the tx is not in txrequest.
    m_txrequest.ForgetTxHash(tx->GetWitnessHash());
    // If it came from the orphanage, remove it from the orphanage and orphan resolution tracker
    // (this doesn't happen if the transaction was missing inputs). No-op if the tx is not in these
    // data structures.
    m_orphanage.EraseTx(tx->GetWitnessHash());
    m_orphan_resolution_tracker.ForgetTxHash(tx->GetWitnessHash());
    return task;
}

void TxDownloadImpl::MempoolRejectedPackage(const uint256& packagehash)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    // Record this package hash in m_recent_rejects_reconsiderable so we don't try this exact
    // combination of transactions again. This is safe to do when the package was too low feerate or
    // if there was a more severe failure. A package containing a superset of these transactions can
    // be considered again (only in theory as we don't do anything beyond 1p1c right now).
    m_recent_rejects_reconsiderable.insert(packagehash);
}

bool TxDownloadImpl::AlreadyHaveTxLocked(const GenTxid& gtxid, bool include_reconsiderable) const
    EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
{
    AssertLockHeld(m_tx_download_mutex);
    const uint256& hash = gtxid.GetHash();

    if (m_orphanage.HaveTx(gtxid)) return true;

    if (include_reconsiderable && m_recent_rejects_reconsiderable.contains(gtxid.GetHash())) return true;

    {
        if (m_recent_confirmed_transactions.contains(hash)) return true;
    }

    return m_recent_rejects.contains(hash) || m_opts.m_mempool_ref.exists(gtxid);
}

bool TxDownloadImpl::AlreadyHaveTx(const GenTxid& gtxid, bool include_reconsiderable) const
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    return AlreadyHaveTxLocked(gtxid, include_reconsiderable);
}

std::optional<Package> TxDownloadImpl::MaybeGet1p1cPackage(const CTransactionRef& tx_parent, NodeId nodeid) const
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    const auto cpfp_candidates{m_orphanage.GetChildren(tx_parent, nodeid)};
    // Shuffle to not create a bias that attackers can use to delay package acceptance.
    std::vector<size_t> tx_indices(cpfp_candidates.size());
    std::iota(tx_indices.begin(), tx_indices.end(), 0);
    Shuffle(tx_indices.begin(), tx_indices.end(), m_opts.m_rng);

    // Return the first package that hasn't already been tried.
    for (const auto index : tx_indices) {
        const auto& tx_orphan = cpfp_candidates.at(index);
        Package maybe_cpfp_package{tx_parent, tx_orphan};
        if (!m_recent_rejects_reconsiderable.contains(GetPackageHash(maybe_cpfp_package))) {
            return maybe_cpfp_package;
        }
    }
    return std::nullopt;
}

void TxDownloadImpl::AddTxAnnouncement(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
    EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
{
    AssertLockHeld(m_tx_download_mutex);

    if (m_peer_info.count(peer) == 0) return;
    // If this inv is by txid, check by txid. If it's by wtxid, also check by txid to attempt to
    // catch same-txid-different-witness.
    if (m_orphanage.HaveTx(gtxid) || (gtxid.IsWtxid() && m_orphanage.HaveTx(GenTxid::Txid(gtxid.GetHash())))) {
        if (gtxid.IsWtxid()) {
            AddOrphanAnnouncer(peer, Wtxid::FromUint256(gtxid.GetHash()), now, /*is_new=*/false);
        }
        return;
    }
    if (AlreadyHaveTxLocked(gtxid, /*include_reconsiderable=*/true)) return;
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
        LogPrint(BCLog::TXPACKAGES, "timeout of in-flight orphan resolution %s for peer=%d\n", orphan_gtxid.GetHash().ToString(), nodeid);
        // All txhashes in m_orphan_resolution_tracker are wtxids.
        Assume(orphan_gtxid.IsWtxid());
        m_orphanage.EraseOrphanOfPeer(Wtxid::FromUint256(orphan_gtxid.GetHash()), nodeid);
        Assume(!m_orphanage.HaveTxAndPeer(orphan_gtxid, nodeid));
    }
    for (const auto& orphan_gtxid : orphans_ready) {
        Assume(orphan_gtxid.IsWtxid());
        Assume(m_orphanage.HaveTxAndPeer(orphan_gtxid, nodeid));
        const auto parent_txids{m_orphanage.GetParentTxids(Wtxid::FromUint256(orphan_gtxid.GetHash()))};
        if (parent_txids.has_value()) {
            if (!Assume(m_peer_info.count(nodeid) > 0)) continue;
            const auto& info = m_peer_info.at(nodeid).m_connection_info;
            bool requesting{false};
            for (const auto& txid : *parent_txids) {
                // Skip any parents that have also entered the orphanage since the orphan was added.
                if (m_orphanage.HaveTxAndPeer(GenTxid::Txid(txid), nodeid)) continue;

                // Schedule with no delay instead of using ReceivedTxInv. This means it's scheduled
                // for request immediately unless there is already a request out for the same txhash
                // (e.g. if there is another orphan that needs this parent).
                m_txrequest.ReceivedInv(nodeid, GenTxid::Txid(txid), info.m_preferred, current_time);
                requesting = true;
                LogPrint(BCLog::TXPACKAGES, "scheduled parent request %s from peer=%d for orphan %s\n",
                    txid.ToString(), nodeid, orphan_gtxid.GetHash().ToString());
            }
            if (requesting) {
                m_orphan_resolution_tracker.RequestedTx(nodeid, orphan_gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
            }
        } else {
            LogPrint(BCLog::TXPACKAGES, "couldn't find parent txids to resolve orphan %s with peer=%d\n", orphan_gtxid.GetHash().ToString(), nodeid);
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
        if (!AlreadyHaveTxLocked(gtxid, /*include_reconsiderable=*/true)) {
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

std::optional<InvalidTxTask> TxDownloadImpl::ReceivedTx(NodeId nodeid, const CTransactionRef& ptx)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);

    // Mark that we have received a response
    m_txrequest.ReceivedResponse(nodeid, ptx->GetHash());
    if (ptx->HasWitness()) m_txrequest.ReceivedResponse(nodeid, ptx->GetWitnessHash());

    // First check if we should drop this tx.
    if (AlreadyHaveTxLocked(GenTxid::Wtxid(ptx->GetWitnessHash().ToUint256()), /*include_reconsiderable=*/false)) {
        return InvalidTxTask::NONE;
    } else if (m_recent_rejects_reconsiderable.contains(ptx->GetWitnessHash().ToUint256())) {
        // This transaction has already been rejected for having low feerate. Don't validate it
        // by itself again; try 1p1c package validation if eligible.
        return InvalidTxTask::TRY_CPFP;
    }
    return std::nullopt;
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

void TxDownloadImpl::AddOrphanAnnouncer(NodeId nodeid, const Wtxid& orphan_wtxid, std::chrono::microseconds now, bool is_new)
{
    if (m_peer_info.count(nodeid) == 0) return;
    if (!Assume(m_orphanage.HaveTx(GenTxid::Wtxid(orphan_wtxid)) || m_orphanage.HaveTx(GenTxid::Txid(orphan_wtxid)))) return;
    const auto& info = m_peer_info.at(nodeid).m_connection_info;
    // This mirrors the delaying and dropping behavior in ReceivedTxInv in order to preserve
    // existing behavior.
    // TODO: add delays and limits based on the amount of orphan resolution we are already doing
    // with this peer, how much they are using the orphanage, etc.
    if (!info.m_relay_permissions && m_orphan_resolution_tracker.Count(nodeid) >= MAX_PEER_TX_ANNOUNCEMENTS) {
        // Too many queued orphan resolutions with this peer
        return;
    }

    if (is_new || m_orphanage.AddAnnouncer(orphan_wtxid, nodeid)) {
        auto delay{0us};
        if (!info.m_preferred) delay += NONPREF_PEER_TX_DELAY;
        // The orphan wtxid is used, but resolution entails requesting the parents by txid.
        if (m_num_wtxid_peers > 0) delay += TXID_RELAY_DELAY;
        const bool overloaded = !info.m_relay_permissions && m_txrequest.CountInFlight(nodeid) >= MAX_PEER_TX_REQUEST_IN_FLIGHT;
        if (overloaded) delay += OVERLOADED_PEER_TX_DELAY;

        m_orphan_resolution_tracker.ReceivedInv(nodeid, GenTxid::Wtxid(orphan_wtxid), info.m_preferred, now + delay);
        LogPrint(BCLog::TXPACKAGES, "added peer=%d as a candidate for resolving orphan %s\n", nodeid, orphan_wtxid.ToString());
    }
}

std::pair<bool, std::vector<Txid>> TxDownloadImpl::NewOrphanTx(const CTransactionRef& tx,
    NodeId nodeid, std::chrono::microseconds current_time)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    const Wtxid& wtxid = tx->GetWitnessHash();
    // Query whether (tx, *) is in orphanage before adding to m_orphan_resolution_tracker
    const bool already_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(wtxid))};
    // Deduplicate parent txids, so that we don't have to loop over
    // the same parent txid more than once down below.
    std::vector<Txid> unique_parents;
    if (already_in_orphanage) {
        unique_parents = m_orphanage.GetParentTxids(wtxid).value_or(std::vector<Txid>{});
    } else {
        unique_parents.reserve(tx->vin.size());
        for (const CTxIn& txin : tx->vin) {
            // We start with all parents, and then remove duplicates below.
            unique_parents.push_back(Txid::FromUint256(txin.prevout.hash));
        }
        std::sort(unique_parents.begin(), unique_parents.end());
        unique_parents.erase(std::unique(unique_parents.begin(), unique_parents.end()), unique_parents.end());

        unique_parents.erase(std::remove_if(unique_parents.begin(), unique_parents.end(),
            [&](const auto& txid) EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
            { return AlreadyHaveTxLocked(GenTxid::Txid(txid), /*include_reconsiderable=*/true); }),
            unique_parents.end());
    }

    m_orphanage.AddTx(tx, nodeid, unique_parents);

    // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789).
    // This may decide to evict the new orphan.
    for (const auto& expired_wtxid : m_orphanage.LimitOrphans(m_opts.m_max_orphan_txs, DEFAULT_MAX_ORPHAN_TOTAL_SIZE, m_opts.m_rng)) {
        m_orphan_resolution_tracker.ForgetTxHash(expired_wtxid);
    }

    // Query whether (tx, nodeid) is in orphanage before adding to m_orphan_resolution_tracker
    const bool still_in_orphanage{m_orphanage.HaveTxAndPeer(GenTxid::Wtxid(wtxid), nodeid)};
    if (still_in_orphanage) {
        // Everyone who announced the orphan is a candidate for orphan resolution.
        AddOrphanAnnouncer(nodeid, wtxid, current_time, /*is_new=*/!already_in_orphanage);
        for (const auto candidate : m_txrequest.GetCandidatePeers(wtxid)) {
            AddOrphanAnnouncer(candidate, wtxid, current_time, /*is_new=*/false);
        }
        for (const auto candidate : m_txrequest.GetCandidatePeers(tx->GetHash())) {
            // Wtxid is correct. We want to track the orphan as 1 transaction identified
            // by its wtxid.
            AddOrphanAnnouncer(candidate, wtxid, current_time, /*is_new=*/false);
        }
    }
    // Once added to the orphan pool, a tx is considered AlreadyHave, and we shouldn't request it
    // anymore. This must be done after adding orphan announcers otherwise we will not be able to
    // retrieve the candidate peers.
    m_txrequest.ForgetTxHash(tx->GetHash());
    m_txrequest.ForgetTxHash(wtxid);

    // We added a new orphan if it wasn't already there, we called AddTx, and LimitOrphans didn't
    // evict it immediately.
    return {!already_in_orphanage && still_in_orphanage, unique_parents};
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
    assert(m_txrequest.Size() == 0);
    Assume(m_peer_info.empty());
    Assume(m_num_wtxid_peers == 0);
    Assume(m_orphan_resolution_tracker.Size() == 0);
}

void TxDownloadImpl::CheckIsEmpty(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    assert(m_txrequest.Count(nodeid) == 0);
    Assume(m_peer_info.count(nodeid) == 0);
    Assume(m_orphan_resolution_tracker.Count(nodeid) == 0);
}
} // namespace node
