// Copyright (c) 2023
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownload_impl.h>

#include <policy/packages.h>

namespace node {
/** How long to wait before requesting orphan ancpkginfo/parents from an additional peer. */
static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};

TxOrphanage& TxDownloadImpl::GetOrphanageRef() EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex) { return m_orphanage; }
TxRequestTracker& TxDownloadImpl::GetTxRequestRef() EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex) { return m_txrequest; }

PackageRelayVersions TxDownloadImpl::GetSupportedVersions() const
{
    return m_opts.m_do_package_relay ?
        PackageRelayVersions{PKG_RELAY_PKGTXNS | PKG_RELAY_ANCPKG} :
        PKG_RELAY_NONE;
}

void TxDownloadImpl::ReceivedSendpackages(NodeId nodeid, PackageRelayVersions version)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    AssertLockNotHeld(m_tx_download_mutex);
    LOCK(m_tx_download_mutex);
    // net processing should not be allowing sendpackages after verack. Don't record sendpackages
    // for a peer after we have already added them to m_peer_info.
    if (!Assume(m_peer_info.count(nodeid) == 0)) return;
    // This doesn't overwrite any existing entry. If a peer sends more than one sendpackages, we
    // essentially ignore all but the first one.
    m_sendpackages_received.emplace(nodeid, version);
}

void TxDownloadImpl::ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    Assume(m_peer_info.count(nodeid) == 0);

    // We can relay packages with this peer if:
    // - They sent sendpackages and there are versions we both support (it's possible that we didn't
    //   have any versions in common).
    // - They support wtxidrelay
    // - They want us to relay transactions
    auto package_relay_versions = (m_sendpackages_received.count(nodeid) > 0 &&
                                   info.m_relays_txs &&
                                   info.m_wtxid_relay)
        ?  PackageRelayVersions{m_sendpackages_received.at(nodeid) & GetSupportedVersions()}
        : PKG_RELAY_NONE;

    m_peer_info.emplace(nodeid, PeerInfo(info, package_relay_versions));
    m_sendpackages_received.erase(nodeid);
    if (info.m_wtxid_relay) m_num_wtxid_peers += 1;
    if (m_peer_info.at(nodeid).SupportsVersion(PackageRelayVersions::PKG_RELAY_ANCPKG)) m_num_ancpkg_relay_peers += 1;
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
        if (m_peer_info.at(nodeid).SupportsVersion(PackageRelayVersions::PKG_RELAY_ANCPKG)) m_num_ancpkg_relay_peers -= 1;
    }
    m_peer_info.erase(nodeid);
    m_sendpackages_received.erase(nodeid);
    auto& index_by_peer = m_packages_downloading.get<ByPeerView>();
    auto it = m_packages_downloading.get<ByPeer>().lower_bound(ByPeerView{nodeid, 0});
    while (it != m_packages_downloading.get<ByPeer>().end() && it->m_pkginfo_provider == nodeid) {
        // If we're at the end or the next package is from a different peer, stop here.
        auto it_next = (std::next(it)->m_peer != peer) ? index.end() : std::next(it);
        m_packages_downloading.get<ByPeer>.erase(it);
        it = it_next;
    }
}

bool TxDownloadImpl::SupportsPackageRelay(NodeId nodeid, PackageRelayVersions version) const
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    if (m_peer_info.count(nodeid) == 0) return false;
    return m_peer_info.at(nodeid).SupportsVersion(version);
}

bool TxDownloadImpl::SupportsPackageRelay(NodeId nodeid) const
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    if (m_peer_info.count(nodeid) == 0) return false;
    return m_peer_info.at(nodeid).SupportsPackageRelay();
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
    {
        // We can add the wtxid of this transaction to our reconsiderable reject filter.
        // Do not add this transaction to m_recent_rejects because we want to reconsider it if we
        // see it in a package.
        m_recent_rejects_reconsiderable.insert(tx->GetWitnessHash());
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

void TxDownloadImpl::ExpirePackagesToDownload(std::chrono::microseconds current_time)
    EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex)
{
    AssertLockHeld(m_tx_download_mutex);
    // Iterate m_packages_downloading by expiry and remove any whose expiry is in the past.
    while (!m_packages_downloading.empty()) {
        auto it = m_packages_downloading.get<ByExpiry>().begin();
        if (it->m_expiry < current_time) {
            m_packages_downloading.erase(it);
        }
    }
}

std::vector<GenRequest> TxDownloadImpl::GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    if (!Assume(m_peer_info.count(nodeid) > 0)) return {};
    std::vector<GenRequest> requests;
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
    const bool is_package_relay_peer{m_peer_info.at(nodeid).SupportsVersion(PackageRelayVersions::PKG_RELAY_ANCPKG)};
    for (const auto& orphan_gtxid : orphans_ready) {
        Assume(orphan_gtxid.IsWtxid());
        if (!m_orphanage.HaveTx(orphan_gtxid)) {
            // No point in trying to resolve an orphan if we don't have it anymore.
            m_orphan_resolution_tracker.ForgetTxHash(orphan_gtxid.GetHash());
        }
        if (is_package_relay_peer) {
            LogPrint(BCLog::TXPACKAGES, "requesting ancpkginfo from peer=%d for orphan %s\n", nodeid, orphan_gtxid.GetHash().ToString());
            requests.emplace_back(GenRequest::PkgRequest(orphan_gtxid));
            m_package_info_requested.insert(GetPackageInfoRequestId(nodeid, orphan_gtxid.GetHash(), PackageRelayVersions::PKG_RELAY_ANCPKG));
            m_orphan_resolution_tracker.RequestedTx(nodeid, orphan_gtxid.GetHash(), current_time + ORPHAN_ANCESTOR_GETDATA_INTERVAL);
        } else if (auto parent_txids{m_orphanage.GetParentTxids(orphan_gtxid.GetHash())}) {
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
            requests.emplace_back(GenRequest::TxRequest(gtxid));
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

void TxDownloadImpl::ReceivedNotFound(NodeId nodeid, const std::vector<GenRequest>& requests)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    for (const auto& request: requests) {
        if (request.m_type == GenRequest::Type::ANCPKGINFO) {
            // We tried to resolve the orphan with this peer, but they couldn't send the
            // ancpkginfo. Mark this as a failed orphan resolution attempt.
            m_orphan_resolution_tracker.ReceivedResponse(nodeid, request.m_id);
        } else {
            // If we receive a NOTFOUND message for a tx we requested, mark the announcement for it as
            // completed in TxRequestTracker.
            m_txrequest.ReceivedResponse(nodeid, request.m_id);
        }
    }
}

bool TxDownloadImpl::PackageInfoAllowed(NodeId nodeid, const uint256& wtxid, PackageRelayVersions version) const
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    LOCK(m_tx_download_mutex);
    // Not allowed if peer isn't registered
    if (m_peer_info.count(nodeid) == 0) return false;
    const auto& peerinfo = m_peer_info.at(nodeid);
    // Not allowed if we didn't negotiate this version of package relay with this peer
    if (!peerinfo.SupportsVersion(version)) return false;
    // Not allowed if we didn't solicit this package info.
    if (!m_package_info_requested.contains(GetPackageInfoRequestId(nodeid, wtxid, version))) return false;

    return true;
}

void TxDownloadImpl::ReceivedAncpkginfo(NodeId nodeid, const std::vector<uint256>& package_wtxids, std::chrono::microseconds current_time)
    EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex)
{
    // We assume the caller has already checked PackageInfoAllowed
    if (!Assume(m_peer_info.count(nodeid) > 0)) return;

    const auto& rep_wtxid{package_wtxids.back()};
    if (package_wtxids.size() > MAX_PACKAGE_COUNT) {
        LogPrint(BCLog::NET, "discarding package info from %d for tx %s, too many transactions\n", rep_wtxid.ToString());
        m_orphan_resolution_tracker.ReceivedResponse(nodeid, rep_wtxid);
        return;
    }
    // We have already validated this exact set of transactions recently, so don't do it again.
    if (m_recent_rejects_reconsiderable.contains(GetCombinedHash(package_wtxids))) {
        LogPrint(BCLog::NET, "discarding package info from %d for tx %s, this package has already been rejected\n",
                 rep_wtxid.ToString());
        m_orphan_resolution_tracker.ReceivedResponse(nodeid, rep_wtxid);
        return;
    }
    for (const auto& wtxid : package_wtxids) {
        // If a transaction is in m_recent_rejects and not m_recent_rejects_reconsiderable, that
        // means it will not become valid by adding another transaction.
        if (m_recent_rejects.contains(wtxid)) {
            LogPrint(BCLog::NET, "discarding package from %d for tx %s, tx %s has already been rejected and is not eligible for reconsideration\n",
                     rep_wtxid.ToString(), wtxid.ToString());
            m_orphan_resolution_tracker.ReceivedResponse(nodeid, rep_wtxid);
            return;
        }
    }
    // For now, just add these transactions as announcements.
    for (const auto& wtxid : package_wtxids) {
        if (!AlreadyHaveTx(GenTxid::Wtxid(wtxid))) {
            AddTxAnnouncement(nodeid, GenTxid::Wtxid(wtxid), current_time);
        }
    }
}

void TxDownloadImpl::AddOrphanAnnouncer(NodeId nodeid, const uint256& orphan_wtxid, std::chrono::microseconds now)
{
    if (!Assume(m_peer_info.count(nodeid) > 0)) return;
    // Skip if we already requested ancpkginfo for this tx from this peer recently.
    if (m_package_info_requested.contains(GetPackageInfoRequestId(nodeid, orphan_wtxid, PackageRelayVersions::PKG_RELAY_ANCPKG))) return;

    const auto& info = m_peer_info.at(nodeid).m_connection_info;
    const bool is_package_relay_peer{m_peer_info.at(nodeid).SupportsVersion(PackageRelayVersions::PKG_RELAY_ANCPKG)};
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
    // Prefer using package relay if possible. It's not guaranteed that a package relay peer will
    // announce this orphan but delay the request to give them a chance to do so.
    if (!is_package_relay_peer && m_num_ancpkg_relay_peers > 0) delay += TXID_RELAY_DELAY;
    // The orphan wtxid is used, but resolution entails requesting the parents by txid.
    if (!is_package_relay_peer && m_num_wtxid_peers > 0) delay += TXID_RELAY_DELAY;

    const bool overloaded = !info.m_relay_permissions && m_txrequest.CountInFlight(nodeid) >= MAX_PEER_TX_REQUEST_IN_FLIGHT;
    if (overloaded) delay += OVERLOADED_PEER_TX_DELAY;

    LogPrint(BCLog::TXPACKAGES, "adding peer=%d as a candidate for resolving orphan %s using %s\n", nodeid, orphan_wtxid.ToString(),
        m_peer_info.at(nodeid).SupportsVersion(PackageRelayVersions::PKG_RELAY_ANCPKG) ? "package relay" : "parent-fetching");
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
