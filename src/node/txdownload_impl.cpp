// Copyright (c) 2023
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownload_impl.h>

#include <chain.h>
#include <consensus/validation.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>

namespace node {
void TxDownloadImpl::UpdatedBlockTipSync()
{
    // If the chain tip has changed previously rejected transactions
    // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
    // or a double-spend. Reset the rejects filter and give those
    // txs a second chance.
    m_recent_rejects.reset();
    m_recent_rejects_reconsiderable.reset();
}

void TxDownloadImpl::BlockConnected(const std::shared_ptr<const CBlock>& pblock)
{
    m_orphanage.EraseForBlock(*pblock);

    for (const auto& ptx : pblock->vtx) {
        m_recent_confirmed_transactions.insert(ptx->GetHash().ToUint256());
        if (ptx->HasWitness()) {
            m_recent_confirmed_transactions.insert(ptx->GetWitnessHash().ToUint256());
        }
    }
    for (const auto& ptx : pblock->vtx) {
        m_txrequest.ForgetTxHash(ptx->GetHash());
        m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
    }
}

void TxDownloadImpl::BlockDisconnected()
{
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

bool TxDownloadImpl::AlreadyHaveTx(const GenTxid& gtxid, bool include_reconsiderable)
{
    const uint256& hash = gtxid.GetHash();

    if (m_orphanage.HaveTx(gtxid)) return true;

    if (include_reconsiderable && m_recent_rejects_reconsiderable.contains(hash)) return true;

    if (m_recent_confirmed_transactions.contains(hash)) return true;

    return m_recent_rejects.contains(hash) || m_opts.m_mempool.exists(gtxid);
}

void TxDownloadImpl::ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info)
{
    // If already connected (shouldn't happen in practice), exit early.
    if (m_peer_info.count(nodeid) > 0) return;

    m_peer_info.emplace(nodeid, PeerInfo(info));
    if (info.m_wtxid_relay) m_num_wtxid_peers += 1;
}
void TxDownloadImpl::DisconnectedPeer(NodeId nodeid)
{
    m_orphanage.EraseForPeer(nodeid);
    m_txrequest.DisconnectedPeer(nodeid);

    if (m_peer_info.count(nodeid) > 0) {
        if (m_peer_info.at(nodeid).m_connection_info.m_wtxid_relay) m_num_wtxid_peers -= 1;
        m_peer_info.erase(nodeid);
    }
}

void TxDownloadImpl::ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
{
    if (m_peer_info.count(peer) == 0) return;
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

std::vector<GenTxid> TxDownloadImpl::GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time)
{
    std::vector<GenTxid> requests;
    std::vector<std::pair<NodeId, GenTxid>> expired;
    auto requestable = m_txrequest.GetRequestable(nodeid, current_time, &expired);
    for (const auto& entry : expired) {
        LogPrint(BCLog::NET, "timeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "wtx" : "tx",
            entry.second.GetHash().ToString(), entry.first);
    }
    for (const GenTxid& gtxid : requestable) {
        if (!AlreadyHaveTx(gtxid, /*include_reconsiderable=*/false)) {
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
} // namespace node
