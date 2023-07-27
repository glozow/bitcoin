// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <logging.h>
#include <node/txdownloadman.h>
#include <sync.h>
#include <txmempool.h>

namespace node {
    /** How long to wait before requesting orphan ancpkginfo/parents from an additional peer. */
    static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};
class TxDownloadManager::Impl {
    const Options m_opts;

    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;

    /** Tracks orphans we are trying to resolve. All hashes stored are wtxids, i.e., the wtxid of
     * the orphan. Used to schedule resolution with peers, which means requesting the missing
     * parents by txid. */
    TxRequestTracker m_orphan_resolution_tracker;

    /** Tracks candidates for requesting and downloading transaction data. */
    TxRequestTracker m_txrequest;

    /**
     * Filter for transactions that were recently rejected by the mempool.
     * These are not rerequested until the chain tip changes, at which point
     * the entire filter is reset.
     *
     * Without this filter we'd be re-requesting txs from each of our peers,
     * increasing bandwidth consumption considerably. For instance, with 100
     * peers, half of which relay a tx we don't accept, that might be a 50x
     * bandwidth increase. A flooding attacker attempting to roll-over the
     * filter using minimum-sized, 60byte, transactions might manage to send
     * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
     * two minute window to send invs to us.
     *
     * Decreasing the false positive rate is fairly cheap, so we pick one in a
     * million to make it highly unlikely for users to have issues with this
     * filter.
     *
     * We typically only add wtxids to this filter. For non-segwit
     * transactions, the txid == wtxid, so this only prevents us from
     * re-downloading non-segwit transactions when communicating with
     * non-wtxidrelay peers -- which is important for avoiding malleation
     * attacks that could otherwise interfere with transaction relay from
     * non-wtxidrelay peers. For communicating with wtxidrelay peers, having
     * the reject filter store wtxids is exactly what we want to avoid
     * redownload of a rejected transaction.
     *
     * In cases where we can tell that a segwit transaction will fail
     * validation no matter the witness, we may add the txid of such
     * transaction to the filter as well. This can be helpful when
     * communicating with txid-relay peers or if we were to otherwise fetch a
     * transaction via txid (eg in our orphan handling).
     *
     * Memory used: 1.3 MB
     */
    CRollingBloomFilter m_recent_rejects{120'000, 0.000'001};
    uint256 hashRecentRejectsChainTip;

    /*
     * Filter for transactions that have been recently confirmed.
     * We use this to avoid requesting transactions that have already been
     * confirnmed.
     *
     * Blocks don't typically have more than 4000 transactions, so this should
     * be at least six blocks (~1 hr) worth of transactions that we can store,
     * inserting both a txid and wtxid for every observed transaction.
     * If the number of transactions appearing in a block goes up, or if we are
     * seeing getdata requests more than an hour after initial announcement, we
     * can increase this number.
     * The false positive rate of 1/1M should come out to less than 1
     * transaction per day that would be inadvertently ignored (which is the
     * same probability that we have in the reject filter).
     */
    mutable Mutex m_recent_confirmed_transactions_mutex;
    CRollingBloomFilter m_recent_confirmed_transactions GUARDED_BY(m_recent_confirmed_transactions_mutex){48'000, 0.000'001};

    struct PeerInfo {
        /** Information relevant to scheduling tx requests. */
        const ConnectionInfo m_connection_info;

        PeerInfo(const ConnectionInfo& info) : m_connection_info{info} {}
    };

    /** Information for all of the peers we may download transactions from. This is not necessarily
     * all peers we are connected to (no block-relay-only and temporary connections). */
    std::map<NodeId, PeerInfo> m_peer_info;

    /** Number of wtxid relay peers we have. */
    uint32_t m_num_wtxid_peers{0};
public:
    Impl(const Options& opts) : m_opts{opts} {}

    TxOrphanage& GetOrphanageRef() { return m_orphanage; }
    TxRequestTracker& GetTxRequestRef() { return m_txrequest; }

    void ConnectedPeer(NodeId nodeid, const ConnectionInfo& info)
    {
        Assume(m_peer_info.count(nodeid) == 0);
        m_peer_info.emplace(nodeid, PeerInfo(info));
        if (info.m_wtxid_relay) m_num_wtxid_peers += 1;
    }

    void DisconnectedPeer(NodeId nodeid)
    {
        m_orphanage.EraseForPeer(nodeid);
        m_txrequest.DisconnectedPeer(nodeid);
        m_orphan_resolution_tracker.DisconnectedPeer(nodeid);

        if (m_peer_info.count(nodeid) == 0) return;
        if (m_peer_info.at(nodeid).m_connection_info.m_wtxid_relay) {
            if (Assume(m_num_wtxid_peers > 0)) m_num_wtxid_peers -= 1;
        }
        m_peer_info.erase(nodeid);
    }

    void BlockConnected(const CBlock& block, const uint256& tiphash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
    {
        LOCK(m_recent_confirmed_transactions_mutex);
        const auto erased_wtxids = m_orphanage.EraseForBlock(block);
        for (const auto& ptx : block.vtx) {
            m_txrequest.ForgetTxHash(ptx->GetHash());
            m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
            m_recent_confirmed_transactions.insert(ptx->GetHash());
            // All hashes in orphan request tracker are wtxid.
            m_orphan_resolution_tracker.ForgetTxHash(ptx->GetWitnessHash());
            m_recent_confirmed_transactions.insert(ptx->GetWitnessHash());
            if (ptx->GetHash() != ptx->GetWitnessHash()) {
                m_recent_confirmed_transactions.insert(ptx->GetWitnessHash());
            }
        }
        // Give up trying to resolve any orphans that were conflicted by the block.
        for (const auto& wtxid: erased_wtxids) {
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

    void BlockDisconnected() EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
    {
        // To avoid relay problems with transactions that were previously
        // confirmed, clear our filter of recently confirmed transactions whenever
        // there's a reorg.
        // This means that in a 1-block reorg (where 1 block is disconnected and
        // then another block reconnected), our filter will drop to having only one
        // block's worth of transactions in it, but that should be fine, since
        // presumably the most common case of relaying a confirmed transaction
        // should be just after a new block containing it is found.
        LOCK(m_recent_confirmed_transactions_mutex);
        m_recent_confirmed_transactions.reset();
    }

    void MempoolAcceptedTx(const CTransactionRef& tx)
    {
        m_orphanage.AddChildrenToWorkSet(*tx);
        // These are noops when transaction/hash is not present. As this version of
        // the transaction was acceptable, we can forget about any requests for it.
        // If it came from the orphanage, remove it.
        m_txrequest.ForgetTxHash(tx->GetHash());
        m_txrequest.ForgetTxHash(tx->GetWitnessHash());
        // All hashes in orphan request tracker are wtxid.
        m_orphan_resolution_tracker.ForgetTxHash(tx->GetWitnessHash());
        m_orphanage.EraseTx(tx->GetWitnessHash());
    }

    bool MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result)
    {
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
                [&](const auto& input)
                { return m_recent_rejects.contains(input.prevout.hash); })) {
                LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s (wtxid=%s)\n",
                         tx->GetHash().ToString(), tx->GetWitnessHash().ToString());
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
        case TxValidationResult::TX_CONSENSUS:
        case TxValidationResult::TX_RECENT_CONSENSUS_CHANGE:
        case TxValidationResult::TX_NOT_STANDARD:
        case TxValidationResult::TX_PREMATURE_SPEND:
        case TxValidationResult::TX_WITNESS_MUTATED:
        case TxValidationResult::TX_CONFLICT:
        case TxValidationResult::TX_MEMPOOL_POLICY:
            break;
        }
        // We can add the wtxid of this transaction to our reject filter.
        m_recent_rejects.insert(tx->GetWitnessHash());
        m_txrequest.ForgetTxHash(tx->GetWitnessHash());
        m_orphanage.EraseTx(tx->GetWitnessHash());
        m_orphan_resolution_tracker.ForgetTxHash(tx->GetWitnessHash());
        return false;
    }

    bool AlreadyHaveTx(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
    {
        const uint256& hash = gtxid.GetHash();

        if (m_orphanage.HaveTx(gtxid)) return true;

        {
            LOCK(m_recent_confirmed_transactions_mutex);
            if (m_recent_confirmed_transactions.contains(hash)) return true;
        }

        return m_recent_rejects.contains(hash) || m_opts.m_mempool_ref.exists(gtxid);
    }

    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
    {
        // If this announcement is for an orphan we're trying to resolve, add this peer as a
        // candidate for orphan resolution.
        if (m_orphanage.HaveTx(gtxid)) AddOrphanAnnouncer(peer, gtxid.GetHash(), now);
        if (!Assume(m_peer_info.count(peer) > 0)) return;
        if (AlreadyHaveTx(gtxid)) return;
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

    std::vector<GenTxid> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
    {
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
            if (!AlreadyHaveTx(gtxid)) {
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

    void ReceivedTx(NodeId nodeid, const uint256& txhash)
    {
        m_txrequest.ReceivedResponse(nodeid, txhash);
    }
    void AddOrphanAnnouncer(NodeId nodeid, const uint256& orphan_wtxid, std::chrono::microseconds now)
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

    bool NewOrphanTx(const CTransactionRef& tx, const std::vector<uint256>& parent_txids, NodeId nodeid,
                     std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
    {
        const bool already_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(tx->GetWitnessHash()))};
        const auto& orphan_txid = tx->GetHash();
        const auto& orphan_wtxid = tx->GetWitnessHash();

        LogPrint(BCLog::TXPACKAGES, "brand new orphan transaction %s\n", orphan_wtxid.ToString());

        m_orphanage.AddTx(tx, nodeid, parent_txids);

        // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789).
        // This may decide to evict the new orphan.
        m_orphanage.LimitOrphans(m_opts.m_max_orphan_txs);

        const bool still_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(orphan_wtxid))};
        if (still_in_orphanage) {
            // Everyone who announced the orphan is a candidate for orphan resolution.
            AddOrphanAnnouncer(nodeid, orphan_wtxid, now);
            for (const auto candidate : m_txrequest.GetCandidatePeers(orphan_wtxid)) {
                AddOrphanAnnouncer(candidate, orphan_wtxid, now);
            }
            for (const auto candidate : m_txrequest.GetCandidatePeers(orphan_txid)) {
                // Wtxid is correct. We want to track the orphan as 1 transaction identified
                // by its wtxid.
                AddOrphanAnnouncer(candidate, orphan_wtxid, now);
            }
        }
        // Once added to the orphan pool, a tx is considered AlreadyHave, and we shouldn't request it anymore.
        // This must be done after adding the orphan announcers because the candidates are taken
        // from m_txrequest.
        m_txrequest.ForgetTxHash(orphan_txid);
        m_txrequest.ForgetTxHash(orphan_wtxid);
        return !already_in_orphanage && still_in_orphanage;
    }

    bool HaveMoreWork(NodeId nodeid) const { return m_orphanage.HaveTxToReconsider(nodeid); }
    CTransactionRef GetTxToReconsider(NodeId nodeid) { return m_orphanage.GetTxToReconsider(nodeid); }

    void CheckIsEmpty() const
    {
        assert(m_orphanage.Size() == 0);
        Assume(m_orphanage.TotalOrphanBytes() == 0);
        assert(m_txrequest.Size() == 0);
        Assume(m_orphan_resolution_tracker.Size() == 0);
    }

    void CheckIsEmpty(NodeId nodeid) const
    {
        Assume(m_orphanage.BytesFromPeer(nodeid) == 0);
        assert(m_txrequest.Count(nodeid) == 0);
        Assume(m_orphan_resolution_tracker.Count(nodeid) == 0);
    }
};

TxDownloadManager::TxDownloadManager(const TxDownloadManager::Options& opts) :
    m_impl{std::make_unique<TxDownloadManager::Impl>(opts)} {}
TxDownloadManager::~TxDownloadManager() = default;

TxOrphanage& TxDownloadManager::GetOrphanageRef() { return m_impl->GetOrphanageRef(); }
TxRequestTracker& TxDownloadManager::GetTxRequestRef() { return m_impl->GetTxRequestRef(); }

void TxDownloadManager::ConnectedPeer(NodeId nodeid, const ConnectionInfo& info) { m_impl->ConnectedPeer(nodeid, info); }
void TxDownloadManager::DisconnectedPeer(NodeId nodeid) { m_impl->DisconnectedPeer(nodeid); }

void TxDownloadManager::BlockConnected(const CBlock& block, const uint256& tiphash) {
    return m_impl->BlockConnected(block, tiphash);
}
void TxDownloadManager::BlockDisconnected() { m_impl->BlockDisconnected(); }
void TxDownloadManager::MempoolAcceptedTx(const CTransactionRef& tx) { m_impl->MempoolAcceptedTx(tx); }
bool TxDownloadManager::MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result) {
    return m_impl->MempoolRejectedTx(tx, result);
}
bool TxDownloadManager::AlreadyHaveTx(const GenTxid& gtxid) const { return m_impl->AlreadyHaveTx(gtxid); }

void TxDownloadManager::ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
    { return m_impl->ReceivedTxInv(peer, gtxid, now); }
std::vector<GenTxid> TxDownloadManager::GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time) {
    return m_impl->GetRequestsToSend(nodeid, current_time);
}
void TxDownloadManager::ReceivedTx(NodeId nodeid, const uint256& txhash) { m_impl->ReceivedTx(nodeid, txhash); }
bool TxDownloadManager::NewOrphanTx(const CTransactionRef& tx, const std::vector<uint256>& parent_txids, NodeId nodeid,
    std::chrono::microseconds now) { return m_impl->NewOrphanTx(tx, parent_txids, nodeid, now); }
bool TxDownloadManager::HaveMoreWork(NodeId nodeid) const { return m_impl->HaveMoreWork(nodeid); }
CTransactionRef TxDownloadManager::GetTxToReconsider(NodeId nodeid) { return m_impl->GetTxToReconsider(nodeid); }
void TxDownloadManager::CheckIsEmpty() const { m_impl->CheckIsEmpty(); }
void TxDownloadManager::CheckIsEmpty(NodeId nodeid) const { m_impl->CheckIsEmpty(nodeid); }
} // namespace node
