// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <node/txdownloadman.h>

#include <txorphanage.h>
#include <txrequest.h>

namespace node {
class TxDownloadManager::Impl {
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;

    /** Tracks orphans we are trying to resolve. All hashes stored are wtxids, i.e., the wtxid of
     * the orphan. Used to schedule resolution with peers, which means requesting the missing
     * parents by txid. */
    TxRequestTracker m_orphan_resolution_tracker;

    /** Global maximum number of transactions to keep in the orphanage. */
    uint32_t m_max_orphan_txs;

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
    CRollingBloomFilter m_recent_confirmed_transactions{48'000, 0.000'001};

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

    // RequestId which helps us identify a request for transaction data pertaining to a package.
    using PackageTxRequestId = uint256;

    /** PackageTxRequestId for a txid request. */
    PackageTxRequestId GetTxRequestId(NodeId nodeid, uint256 txid) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << txid).GetHash();
    }

    /** Information about a package for which we know the (w)txids and are in the process of
     * downloading transaction data. */
    struct PackageToDownload {
        /** Which peer we are downloading this package from. */
        const NodeId m_peer;

        /** wtxid of the transaction this package pertains to, i.e. the orphan.
         * This is also what m_packages_downloading is indexed by. */
        const uint256 m_rep_wtxid;

        enum RequestStatus : uint8_t {
            WANTED,         //!> We know this tx is in the package but haven't done anything about it yet.
            SCHEDULED,      //!> We scheduled this tx in m_txrequest.
            REQUESTED,      //!> We have requested this tx.
        };

        /** PackageTxRequestId for each getdata sent. Used to delete entries from m_expected_responses. */
        std::map<PackageTxRequestId, RequestStatus> m_requests;

        /** An orphan transaction in which we only know parent txids. */
        PackageToDownload(NodeId peer, const uint256& rep_wtxid, const std::vector<uint256> parent_txids) :
            m_peer{peer},
            m_rep_wtxid{rep_wtxid}
        {
            for (const auto& txhash : parent_txids) {
                m_requests.emplace(txhash, RequestStatus::WANTED);
            }
        }

        /** Record a getdata we have scheduled for this package, i.e. entered into TxRequestTracker.
         * It won't necessarily be requested - there is usually a delay and, during that time, the
         * transaction could confirm or we could give up trying to download this package. */
        void RequestScheduled(const PackageTxRequestId& request_id) {
            if (!Assume(m_requests.count(request_id) > 0)) {
                m_requests.emplace(request_id, RequestStatus::SCHEDULED);
            } else {
                Assume(m_requests.at(request_id) == RequestStatus::WANTED);
                m_requests.at(request_id) = RequestStatus::SCHEDULED;
            }
        }
        /** Record a getdata we actually sent for this package. */
        void RequestSent(const PackageTxRequestId& request_id) {
            if (!Assume(m_requests.count(request_id) > 0)) {
                m_requests.emplace(request_id, RequestStatus::REQUESTED);
            } else {
                Assume(m_requests.at(request_id) == RequestStatus::SCHEDULED);
                m_requests.at(request_id) = RequestStatus::REQUESTED;
            }
        }
    };

    /** All PackageToDownload we are working on right now. */
    std::map<uint256, PackageToDownload> m_packages_downloading;
    using PendingMap = decltype(m_packages_downloading);

    /** Map from requests for transaction data we have sent to their respective PackageToDownload.
     * Since each orphan may have multiple missing inputs, multiple PackageTxRequestIds may
     * point to the same PackageToDownload. */
    std::map<PackageTxRequestId, PendingMap::iterator> m_package_download_requests;

public:
    Impl() = delete;
    Impl(uint32_t max_orphan_txs) : m_max_orphan_txs{max_orphan_txs} {}

    /** Abandon a PackageToDownload. Do nothing if we aren't downloading a package for rep_wtxid.
     * If nodeid is provided, we only abandon a package if it's for rep_wtxid and being downloaded
     * specifically from this peer. Otherwise, abandon unconditionally. */
    void AbandonPackageToDownload(const uint256& rep_wtxid, std::optional<NodeId> nodeid)
    {
        if (m_packages_downloading.count(rep_wtxid) == 0) return;
        auto& package = m_packages_downloading.at(rep_wtxid);
        // If a nodeid is provided, we only abandon if we are downloading from this peer.
        if (nodeid.has_value() && package.m_peer != *nodeid) return;
        for (const auto& [request_id, _] : package.m_requests) {
            m_package_download_requests.erase(request_id);
        }
        m_packages_downloading.erase(rep_wtxid);
    }
    bool OrphanageAddTx(const CTransactionRef& tx, NodeId peer) { return m_orphanage.AddTx(tx, peer); }
    bool OrphanageHaveTx(const GenTxid& gtxid) { return m_orphanage.HaveTx(gtxid); }
    CTransactionRef OrphanageGetTxToReconsider(NodeId peer) { return m_orphanage.GetTxToReconsider(peer); }
    void ConnectedPeer(NodeId peer, const ConnectionInfo& info)
    {
        Assume(m_peer_info.count(peer) == 0);
        m_peer_info.emplace(peer, PeerInfo(info));
        if (info.m_wtxid_relay) m_num_wtxid_peers += 1;
    }
    void DisconnectedPeer(NodeId peer) {
        const auto peer_orphans = m_orphanage.EraseForPeer(peer);
        for (const auto& wtxid : peer_orphans) {
            AbandonPackageToDownload(wtxid, peer);
        }
        m_txrequest.DisconnectedPeer(peer);

        m_orphan_resolution_tracker.DisconnectedPeer(peer);

        if (m_peer_info.count(peer) == 0) return;
        if (m_peer_info.at(peer).m_connection_info.m_wtxid_relay) {
            if (Assume(m_num_wtxid_peers > 0)) m_num_wtxid_peers -= 1;
        }
        m_peer_info.erase(peer);
    }
    void BlockConnected(const CBlock& block) {
        for (const auto& wtxid: m_orphanage.EraseForBlock(block)) {
            AbandonPackageToDownload(wtxid, /*nodeid=*/std::nullopt);
        }
        for (const auto& ptx: block.vtx) {
            m_txrequest.ForgetTxHash(ptx->GetHash());
            m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
            // All hashes in orphan request tracker are wtxid.
            m_orphan_resolution_tracker.ForgetTxHash(ptx->GetWitnessHash());
            m_recent_confirmed_transactions.insert(ptx->GetWitnessHash());
            if (ptx->GetHash() != ptx->GetWitnessHash()) {
                m_recent_confirmed_transactions.insert(ptx->GetHash());
            }
        }
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
        AbandonPackageToDownload(tx->GetWitnessHash(), /*nodeid=*/std::nullopt);
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
            if (std::any_of(tx->vin.cbegin(), tx->vin.cend(), [&](const auto& input)
                { return m_recent_rejects.contains(input.prevout.hash); })) {
                LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s\n",tx->GetHash().ToString());
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
        AbandonPackageToDownload(tx->GetWitnessHash(), /*nodeid=*/std::nullopt);
        m_orphan_resolution_tracker.ForgetTxHash(tx->GetWitnessHash());
        return false;
    }
    bool OrphanageHaveTxToReconsider(NodeId peer) { return m_orphanage.HaveTxToReconsider(peer); }
    size_t OrphanageSize() { return m_orphanage.Size(); }
    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
    {
        if (!Assume(m_peer_info.count(peer) > 0)) return;
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

    void TxRequestForgetTxHash(const uint256& txhash)
    {
        m_txrequest.ForgetTxHash(txhash);
    }

    std::vector<GenTxid> TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
        std::vector<std::pair<NodeId, GenTxid>>* expired)
    {
        // Orphan Resolution Tracker
        std::vector<std::pair<NodeId, GenTxid>> expired_orphan_resolution;
        const auto orphans_ready_to_request = m_orphan_resolution_tracker.GetRequestable(peer, now, &expired_orphan_resolution);
        // Expire orphan resolution attempts
        for (const auto& [nodeid, orphan_gtxid] : expired_orphan_resolution) {
            // All txhashes in m_orphan_resolution_tracker are wtxids.
            Assume(orphan_gtxid.IsWtxid());
            AbandonPackageToDownload(orphan_gtxid.GetHash(), nodeid);
            m_orphanage.EraseOrphanOfPeer(orphan_gtxid.GetHash(), nodeid);
        }
        for (const auto& orphan_gtxid : orphans_ready_to_request) {
            Assume(orphan_gtxid.IsWtxid());
            const bool still_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(orphan_gtxid.GetHash()))};
            if (still_in_orphanage) {
                // Get PackageToDownload. If it doesn't exist, skip.
                if (m_packages_downloading.count(orphan_gtxid.GetHash()) == 0) break;
                auto iter = m_packages_downloading.find(orphan_gtxid.GetHash());

                for (const auto& [txid, status]: iter->second.m_requests) {
                    // Here, we only have the txid (and not wtxid) of the
                    // inputs, so we only request in txid mode, even for
                    // wtxidrelay peers.
                    // Eventually we should replace this with an improved
                    // protocol for getting all unconfirmed parents.
                    // These parents have already been filtered using AlreadyHaveTx, so we don't need to
                    // check m_recent_rejects and m_recent_confirmed_transactions. Schedule this
                    // request with no delay; it should immediately show up in GetRequestable below
                    // unless there is already a request out for this transaction.
                    ReceivedTxInv(peer, GenTxid::Txid(txid), now);
                    const auto request_id{GetTxRequestId(peer, txid)};
                    package.RequestScheduled(request_id);
                    m_package_download_requests.emplace(request_id, iter);
                }
            }
        
        }
        return m_txrequest.GetRequestable(peer, now, expired);
    }

    void TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
    {
        // Check if this request pertains to a package.
        const auto orphan_parent_request_id{GetTxRequestId(peer, txhash)};
        if (m_package_download_requests.count(orphan_parent_request_id) > 0) {
            auto iter = m_package_download_requests.at(orphan_parent_request_id);
            // The PackageToDownload should have record fo this scheduled request.
            iter->second.RequestSent(orphan_parent_request_id);
            Assume(m_orphanage.HaveTx(GenTxid::Wtxid(iter->second.m_rep_wtxid)));
        }
        m_txrequest.RequestedTx(peer, txhash, expiry);
    }

    void ReceivedResponse(NodeId peer, const uint256& txhash, bool notfound)
    {
        // Check if this request pertains to a package.
        const auto orphan_parent_request_id{GetTxRequestId(peer, txhash)};
        if (m_package_download_requests.count(orphan_parent_request_id) > 0) {
            auto iter = m_package_download_requests.at(orphan_parent_request_id);
            // The PackageToDownload should have record fo this scheduled request.
            Assume(iter->second.m_requests.count(orphan_parent_request_id) > 0);
            Assume(m_orphanage.HaveTx(GenTxid::Wtxid(iter->second.m_rep_wtxid)));
            if (notfound) {
                const auto& orphan_wtxid = iter->second.m_rep_wtxid;
                // Abandon trying to resolve this orphan with this peer.
                AbandonPackageToDownload(orphan_wtxid, peer);
                m_orphanage.EraseOrphanOfPeer(orphan_wtxid, peer);
                // Record the notfound to make progress resolving this orphan. We know this
                // peer can't help us get the parent(s), so we can move on to other peers.
                m_orphan_resolution_tracker.ReceivedResponse(peer, orphan_wtxid);
            }
        }
        m_txrequest.ReceivedResponse(peer, txhash);
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

    void RecentConfirmedReset() { m_recent_confirmed_transactions.reset(); }
    bool ShouldReject(const GenTxid& gtxid, const uint256& blockhash)
    {
        if (blockhash != hashRecentRejectsChainTip) {
            // If the chain tip has changed previously rejected transactions
            // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
            // or a double-spend. Reset the rejects filter and give those
            // txs a second chance.
            hashRecentRejectsChainTip = blockhash;
            m_recent_rejects.reset();
        }
        if (m_orphanage.HaveTx(gtxid)) return true;
        if (m_recent_confirmed_transactions.contains(gtxid.GetHash())) return true;
        if (m_recent_rejects.contains(gtxid.GetHash())) return true;
        return false;
    }
    bool NewOrphanTx(const CTransactionRef& tx, const std::vector<uint256>& parent_txids, NodeId nodeid,
                     std::chrono::microseconds now)
    {
        const bool already_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(tx->GetWitnessHash()))};

        // Once added to the orphan pool, a tx is considered AlreadyHave, and we shouldn't request it anymore.
        m_txrequest.ForgetTxHash(tx->GetHash());
        m_txrequest.ForgetTxHash(tx->GetWitnessHash());

        // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789).
        // This may decide to evict the new orphan.
        const auto expired_orphans = m_orphanage.LimitOrphans(m_max_orphan_txs);
        for (const auto& wtxid : expired_orphans) AbandonPackageToDownload(wtxid, /*nodeid=*/std::nullopt);

        const bool still_in_orphanage{m_orphanage.HaveTx(GenTxid::Wtxid(tx->GetWitnessHash()))};
        if (still_in_orphanage) {
            const auto [_, success] = m_packages_downloading.emplace(tx->GetWitnessHash(),
                PackageToDownload{nodeid, tx->GetWitnessHash(), parent_txids});
            // if success=false, somehow we are already trying to download a package for this tx.
            if (Assume(success)) {
                // Add these requests to m_package_download_requests
                for (const uint256& parent_txid : parent_txids) {
                    const auto request_id{GetTxRequestId(nodeid, parent_txid)};
                }
            }
        }
        return !already_in_orphanage && still_in_orphanage;
    }
};

TxDownloadManager::TxDownloadManager(uint32_t max_orphan_txs) : m_impl{std::make_unique<TxDownloadManager::Impl>(max_orphan_txs)} {}
TxDownloadManager::~TxDownloadManager() = default;

bool TxDownloadManager::NewOrphanTx(const CTransactionRef& tx, const std::vector<uint256>& parent_txids, NodeId nodeid,
    std::chrono::microseconds now) { return m_impl->NewOrphanTx(tx, parent_txids, nodeid, now); }
CTransactionRef TxDownloadManager::OrphanageGetTxToReconsider(NodeId peer) { return m_impl->OrphanageGetTxToReconsider(peer); }
bool TxDownloadManager::OrphanageHaveTxToReconsider(NodeId peer) { return m_impl->OrphanageHaveTxToReconsider(peer); }
size_t TxDownloadManager::OrphanageSize() { return m_impl->OrphanageSize(); }
void TxDownloadManager::ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
    { return m_impl->ReceivedTxInv(peer, gtxid, now); }
void TxDownloadManager::BlockConnected(const CBlock& block) { m_impl->BlockConnected(block); }
void TxDownloadManager::ConnectedPeer(NodeId peer, const ConnectionInfo& info) { m_impl->ConnectedPeer(peer, info); }
void TxDownloadManager::DisconnectedPeer(NodeId peer) { m_impl->DisconnectedPeer(peer); }
void TxDownloadManager::MempoolAcceptedTx(const CTransactionRef& tx) { m_impl->MempoolAcceptedTx(tx); }
bool TxDownloadManager::MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result) { return m_impl->MempoolRejectedTx(tx, result); }
void TxDownloadManager::TxRequestForgetTxHash(const uint256& txhash) { m_impl->TxRequestForgetTxHash(txhash); }
std::vector<GenTxid> TxDownloadManager::TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
    std::vector<std::pair<NodeId, GenTxid>>* expired) { return m_impl->TxRequestGetRequestable(peer, now, expired); }
void TxDownloadManager::TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
    { m_impl->TxRequestRequestedTx(peer, txhash, expiry); }
void TxDownloadManager::ReceivedResponse(NodeId peer, const uint256& txhash, bool notfound) { m_impl->ReceivedResponse(peer, txhash, notfound); }
size_t TxDownloadManager::TxRequestCount(NodeId peer) const { return m_impl->TxRequestCount(peer); }
size_t TxDownloadManager::TxRequestSize() const { return m_impl->TxRequestSize(); }
void TxDownloadManager::RecentConfirmedReset() { m_impl->RecentConfirmedReset(); }
bool TxDownloadManager::ShouldReject(const GenTxid& gtxid, const uint256& blockhash) { return m_impl->ShouldReject(gtxid, blockhash); }
} // namespace node
