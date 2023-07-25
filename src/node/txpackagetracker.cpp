// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackagetracker.h>

#include <txorphanage.h>
#include <txrequest.h>

namespace node {
class TxPackageTracker::Impl {
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;
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

public:
    Impl() = default;

    bool OrphanageAddTx(const CTransactionRef& tx, NodeId peer) { return m_orphanage.AddTx(tx, peer); }
    bool OrphanageHaveTx(const GenTxid& gtxid) { return m_orphanage.HaveTx(gtxid); }
    CTransactionRef OrphanageGetTxToReconsider(NodeId peer) { return m_orphanage.GetTxToReconsider(peer); }
    int OrphanageEraseTx(const uint256& wtxid) { return m_orphanage.EraseTx(wtxid); }
    void DisconnectedPeer(NodeId peer) {
        m_orphanage.EraseForPeer(peer);
    }
    void BlockConnected(const CBlock& block) {
        m_orphanage.EraseForBlock(block);
        for (const auto& ptx: block.vtx) {
            m_txrequest.ForgetTxHash(ptx->GetHash());
            m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
            m_recent_confirmed_transactions.insert(ptx->GetWitnessHash());
            if (ptx->GetHash() != ptx->GetWitnessHash()) {
                m_recent_confirmed_transactions.insert(ptx->GetHash());
            }
        }
    }
    void MempoolAcceptedTx(const CTransactionRef& tx)
    {
        m_txrequest.ForgetTxHash(tx->GetHash());
        m_txrequest.ForgetTxHash(tx->GetWitnessHash());
        m_orphanage.AddChildrenToWorkSet(*tx);
        m_orphanage.EraseTx(tx->GetWitnessHash());
    }
    void OrphanageLimitOrphans(unsigned int max_orphans) { m_orphanage.LimitOrphans(max_orphans); }
    bool OrphanageHaveTxToReconsider(NodeId peer) { return m_orphanage.HaveTxToReconsider(peer); }
    size_t OrphanageSize() { return m_orphanage.Size(); }
    void TxRequestReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred, std::chrono::microseconds reqtime)
    {
        m_txrequest.ReceivedInv(peer, gtxid, preferred, reqtime);
    }

    void TxRequestForgetTxHash(const uint256& txhash)
    {
        m_txrequest.ForgetTxHash(txhash);
    }

    std::vector<GenTxid> TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
        std::vector<std::pair<NodeId, GenTxid>>* expired)
    {
        return m_txrequest.GetRequestable(peer, now, expired);
    }

    void TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
    {
        m_txrequest.RequestedTx(peer, txhash, expiry);
    }

    void TxRequestReceivedResponse(NodeId peer, const uint256& txhash)
    {
        m_txrequest.ReceivedResponse(peer, txhash);
    }

    /** Count how many REQUESTED announcements a peer has. */
    size_t TxRequestCountInFlight(NodeId peer) const
    {
        return m_txrequest.CountInFlight(peer);
    }

    /** Count how many CANDIDATE announcements a peer has. */
    size_t TxRequestCountCandidates(NodeId peer) const
    {
        return m_txrequest.CountCandidates(peer);
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

    bool RecentRejectsContains(const uint256& hash) { return m_recent_rejects.contains(hash); }
    void RecentRejectsInsert(const uint256& hash) { m_recent_rejects.insert(hash); }
    void MaybeResetRecentRejects(const uint256& blockhash)
    {
        if (blockhash != hashRecentRejectsChainTip) {
            // If the chain tip has changed previously rejected transactions
            // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
            // or a double-spend. Reset the rejects filter and give those
            // txs a second chance.
            hashRecentRejectsChainTip = blockhash;
            m_recent_rejects.reset();
        }
    }
    bool RecentConfirmedContains(const uint256& hash) { return m_recent_confirmed_transactions.contains(hash); }
    void RecentConfirmedInsert(const uint256& hash) { m_recent_confirmed_transactions.insert(hash); }
    void RecentConfirmedReset() { m_recent_confirmed_transactions.reset(); }
};

TxPackageTracker::TxPackageTracker() : m_impl{std::make_unique<TxPackageTracker::Impl>()} {}
TxPackageTracker::~TxPackageTracker() = default;

bool TxPackageTracker::OrphanageAddTx(const CTransactionRef& tx, NodeId peer) { return m_impl->OrphanageAddTx(tx, peer); }
bool TxPackageTracker::OrphanageHaveTx(const GenTxid& gtxid) { return m_impl->OrphanageHaveTx(gtxid); }
CTransactionRef TxPackageTracker::OrphanageGetTxToReconsider(NodeId peer) { return m_impl->OrphanageGetTxToReconsider(peer); }
int TxPackageTracker::OrphanageEraseTx(const uint256& txid) { return m_impl->OrphanageEraseTx(txid); }
void TxPackageTracker::OrphanageLimitOrphans(unsigned int max_orphans) { m_impl->OrphanageLimitOrphans(max_orphans); }
bool TxPackageTracker::OrphanageHaveTxToReconsider(NodeId peer) { return m_impl->OrphanageHaveTxToReconsider(peer); }
size_t TxPackageTracker::OrphanageSize() { return m_impl->OrphanageSize(); }
void TxPackageTracker::TxRequestReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred, std::chrono::microseconds reqtime)
    { return m_impl->TxRequestReceivedInv(peer, gtxid, preferred, reqtime); }
void TxPackageTracker::BlockConnected(const CBlock& block) { m_impl->BlockConnected(block); }
void TxPackageTracker::DisconnectedPeer(NodeId peer) { m_impl->DisconnectedPeer(peer); }
void TxPackageTracker::MempoolAcceptedTx(const CTransactionRef& tx) { m_impl->MempoolAcceptedTx(tx); }
void TxPackageTracker::TxRequestForgetTxHash(const uint256& txhash) { m_impl->TxRequestForgetTxHash(txhash); }
std::vector<GenTxid> TxPackageTracker::TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
    std::vector<std::pair<NodeId, GenTxid>>* expired) { return m_impl->TxRequestGetRequestable(peer, now, expired); }
void TxPackageTracker::TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
    { m_impl->TxRequestRequestedTx(peer, txhash, expiry); }
void TxPackageTracker::TxRequestReceivedResponse(NodeId peer, const uint256& txhash) { m_impl->TxRequestReceivedResponse(peer, txhash); }
size_t TxPackageTracker::TxRequestCountInFlight(NodeId peer) const { return m_impl->TxRequestCountInFlight(peer); }
size_t TxPackageTracker::TxRequestCountCandidates(NodeId peer) const { return m_impl->TxRequestCountCandidates(peer); }
size_t TxPackageTracker::TxRequestCount(NodeId peer) const { return m_impl->TxRequestCount(peer); }
size_t TxPackageTracker::TxRequestSize() const { return m_impl->TxRequestSize(); }
bool TxPackageTracker::RecentRejectsContains(const uint256& hash) const { return m_impl->RecentRejectsContains(hash); }
void TxPackageTracker::RecentRejectsInsert(const uint256& hash) { m_impl->RecentRejectsInsert(hash); }
void TxPackageTracker::MaybeResetRecentRejects(const uint256& blockhash) { m_impl->MaybeResetRecentRejects(blockhash); }
bool TxPackageTracker::RecentConfirmedContains(const uint256& hash) const { return m_impl->RecentConfirmedContains(hash); }
void TxPackageTracker::RecentConfirmedReset() { m_impl->RecentConfirmedReset(); }
} // namespace node
