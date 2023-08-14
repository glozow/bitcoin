// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <logging.h>
#include <node/txdownloadman.h>
#include <sync.h>
#include <txmempool.h>

namespace node {
class TxDownloadManager::Impl {
    const Options m_opts;

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
    mutable Mutex m_recent_confirmed_transactions_mutex;
    CRollingBloomFilter m_recent_confirmed_transactions GUARDED_BY(m_recent_confirmed_transactions_mutex){48'000, 0.000'001};

public:
    Impl(const Options& opts) : m_opts{opts} {}

    TxOrphanage& GetOrphanageRef() { return m_orphanage; }

    TxRequestTracker& GetTxRequestRef() { return m_txrequest; }

    void DisconnectedPeer(NodeId nodeid)
    {
        m_orphanage.EraseForPeer(nodeid);
        m_txrequest.DisconnectedPeer(nodeid);
    }

    void BlockConnected(const CBlock& block, const uint256& tiphash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
    {
        LOCK(m_recent_confirmed_transactions_mutex);
        m_orphanage.EraseForBlock(block);
        for (const auto& ptx : block.vtx) {
            m_txrequest.ForgetTxHash(ptx->GetHash());
            m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
            m_recent_confirmed_transactions.insert(ptx->GetHash());
            if (ptx->GetHash() != ptx->GetWitnessHash()) {
                m_recent_confirmed_transactions.insert(ptx->GetWitnessHash());
            }
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
};

TxDownloadManager::TxDownloadManager(const TxDownloadManager::Options& opts) :
    m_impl{std::make_unique<TxDownloadManager::Impl>(opts)} {}
TxDownloadManager::~TxDownloadManager() = default;

TxOrphanage& TxDownloadManager::GetOrphanageRef() { return m_impl->GetOrphanageRef(); }
TxRequestTracker& TxDownloadManager::GetTxRequestRef() { return m_impl->GetTxRequestRef(); }

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
} // namespace node
