// Copyright (c) 2023
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownload_impl.h>

namespace node {
TxOrphanage& TxDownloadImpl::GetOrphanageRef() { return m_orphanage; }
TxRequestTracker& TxDownloadImpl::GetTxRequestRef() { return m_txrequest; }

void TxDownloadImpl::DisconnectedPeer(NodeId nodeid)
{
    m_orphanage.EraseForPeer(nodeid);
    m_txrequest.DisconnectedPeer(nodeid);
}

void TxDownloadImpl::BlockConnected(const CBlock& block, const uint256& tiphash)
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

void TxDownloadImpl::BlockDisconnected() EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
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

void TxDownloadImpl::MempoolAcceptedTx(const CTransactionRef& tx)
{
    m_orphanage.AddChildrenToWorkSet(*tx);
    // As this version of the transaction was acceptable, we can forget about any requests for it.
    // No-op if the tx is not in txrequest.
    m_txrequest.ForgetTxHash(tx->GetHash());
    m_txrequest.ForgetTxHash(tx->GetWitnessHash());
    // If it came from the orphanage, remove it. No-op if the tx is not in txorphanage.
    m_orphanage.EraseTx(tx->GetWitnessHash());
}

bool TxDownloadImpl::MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result)
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
    return false;
}

bool TxDownloadImpl::AlreadyHaveTx(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex)
{
    const uint256& hash = gtxid.GetHash();

    if (m_orphanage.HaveTx(gtxid)) return true;

    {
        LOCK(m_recent_confirmed_transactions_mutex);
        if (m_recent_confirmed_transactions.contains(hash)) return true;
    }

    return m_recent_rejects.contains(hash) || m_opts.m_mempool_ref.exists(gtxid);
}
} // namespace node
