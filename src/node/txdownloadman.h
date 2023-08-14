// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <node/txdownload_impl.h>

#include <cstdint>
#include <map>
#include <vector>

class CTxMemPool;
class TxOrphanage;
class TxRequestTracker;
enum class TxValidationResult;
namespace node {

class TxDownloadManager {
    const std::unique_ptr<TxDownloadImpl> m_impl;

public:
    explicit TxDownloadManager(const TxDownloadOptions& options) : m_impl{std::make_unique<TxDownloadImpl>(options)} {}
    ~TxDownloadManager() = default;

    /** Get reference to orphanage. */
    TxOrphanage& GetOrphanageRef() { return m_impl->GetOrphanageRef(); }
    /** Get reference to txrequest tracker. */
    TxRequestTracker& GetTxRequestRef() { return m_impl->GetTxRequestRef(); }

    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId nodeid) { m_impl->DisconnectedPeer(nodeid); }

    /** Resets rejections cache. */
    void UpdatedBlockTipSync() {
        return m_impl->UpdatedBlockTipSync();
    }

    /** Deletes all block and conflicted transactions from txrequest and orphanage. */
    void BlockConnected(const CBlock& block, const uint256& tiphash) {
        return m_impl->BlockConnected(block, tiphash);
    }

    /** Should be called when a peer is disconnected. */
    void BlockDisconnected() { m_impl->BlockDisconnected(); }

    /** Should be called whenever a transaction is submitted to mempool. */
    void MempoolAcceptedTx(const CTransactionRef& tx) { m_impl->MempoolAcceptedTx(tx); }

    /** Should be called whenever a transaction is rejected from mempool for any reason. */
    bool MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result) {
        return m_impl->MempoolRejectedTx(tx, result);
    }

    /** Whether this transaction is found in orphanage, recently confirmed, or recently rejected transactions. */
    bool AlreadyHaveTx(const GenTxid& gtxid) const { return m_impl->AlreadyHaveTx(gtxid); }
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
