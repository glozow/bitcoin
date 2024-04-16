// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <node/txdownload_impl.h>

#include <cstdint>
#include <map>
#include <vector>

class TxOrphanage;
class TxRequestTracker;
class CBlockIndex;
enum class ChainstateRole;
namespace node {

class TxDownloadManager {
    const std::unique_ptr<TxDownloadImpl> m_impl;

public:
    explicit TxDownloadManager(const TxDownloadOptions& options) : m_impl{std::make_unique<TxDownloadImpl>(options)} {}

    // Get references to internal data structures. Outside access to these data structures should be
    // temporary and removed later once logic has been moved internally.
    TxOrphanage& GetOrphanageRef() { return m_impl->m_orphanage; }
    TxRequestTracker& GetTxRequestRef() { return m_impl->m_txrequest; }
    CRollingBloomFilter& GetRecentRejectsRef() { return m_impl->m_recent_rejects; }
    CRollingBloomFilter& GetRecentRejectsReconsiderableRef() { return m_impl->m_recent_rejects_reconsiderable; }
    CRollingBloomFilter& GetRecentConfirmedRef() { return m_impl->m_recent_confirmed_transactions; }

    // Responses to chain events. TxDownloadManager is not an actual client of ValidationInterface, these are called through PeerManager.
    void UpdatedBlockTipSync() { return m_impl->UpdatedBlockTipSync(); }
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock) {
        return m_impl->BlockConnected(pblock);
    }
    void BlockDisconnected() {
        return m_impl->BlockDisconnected();
    }
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
