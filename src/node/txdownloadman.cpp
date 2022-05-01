// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownloadman.h>

namespace node {
class TxDownloadManager::Impl {
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;
    /** Tracks candidates for requesting and downloading transaction data. */
    TxRequestTracker m_txrequest;
public:
    Impl() = default;

    TxOrphanage& GetOrphanageRef() { return m_orphanage; }

    TxRequestTracker& GetTxRequestRef() { return m_txrequest; }
};

TxDownloadManager::TxDownloadManager() : m_impl{std::make_unique<TxDownloadManager::Impl>()} {}
TxDownloadManager::~TxDownloadManager() = default;

TxOrphanage& TxDownloadManager::GetOrphanageRef() { return m_impl->GetOrphanageRef(); }
TxRequestTracker& TxDownloadManager::GetTxRequestRef() { return m_impl->GetTxRequestRef(); }
} // namespace node
