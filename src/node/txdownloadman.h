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
namespace node {

class TxDownloadManager {
    const std::unique_ptr<TxDownloadImpl> m_impl;

public:
    explicit TxDownloadManager() : m_impl{std::make_unique<TxDownloadImpl>()} {}

    /** Get reference to orphanage. */
    TxOrphanage& GetOrphanageRef() { return m_impl->GetOrphanageRef(); }
    /** Get reference to txrequest tracker. */
    TxRequestTracker& GetTxRequestRef() { return m_impl->GetTxRequestRef(); }
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
