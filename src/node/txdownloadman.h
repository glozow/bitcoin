// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <net.h>
#include <txorphanage.h>
#include <txrequest.h>

#include <cstdint>
#include <map>
#include <vector>

class TxOrphanage;
class TxRequestTracker;
namespace node {

class TxDownloadManager {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxDownloadManager();
    ~TxDownloadManager();

    /** Get reference to orphanage. */
    TxOrphanage& GetOrphanageRef();

    /** Get reference to txrequest tracker. */
    TxRequestTracker& GetTxRequestRef();
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
