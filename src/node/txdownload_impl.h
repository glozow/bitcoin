// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NODE_TXDOWNLOAD_IMPL_H
#define BITCOIN_NODE_TXDOWNLOAD_IMPL_H

#include <net.h>
#include <txorphanage.h>
#include <txrequest.h>

namespace node {
class TxDownloadImpl {
public:
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;
    /** Tracks candidates for requesting and downloading transaction data. */
    TxRequestTracker m_txrequest;

    TxDownloadImpl() = default;

    TxOrphanage& GetOrphanageRef();

    TxRequestTracker& GetTxRequestRef();
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOAD_IMPL_H
