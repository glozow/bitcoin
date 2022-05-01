// Copyright (c) 2023
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownload_impl.h>

namespace node {
TxOrphanage& TxDownloadImpl::GetOrphanageRef() { return m_orphanage; }
TxRequestTracker& TxDownloadImpl::GetTxRequestRef() { return m_txrequest; }
} // namespace node
