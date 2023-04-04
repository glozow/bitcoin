// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXPACKAGETRACKER_H
#define BITCOIN_NODE_TXPACKAGETRACKER_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

namespace node {
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};

class TxPackageTracker {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    struct Options {
        bool enable_package_relay{DEFAULT_ENABLE_PACKAGE_RELAY};
        /** Maximum number of transactions in orphanage. Configured using -maxorphantx.*/
        unsigned int max_orphan_count{DEFAULT_MAX_ORPHAN_TRANSACTIONS};
    };
    TxPackageTracker(const Options& opts);
    ~TxPackageTracker();
};
} // namespace node
#endif // BITCOIN_NODE_TXPACKAGETRACKER_H
