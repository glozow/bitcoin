// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TX_PKG_RELAY_H
#define BITCOIN_TX_PKG_RELAY_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

static constexpr bool DEFAULT_ENABLE_PACKAGE_RELAY{false};

class TxPackageTracker {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxPackageTracker();
    ~TxPackageTracker();
};

#endif // BITCOIN_TX_PKG_RELAY_H
