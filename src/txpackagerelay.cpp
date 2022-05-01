// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txpackagerelay.h>

class TxPackageTracker::Impl {
public:
};

TxPackageTracker::TxPackageTracker() : m_impl{std::make_unique<TxPackageTracker::Impl>()} {}
TxPackageTracker::~TxPackageTracker() = default;

