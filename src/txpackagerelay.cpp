// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txpackagerelay.h>

class TxPackageTracker::Impl {
    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage& orphanage_ref;
public:
    Impl(TxOrphanage& orphanage) : orphanage_ref{orphanage} {}
};

TxPackageTracker::TxPackageTracker(TxOrphanage& orphanage) : m_impl{std::make_unique<TxPackageTracker::Impl>(orphanage)} {}
TxPackageTracker::~TxPackageTracker() = default;

