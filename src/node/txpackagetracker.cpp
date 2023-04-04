// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackagetracker.h>

namespace node {
    /** How long to wait before requesting orphan ancpkginfo/parents from an additional peer.
     * Same as GETDATA_TX_INTERVAL. */
    static constexpr auto ORPHAN_ANCESTOR_GETDATA_INTERVAL{60s};
class TxPackageTracker::Impl {
    /** Whether package relay is enabled. When false, the tracker does basic orphan handling. */
    const bool m_enable_package_relay;
    /** Maximum number of transactions in orphanage. */
    const unsigned int m_max_orphan_count;

public:
    Impl(const TxPackageTracker::Options& opts) :
        m_enable_package_relay{opts.enable_package_relay},
        m_max_orphan_count{opts.max_orphan_count}
    {}
};

TxPackageTracker::TxPackageTracker(const TxPackageTracker::Options& opts) : m_impl{std::make_unique<TxPackageTracker::Impl>(opts)} {}
TxPackageTracker::~TxPackageTracker() = default;

} // namespace node
