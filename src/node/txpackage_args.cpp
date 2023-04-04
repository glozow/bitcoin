// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txpackage_args.h>

#include <util/system.h>

void ApplyArgsManOptions(const ArgsManager& argsman, node::TxPackageTracker::Options& options)
{
    options.max_orphan_count = (unsigned int)std::max((int64_t)0, argsman.GetIntArg("-maxorphantx", node::DEFAULT_MAX_ORPHAN_TRANSACTIONS));
}
