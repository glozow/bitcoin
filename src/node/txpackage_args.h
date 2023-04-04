// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXPACKAGE_ARGS_H
#define BITCOIN_NODE_TXPACKAGE_ARGS_H

#include <node/txpackagetracker.h>
class ArgsManager;

/**
 * Overlay the options set in \p argsman on top of corresponding members in \p options.
 * Returns an error if one was encountered.
 *
 * @param[in]  argsman    The ArgsManager in which to check set options.
 * @param[in,out] options The TxPackageTracker Options to modify according to \p argsman.
 */
void ApplyArgsManOptions(const ArgsManager& argsman, node::TxPackageTracker::Options& options);


#endif // BITCOIN_NODE_TXPACKAGE_ARGS_H
