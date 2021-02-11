// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PACKAGES_H
#define BITCOIN_PACKAGES_H

#include <consensus/validation.h>
#include <primitives/transaction.h>

/** Default maximum number of transactions in a package. */
static const unsigned int MAX_PACKAGE_COUNT = 25;
/** Default maximum total virtual size of transactions in a package in KvB. */
static const unsigned int MAX_PACKAGE_SIZE = 101;

/** A "reason" why a package was invalid. It may be that one or more of the included
 * transactions is invalid or the package itself violates our rules.
 * We don't distinguish between consensus and policy validity right now.
 */
enum class PackageValidationResult {
    PCKG_RESULT_UNSET = 0,        //!< Initial value. The package has not yet been rejected.
    PCKG_POLICY,                  //!< The package itself is invalid (e.g. too many transactions).
    PCKG_TX,                      //!< At least one tx is invalid.
};

// Alias with the possibility of having other members in the future.
using Package = std::vector<CTransactionRef>;

class PackageValidationState : public ValidationState<PackageValidationResult> {};

#endif // BITCOIN_PACKAGES_H
