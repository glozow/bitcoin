// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/txmempool.h>

#include <chainparams.h>
#include <node/context.h>
#include <node/mempool_args.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

using node::NodeContext;

CTxMemPool::Options MemPoolOptionsForTest(const NodeContext& node)
{
    CTxMemPool::Options mempool_opts{
        .estimator = node.fee_estimator.get(),
        // Default to always checking mempool regardless of
        // chainparams.DefaultConsistencyChecks for tests
        .check_ratio = 1,
    };
    const auto result{ApplyArgsManOptions(*node.args, ::Params(), mempool_opts)};
    Assert(result);
    return mempool_opts;
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CMutableTransaction& tx) const
{
    return FromTx(MakeTransactionRef(tx));
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CTransactionRef& tx) const
{
    return CTxMemPoolEntry{tx, nFee, TicksSinceEpoch<std::chrono::seconds>(time), nHeight, m_sequence, spendsCoinbase, sigOpCost, lp};
}

/** Helper for CheckPackageMempoolAcceptResult. Combines population of error string and return statement. */
static bool Err(std::string& err_msg, const std::string& err_msg_to_copy)
{
    err_msg = err_msg_to_copy;
    return false;
}

bool CheckPackageMempoolAcceptResult(const Package& txns, const PackageMempoolAcceptResult& result, bool expect_valid,
                                     const CTxMemPool* mempool, std::string& s)
{
    if (expect_valid) {
        if (result.m_state.IsInvalid()) {
            return Err(s, strprintf("Package validation unexpectedly failed: %s", result.m_state.ToString()));
        }
    } else {
        if (result.m_state.IsValid()) {
            return Err(s, strprintf("Package validation unexpectedly succeeded. %s", result.m_state.ToString()));
        }
    }
    if (result.m_state.GetResult() != PackageValidationResult::PCKG_POLICY && txns.size() != result.m_tx_results.size()) {
        return Err(s, strprintf("txns size %u does not match tx results size %u", txns.size(), result.m_tx_results.size()));
    }
    for (const auto& tx : txns) {
        const auto& wtxid = tx->GetWitnessHash();
        if (result.m_tx_results.count(wtxid) == 0) {
            return Err(s, strprintf("result not found for tx %s", wtxid.ToString()));
        }

        const auto& atmp_result = result.m_tx_results.at(wtxid);
        const bool valid{atmp_result.m_result_type == MempoolAcceptResult::ResultType::VALID};
        if (expect_valid && atmp_result.m_state.IsInvalid()) {
            return Err(s, strprintf("tx %s unexpectedly failed: %s", wtxid.ToString(), atmp_result.m_state.ToString()));
        }

        //m_replaced_transactions should exist iff the result was VALID
        if (atmp_result.m_replaced_transactions.has_value() != valid) {
            return Err(s, strprintf("tx %s result should %shave m_replaced_transactions",
                                    wtxid.ToString(), valid ? "" : "not "));
        }

        // m_vsize and m_base_fees should exist iff the result was VALID or MEMPOOL_ENTRY
        const bool mempool_entry{atmp_result.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY};
        if (atmp_result.m_base_fees.has_value() != (valid || mempool_entry)) {
            return Err(s, strprintf("tx %s result should %shave m_base_fees", wtxid.ToString(), valid || mempool_entry ? "" : "not "));
        }
        if (atmp_result.m_vsize.has_value() != (valid || mempool_entry)) {
            return Err(s, strprintf("tx %s result should %shave m_vsize", wtxid.ToString(), valid || mempool_entry ? "" : "not "));
        }

        // m_other_wtxid should exist iff the result was DIFFERENT_WITNESS
        const bool diff_witness{atmp_result.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS};
        if (atmp_result.m_other_wtxid.has_value() != diff_witness) {
            return Err(s, strprintf("tx %s result should %shave m_other_wtxid", wtxid.ToString(), diff_witness ? "" : "not "));
        }

        // m_effective_feerate and m_wtxids_fee_calculations should exist iff the result was valid or
        // the failure was TX_SINGLE_FAILURE
        const bool valid_or_single_failure{atmp_result.m_result_type == MempoolAcceptResult::ResultType::VALID ||
            atmp_result.m_state.GetResult() == TxValidationResult::TX_SINGLE_FAILURE};
        if (atmp_result.m_effective_feerate.has_value() != valid_or_single_failure) {
            return Err(s, strprintf("tx %s result should %shave m_effective_feerate",
                                    wtxid.ToString(), valid_or_single_failure ? "" : "not "));
        }
        if (atmp_result.m_wtxids_fee_calculations.has_value() != valid_or_single_failure) {
            return Err(s, strprintf("tx %s result should %shave m_effective_feerate",
                                    wtxid.ToString(), valid_or_single_failure ? "" : "not "));
        }

        if (mempool) {
            // The tx by txid should be in the mempool iff the result was not INVALID.
            const bool txid_in_mempool{atmp_result.m_result_type != MempoolAcceptResult::ResultType::INVALID};
            if (mempool->exists(GenTxid::Txid(tx->GetHash())) != txid_in_mempool) {
                return Err(s, strprintf("tx %s should %sbe in mempool", wtxid.ToString(), txid_in_mempool ? "" : "not "));
            }
            // Additionally, if the result was DIFFERENT_WITNESS, we shouldn't be able to find the tx in mempool by wtxid.
            if (tx->HasWitness() && atmp_result.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS) {
                if (mempool->exists(GenTxid::Wtxid(wtxid))) {
                    return Err(s, strprintf("wtxid %s should not be in mempool", wtxid.ToString()));
                }
            }
        }
    }
    return true;
}
