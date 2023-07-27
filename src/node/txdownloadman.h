// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <net.h>

#include <cstdint>
#include <map>
#include <vector>

class TxOrphanage;
class TxRequestTracker;
enum class TxValidationResult;
namespace node {
/** Maximum number of in-flight transaction requests from a peer. It is not a hard limit, but the threshold at which
 *  point the OVERLOADED_PEER_TX_DELAY kicks in. */
static constexpr int32_t MAX_PEER_TX_REQUEST_IN_FLIGHT = 100;
/** Maximum number of transactions to consider for requesting, per peer. It provides a reasonable DoS limit to
 *  per-peer memory usage spent on announcements, while covering peers continuously sending INVs at the maximum
 *  rate (by our own policy, see INVENTORY_BROADCAST_PER_SECOND) for several minutes, while not receiving
 *  the actual transaction (from any peer) in response to requests for them. */
static constexpr int32_t MAX_PEER_TX_ANNOUNCEMENTS = 5000;
/** How long to delay requesting transactions via txids, if we have wtxid-relaying peers */
static constexpr auto TXID_RELAY_DELAY{2s};
/** How long to delay requesting transactions from non-preferred peers */
static constexpr auto NONPREF_PEER_TX_DELAY{2s};
/** How long to delay requesting transactions from overloaded peers (see MAX_PEER_TX_REQUEST_IN_FLIGHT). */
static constexpr auto OVERLOADED_PEER_TX_DELAY{2s};

class TxDownloadManager {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    TxDownloadManager() = delete;
    TxDownloadManager(uint32_t max_orphan_txs);
    ~TxDownloadManager();

    /** Add a new orphan transaction. Returns whether this orphan is going to be processed. */
    bool NewOrphanTx(const CTransactionRef& tx, const std::vector<uint256>& parent_txids, NodeId nodeid,
                     std::chrono::microseconds now);

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef OrphanageGetTxToReconsider(NodeId peer);

    /** Does this peer have any orphans to validate? */
    bool OrphanageHaveTxToReconsider(NodeId peer);

    /** Return how many entries exist in the orphange */
    size_t OrphanageSize();

    struct ConnectionInfo {
        /** Whether this peer is preferred for transaction download. */
        const bool m_preferred;
        /** Whether this peer has Relay permissions. */
        const bool m_relay_permissions;
        /** Whether this peer supports wtxid relay. */
        const bool m_wtxid_relay;
    };
    /** Should be called when a peer connects successfully (after verack). */
    void ConnectedPeer(NodeId peer, const ConnectionInfo& info);

    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId peer);

    /** Deletes all block and conflicted transactions from txrequest and orphanage. */
    void BlockConnected(const CBlock& block);

    /** Should be called whenever a transaction is submitted to mempool.
     * Erases the tx from orphanage, and forgets its txid and wtxid from txrequest.
     * Adds any orphan transactions depending on it to their respective peers' workset. */
    void MempoolAcceptedTx(const CTransactionRef& tx);

    /** Should be called whenever a transaction is rejected from mempool.
     * May add the transaction's txid and/or wtxid to recent_rejects depending on the rejection
     * result. Returns true if this transaction is an orphan who should be processed, false
     * otherwise. */
    bool MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result);

    /** Adds a new CANDIDATE announcement. */
    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now);

    /** Deletes all announcements for a given txhash (both txid and wtxid ones). */
    void TxRequestForgetTxHash(const uint256& txhash);

    /** Find the txids to request now from peer. */
    std::vector<GenTxid> TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
        std::vector<std::pair<NodeId, GenTxid>>* expired = nullptr);

    /** Marks a transaction as requested, with a specified expiry. */
    void TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry);

    /** Converts a CANDIDATE or REQUESTED announcement to a COMPLETED one. */
    void ReceivedResponse(NodeId peer, const uint256& txhash, bool notfound);

    /** Count how many announcements a peer has (REQUESTED, CANDIDATE, and COMPLETED combined). */
    size_t TxRequestCount(NodeId peer) const;

    /** Count how many announcements are being tracked in total across all peers and transaction hashes. */
    size_t TxRequestSize() const;

    /** Returns whether this txhash should be rejected, i.e. is in recent_rejects,
     * recent_confirmed_transactions, or orphanage. The recent_rejects filter will be reset if the
     * blockhash does not match hashRecentRejectsChainTip. */
    bool ShouldReject(const GenTxid& gtxid, const uint256& blockhash);

    /** Should be called when block is disconnected. Resets recent_confirmed_transactions. */
    void RecentConfirmedReset();
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
