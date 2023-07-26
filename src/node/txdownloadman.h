// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <net.h>
#include <txorphanage.h>
#include <txrequest.h>

#include <cstdint>
#include <map>
#include <vector>

class CTxMemPool;
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
/** How long to wait before downloading a transaction from an additional peer */
static constexpr auto GETDATA_TX_INTERVAL{60s};

class TxDownloadManager {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    struct Options {
        /** Global maximum number of orphan transactions to keep. Enforced with LimitOrphans. */
        uint32_t m_max_orphan_txs;
        /** Read-only reference to mempool. */
        const CTxMemPool& m_mempool_ref;
    };

    explicit TxDownloadManager(const Options& options);
    ~TxDownloadManager();

    /** Get reference to orphanage. */
    TxOrphanage& GetOrphanageRef();

    /** Get reference to txrequest tracker. */
    TxRequestTracker& GetTxRequestRef();

    struct ConnectionInfo {
        /** Whether this peer is preferred for transaction download. */
        const bool m_preferred;
        /** Whether this peer has Relay permissions. */
        const bool m_relay_permissions;
        /** Whether this peer supports wtxid relay. */
        const bool m_wtxid_relay;
    };
    /** New peer successfully completed handshake. */
    void ConnectedPeer(NodeId nodeid, const ConnectionInfo& info);

    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId nodeid);

    /** Deletes all block and conflicted transactions from txrequest and orphanage. */
    void BlockConnected(const CBlock& block, const uint256& tiphash);

    /** Resets recently confirmed filter. */
    void BlockDisconnected();

    /** Should be called whenever a transaction is submitted to mempool.
     * Erases the tx from orphanage, and forgets its txid and wtxid from txrequest.
     * Adds any orphan transactions depending on it to their respective peers' workset. */
    void MempoolAcceptedTx(const CTransactionRef& tx);

    /** Should be called whenever a transaction is rejected from mempool.
     * May add the transaction's txid and/or wtxid to recent_rejects depending on the rejection
     * result. Returns true if this transaction is an orphan who should be processed, false
     * otherwise. */
    bool MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result);

    /** Whether this transaction is found in orphanage, recently confirmed, or recently rejected transactions. */
    bool AlreadyHaveTx(const GenTxid& gtxid) const;

    /** New inv has been received. May be added as a candidate to txrequest. */
    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now);

    /** Get getdata requests to send. */
    std::vector<GenTxid> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time);

    /** If this tx was something we requested, record that we received a response. */
    void ReceivedTx(NodeId nodeid, const uint256& txhash);

    /** Add a new orphan transaction. Returns whether this orphan is going to be processed. */
    bool NewOrphanTx(const CTransactionRef& tx, const std::vector<uint256>& parent_txids, NodeId nodeid,
                     std::chrono::microseconds now);
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
