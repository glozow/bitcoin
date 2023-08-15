// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NODE_TXDOWNLOAD_IMPL_H
#define BITCOIN_NODE_TXDOWNLOAD_IMPL_H

#include <consensus/validation.h>
#include <logging.h>
#include <net.h>
#include <sync.h>
#include <txmempool.h>
#include <txorphanage.h>
#include <txrequest.h>

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

struct TxDownloadOptions {
    /** Global maximum number of orphan transactions to keep. Enforced with LimitOrphans. */
    uint32_t m_max_orphan_txs;
    /** Read-only reference to mempool. */
    const CTxMemPool& m_mempool_ref;
};
struct TxDownloadConnectionInfo {
    /** Whether this peer is preferred for transaction download. */
    const bool m_preferred;
    /** Whether this peer has Relay permissions. */
    const bool m_relay_permissions;
    /** Whether this peer supports wtxid relay. */
    const bool m_wtxid_relay;
};

class TxDownloadImpl {
public:
    const TxDownloadOptions m_opts;

    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage;
    /** Tracks candidates for requesting and downloading transaction data. */
    TxRequestTracker m_txrequest;

    /**
     * Filter for transactions that were recently rejected by the mempool.
     * These are not rerequested until the chain tip changes, at which point
     * the entire filter is reset.
     *
     * Without this filter we'd be re-requesting txs from each of our peers,
     * increasing bandwidth consumption considerably. For instance, with 100
     * peers, half of which relay a tx we don't accept, that might be a 50x
     * bandwidth increase. A flooding attacker attempting to roll-over the
     * filter using minimum-sized, 60byte, transactions might manage to send
     * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
     * two minute window to send invs to us.
     *
     * Decreasing the false positive rate is fairly cheap, so we pick one in a
     * million to make it highly unlikely for users to have issues with this
     * filter.
     *
     * We typically only add wtxids to this filter. For non-segwit
     * transactions, the txid == wtxid, so this only prevents us from
     * re-downloading non-segwit transactions when communicating with
     * non-wtxidrelay peers -- which is important for avoiding malleation
     * attacks that could otherwise interfere with transaction relay from
     * non-wtxidrelay peers. For communicating with wtxidrelay peers, having
     * the reject filter store wtxids is exactly what we want to avoid
     * redownload of a rejected transaction.
     *
     * In cases where we can tell that a segwit transaction will fail
     * validation no matter the witness, we may add the txid of such
     * transaction to the filter as well. This can be helpful when
     * communicating with txid-relay peers or if we were to otherwise fetch a
     * transaction via txid (eg in our orphan handling).
     *
     * Memory used: 1.3 MB
     */
    CRollingBloomFilter m_recent_rejects {120'000, 0.000'001};

    /*
     * Filter for transactions that have been recently confirmed.
     * We use this to avoid requesting transactions that have already been
     * confirnmed.
     *
     * Blocks don't typically have more than 4000 transactions, so this should
     * be at least six blocks (~1 hr) worth of transactions that we can store,
     * inserting both a txid and wtxid for every observed transaction.
     * If the number of transactions appearing in a block goes up, or if we are
     * seeing getdata requests more than an hour after initial announcement, we
     * can increase this number.
     * The false positive rate of 1/1M should come out to less than 1
     * transaction per day that would be inadvertently ignored (which is the
     * same probability that we have in the reject filter).
     */
    mutable Mutex m_recent_confirmed_transactions_mutex;
    CRollingBloomFilter m_recent_confirmed_transactions GUARDED_BY(m_recent_confirmed_transactions_mutex){48'000, 0.000'001};

    struct PeerInfo {
        /** Information relevant to scheduling tx requests. */
        const TxDownloadConnectionInfo m_connection_info;

        PeerInfo(const TxDownloadConnectionInfo& info) : m_connection_info{info} {}
    };

    /** Information for all of the peers we may download transactions from. This is not necessarily
     * all peers we are connected to (no block-relay-only and temporary connections). */
    std::map<NodeId, PeerInfo> m_peer_info;

    /** Number of wtxid relay peers we have. */
    uint32_t m_num_wtxid_peers{0};

    TxDownloadImpl(const TxDownloadOptions& options) : m_opts{options} {}

    TxOrphanage& GetOrphanageRef();

    TxRequestTracker& GetTxRequestRef();

    /** Creates a new PeerInfo. Saves the connection info to calculate tx announcement delays later. */
    void ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info);

    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId nodeid);

    /** Resets m_recent_rejects. */
    void UpdatedBlockTipSync();

    /** Deletes all block and conflicted transactions from txrequest and orphanage. */
    void BlockConnected(const CBlock& block, const uint256& tiphash);

    /** Resets recently confirmed filter. */
    void BlockDisconnected();

    /** Erases the tx from orphanage, and forgets its txid and wtxid from txrequest.  Adds any
     * orphan transactions depending on it to their respective peers' workset. */
    void MempoolAcceptedTx(const CTransactionRef& tx);

    /** May add the transaction's txid and/or wtxid to recent_rejects depending on the rejection
     * result. Returns true if this transaction is an orphan who should be processed, false
     * otherwise. */
    bool MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result);

    /** Whether this transaction is found in orphanage, recently confirmed, or recently rejected transactions. */
    bool AlreadyHaveTx(const GenTxid& gtxid) const;

    /** New inv has been received. May be added as a candidate to txrequest. */
    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now);

    /** Get getdata requests to send. */
    std::vector<GenTxid> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time);

    /** Marks a tx as ReceivedResponse in txrequest. Returns whether we AlreadyHaveTx. */
    bool ReceivedTx(NodeId nodeid, const CTransactionRef& ptx);

    /** Marks a tx as ReceivedResponse in txrequest. */
    void ReceivedNotFound(NodeId nodeid, const std::vector<uint256>& txhashes);

    /** Creates deduplicated list of missing parents (based on AlreadyHaveTx). Adds tx to orphanage
     * and schedules requests for missing parents in txrequest. Returns whether the tx is new to the
     * orphanage and staying there. */
    std::pair<bool, std::vector<Txid>> NewOrphanTx(const CTransactionRef& tx, NodeId nodeid,
                                                   std::chrono::microseconds current_time);

    /** Whether there are any orphans in this peer's work set. */
    bool HaveMoreWork(NodeId nodeid) const;

    /** Get orphan transaction from this peer's workset. */
    CTransactionRef GetTxToReconsider(NodeId nodeid);

    /** Size() of orphanage, txrequest, and orphan request tracker are equal to 0. */
    void CheckIsEmpty() const;

    /** Count(nodeid) of orphanage, txrequest, and orphan request tracker are equal to 0. */
    void CheckIsEmpty(NodeId nodeid) const;
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOAD_IMPL_H