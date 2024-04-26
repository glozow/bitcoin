// Copyright (c) 2022
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NODE_TXDOWNLOAD_IMPL_H
#define BITCOIN_NODE_TXDOWNLOAD_IMPL_H

#include <consensus/validation.h>
#include <kernel/chain.h>
#include <net.h>
#include <policy/packages.h>
#include <txorphanage.h>
#include <txrequest.h>

class CTxMemPool;
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
    /** Read-only reference to mempool. */
    const CTxMemPool& m_mempool;
    /** RNG provided by caller. */
    FastRandomContext& m_rng;
    /** Maximum number of transactions allowed in orphanage. */
    uint32_t m_max_orphan_txs;
};
struct TxDownloadConnectionInfo {
    /** Whether this peer is preferred for transaction download. */
    const bool m_preferred;
    /** Whether this peer has Relay permissions. */
    const bool m_relay_permissions;
    /** Whether this peer supports wtxid relay. */
    const bool m_wtxid_relay;
};
/** A package to validate  */
struct PackageToValidate {
    const Package m_txns;
    const std::vector<NodeId> m_senders;
    /** Construct a 1-parent-1-child package. */
    explicit PackageToValidate(const CTransactionRef& parent,
                               const CTransactionRef& child,
                               NodeId parent_sender,
                               NodeId child_sender) :
        m_txns{parent, child},
        m_senders {parent_sender, child_sender}
    {}

    std::string ToString() const {
        Assume(m_txns.size() == 2);
        return strprintf("parent %s (wtxid=%s, sender=%d) + child %s (wtxid=%s, sender=%d)",
                         m_txns.front()->GetHash().ToString(),
                         m_txns.front()->GetWitnessHash().ToString(),
                         m_senders.front(),
                         m_txns.back()->GetHash().ToString(),
                         m_txns.back()->GetWitnessHash().ToString(),
                         m_senders.back());
    }
};

class TxDownloadImpl {
public:
    TxDownloadOptions m_opts;

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
    CRollingBloomFilter m_recent_rejects{120'000, 0.000'001};

    /**
     * Filter for:
     * (1) wtxids of transactions that were recently rejected by the mempool but are
     * eligible for reconsideration if submitted with other transactions.
     * (2) packages (see GetPackageHash) we have already rejected before and should not retry.
     *
     * Similar to m_recent_rejects, this filter is used to save bandwidth when e.g. all of our peers
     * have larger mempools and thus lower minimum feerates than us.
     *
     * When a transaction's error is TxValidationResult::TX_RECONSIDERABLE (in a package or by
     * itself), add its wtxid to this filter. When a package fails for any reason, add the combined
     * hash to this filter.
     *
     * Upon receiving an announcement for a transaction, if it exists in this filter, do not
     * download the txdata. When considering packages, if it exists in this filter, drop it.
     *
     * Reset this filter when the chain tip changes.
     *
     * Parameters are picked to be the same as m_recent_rejects, with the same rationale.
     */
    CRollingBloomFilter m_recent_rejects_reconsiderable{120'000, 0.000'001};

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
    CRollingBloomFilter m_recent_confirmed_transactions{48'000, 0.000'001};

    TxDownloadImpl(const TxDownloadOptions& options) : m_opts{options} {}

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

    void UpdatedBlockTipSync();
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock);
    void BlockDisconnected();
    bool AlreadyHaveTx(const GenTxid& gtxid, bool include_reconsiderable);

    void ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info);
    void DisconnectedPeer(NodeId nodeid);

    /** New inv has been received. May be added as a candidate to txrequest. */
    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now);

    /** Get getdata requests to send. */
    std::vector<GenTxid> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time);

    /** Marks a tx as ReceivedResponse in txrequest. */
    void ReceivedNotFound(NodeId nodeid, const std::vector<uint256>& txhashes);

    void MempoolAcceptedTx(const CTransactionRef& tx);
    bool MempoolRejectedTx(const CTransactionRef& ptx, const TxValidationState& state);
    void MempoolRejectedPackage(const Package& package);

    std::optional<PackageToValidate> Find1P1CPackage(const CTransactionRef& ptx, NodeId nodeid);

    std::pair<bool, std::optional<PackageToValidate>> ReceivedTx(NodeId nodeid, const CTransactionRef& ptx);

    std::pair<std::vector<uint256>, bool> MaybeAddNewOrphan(const CTransactionRef& ptx, NodeId nodeid);

    bool HaveMoreWork(NodeId nodeid);
    CTransactionRef GetTxToReconsider(NodeId nodeid);

    void CheckIsEmpty();
    void CheckIsEmpty(NodeId nodeid);
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOAD_IMPL_H
