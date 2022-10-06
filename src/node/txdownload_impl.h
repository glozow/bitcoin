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

/** Default -packagerelay value. */
static constexpr auto DEFAULT_DO_PACKAGE_RELAY{false};

/** The bits in sendpackages "versions" field */
enum PackageRelayVersions : uint64_t {
    PKG_RELAY_NONE = 0,
    // BIP331: getpkgtxns, pkgtxns, MSG_PKGTXNS
    PKG_RELAY_PKGTXNS = (1 << 0),
    // BIP331: ancpkginfo, MSG_ANCPKGINFO
    PKG_RELAY_ANCPKG = (1 << 1),
};
struct TxDownloadOptions {
    /** Global maximum number of orphan transactions to keep. Enforced with LimitOrphans. */
    uint32_t m_max_orphan_txs;
    /** Read-only reference to mempool. */
    const CTxMemPool& m_mempool_ref;
    /** Whether we do package relay (-packagerelay). */
    bool m_do_package_relay;
};
struct TxDownloadConnectionInfo {
    /** Whether this peer is preferred for transaction download. */
    const bool m_preferred;
    /** Whether this peer has Relay permissions. */
    const bool m_relay_permissions;
    /** Whether this peer supports wtxid relay. */
    const bool m_wtxid_relay;
    /** Whether this peer is ok with us relaying transactions. */
    const bool m_relays_txs;
    /** Whether this peer is an inbound peer. */
    const bool m_inbound;
};
/** Represents a getdata message. */
struct GenRequest {
    uint256 m_id;
    enum class Type : uint8_t {
        TXID,       //!> txid only
        WTXID,      //!> wtxid only
        ANYTX,      //!> Any tx hash, not package
        ANCPKGINFO, //!> wtxid, ancpkginfo
    };
    Type m_type;
    GenRequest() = delete;
    // All construction should be through these static methods.
    static GenRequest TxRequest(const GenTxid& gtxid) { return GenRequest(gtxid.GetHash(), gtxid.IsWtxid() ? Type::WTXID : Type::TXID); }
    static GenRequest TxRequest(const uint256& txhash) { return GenRequest(txhash, Type::ANYTX); }
    static GenRequest PkgRequest(const GenTxid& gtxid) { return GenRequest(gtxid.GetHash(), Type::ANCPKGINFO); }
    static GenRequest PkgRequest(const uint256& txhash) { return GenRequest(txhash, Type::ANCPKGINFO); }


    // Ctor is private to avoid misuse
    private:
    explicit GenRequest(const uint256& id, Type type) : m_id{id}, m_type{type} {}

};

class TxDownloadImpl {
public:
    mutable Mutex m_tx_download_mutex;

    const TxDownloadOptions m_opts;

    /** Manages unvalidated tx data (orphan transactions for which we are downloading ancestors). */
    TxOrphanage m_orphanage GUARDED_BY(m_tx_download_mutex);
    /** Tracks candidates for requesting and downloading transaction data. */
    TxRequestTracker m_txrequest GUARDED_BY(m_tx_download_mutex);

    /** Tracks orphans we are trying to resolve. All hashes stored are wtxids, i.e., the wtxid of
     * the orphan. Used to schedule resolution with peers, which means requesting the missing
     * parents by txid. */
    TxRequestTracker m_orphan_resolution_tracker GUARDED_BY(m_tx_download_mutex);

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
    CRollingBloomFilter m_recent_rejects GUARDED_BY(m_tx_download_mutex){120'000, 0.000'001};
    uint256 hashRecentRejectsChainTip GUARDED_BY(m_tx_download_mutex);

    /**
     * Filter for transactions or packages of transactions that were recently rejected by
     * the mempool but are eligible for reconsideration if submitted with other transactions.
     * This filter only contains wtxids of individual transactions and combined hashes of packages
     * (see GetCombinedHash and GetPackageHash).
     *
     * When a transaction's error is too low fee (in a package or by itself), add its wtxid to this
     * filter. If it was in a package, also add the combined hash of the transactions in its
     * subpackage to this filter. When a package fails for any reason, add the combined hash of all
     * transactions in the package info to this filter.
     *
     * Upon receiving an announcement for a transaction, if it exists in this filter, do not
     * download the txdata. Upon receiving a package info, if the combined hash of its transactions
     * are in this filter, do not download the txdata.
     *
     * Reset this filter when the chain tip changes.
     *
     * We will only add wtxids to this filter. Groups of multiple transactions are represented by
     * the hash of their wtxids, concatenated together in lexicographical order.
     *
     * Parameters are picked to be identical to that of m_recent_rejects, with the same rationale.
     * Memory used: 1.3 MB
     * FIXME: this filter can probably be smaller, but how much smaller?
     */
    CRollingBloomFilter m_recent_rejects_reconsiderable GUARDED_BY(::cs_main){120'000, 0.000'001};

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
    CRollingBloomFilter m_recent_confirmed_transactions GUARDED_BY(m_tx_download_mutex){48'000, 0.000'001};

    struct PeerInfo {
        /** Information relevant to scheduling tx requests. */
        const TxDownloadConnectionInfo m_connection_info;

        /** What package versions we agreed to relay. */
        PackageRelayVersions m_versions_supported;

        PeerInfo(const TxDownloadConnectionInfo& info, PackageRelayVersions versions) :
            m_connection_info{info},
            m_versions_supported{versions}
        {}

        /** Whether any version of package relay is supported. */
        bool SupportsPackageRelay() const { return m_versions_supported != PKG_RELAY_NONE; }

        /** Whether version is supported. If multiple bits are set in version, returns whether any
         * of them are supported. */
        bool SupportsVersion(PackageRelayVersions version) const { return m_versions_supported & version; }
    };

    /** Records the "sendpackages" versions we have received from peers prior to verack. This map
     * and m_peer_info should not have any keys in common. If the peer connects successfully, we use
     * this to determine what versions of package relay we both support. */
    std::map<NodeId, PackageRelayVersions> m_sendpackages_received GUARDED_BY(m_tx_download_mutex);

    /** Information for all of the successfully connected peers we may download transactions from.
     * This map and m_sendpackages_received should not have any keys in common. This is not
     * necessarily all peers we are connected to (no block-relay-only and temporary connections). */
    std::map<NodeId, PeerInfo> m_peer_info GUARDED_BY(m_tx_download_mutex);

    /** unique ID for a package information request for a tx to a peer. */
    using PackageInfoRequestId = uint256;
    static PackageInfoRequestId GetPackageInfoRequestId(NodeId nodeid, const uint256& wtxid, PackageRelayVersions version) {
        return (CHashWriter(SER_GETHASH, 0) << nodeid << wtxid << uint64_t{version}).GetSHA256(); 
    }

    /** Keep track of the package info requests we have sent recently. Used to identify unsolicited
     * package info messages and already-sent-recently requests. */
    CRollingBloomFilter m_package_info_requested GUARDED_BY(m_tx_download_mutex){50'000, 0.000001};

    /** Number of wtxid relay peers we have. */
    uint32_t m_num_wtxid_peers GUARDED_BY(m_tx_download_mutex){0};

    /** Number of ancestor package relay peers we have. */
    uint32_t m_num_ancpkg_relay_peers GUARDED_BY(m_tx_download_mutex){0};
private:
    /** Maybe adds an inv to txrequest. */
    void AddTxAnnouncement(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex);

    /** Internal AlreadyHaveTx. */
    bool AlreadyHaveTxLocked(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex);

    /** Add another announcer of an orphan who is a potential candidate for resolution. */
    void AddOrphanAnnouncer(NodeId nodeid, const uint256& orphan_wtxid, std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex);

public:
    TxDownloadImpl(const TxDownloadOptions& options) : m_opts{options} {}

    TxOrphanage& GetOrphanageRef() EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex);

    TxRequestTracker& GetTxRequestRef() EXCLUSIVE_LOCKS_REQUIRED(m_tx_download_mutex);

    /** Returns all supported versions if m_opts.m_do_package_relay is true, otherwise PKG_RELAY_NONE. */
    PackageRelayVersions GetSupportedVersions() const;

    /** Whether we have negotiated this version of package relay with this peer. */
    bool SupportsPackageRelay(NodeId nodeid, PackageRelayVersions version) const;

    /** Whether we have negotiated any version of package relay with this peer. */
    bool SupportsPackageRelay(NodeId nodeid) const;

    /** Adds version to m_sendpackages_received. */
    void ReceivedSendpackages(NodeId nodeid, PackageRelayVersions version);

    /** Creates a new PeerInfo. Saves the connection info to calculate tx announcement delays later. */
    void ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Deletes all block and conflicted transactions from txrequest and orphanage. */
    void BlockConnected(const CBlock& block, const uint256& tiphash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Resets recently confirmed filter. */
    void BlockDisconnected() EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Erases the tx from orphanage, and forgets its txid and wtxid from txrequest.  Adds any
     * orphan transactions depending on it to their respective peers' workset. */
    void MempoolAcceptedTx(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** May add the transaction's txid and/or wtxid to recent_rejects depending on the rejection
     * result. Returns true if this transaction is an orphan who should be processed, false
     * otherwise. */
    bool MempoolRejectedTx(const CTransactionRef& tx, const TxValidationResult& result)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Whether this transaction is found in orphanage, recently confirmed, or recently rejected transactions. */
    bool AlreadyHaveTx(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** New inv has been received. May be added as a candidate to txrequest. */
    void ReceivedTxInv(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Get getdata requests to send. */
    std::vector<GenRequest> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Marks a tx as ReceivedResponse in txrequest. Returns whether we AlreadyHaveTx. */
    bool ReceivedTx(NodeId nodeid, const CTransactionRef& ptx)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Marks a tx as ReceivedResponse in txrequest. */
    void ReceivedNotFound(NodeId nodeid, const std::vector<GenRequest>& txhashes)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Returns whether a peer is allowed to send this package info. */
    bool PackageInfoAllowed(NodeId nodeid, const uint256& wtxid, PackageRelayVersions version) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Updates the orphan resolution tracker, schedules transactions from this package that may
     * need to be requested. */
    void ReceivedAncpkginfo(NodeId nodeid, const std::vector<uint256>& package_wtxids, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Creates deduplicated list of missing parents (based on AlreadyHaveTx). Adds tx to orphanage
     * and schedules requests for missing parents in txrequest. Returns whether the tx is new to the
     * orphanage and staying there. */
    std::pair<bool, std::vector<uint256>> NewOrphanTx(const CTransactionRef& tx, NodeId nodeid,
                                                      std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Whether there are any orphans in this peer's work set. */
    bool HaveMoreWork(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Get orphan transaction from this peer's workset. */
    CTransactionRef GetTxToReconsider(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Size() of orphanage, txrequest, and orphan request tracker are equal to 0. */
    void CheckIsEmpty() const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);

    /** Count(nodeid) of orphanage, txrequest, and orphan request tracker are equal to 0. */
    void CheckIsEmpty(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOAD_IMPL_H
