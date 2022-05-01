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
namespace node {

class TxDownloadManager {
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxDownloadManager();
    ~TxDownloadManager();

    bool OrphanageAddTx(const CTransactionRef& tx, NodeId peer);

    /** Check if we already have an orphan transaction (by txid or wtxid) */
    bool OrphanageHaveTx(const GenTxid& gtxid);

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef OrphanageGetTxToReconsider(NodeId peer);

    /** Erase an orphan by wtxid */
    int OrphanageEraseTx(const uint256& wtxid);

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void OrphanageEraseForPeer(NodeId peer);

    /** Erase all orphans included in or invalidated by a new block */
    void OrphanageEraseForBlock(const CBlock& block);

    /** Limit the orphanage to the given maximum */
    void OrphanageLimitOrphans(unsigned int max_orphans);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void OrphanageAddChildrenToWorkSet(const CTransaction& tx);

    /** Does this peer have any orphans to validate? */
    bool OrphanageHaveTxToReconsider(NodeId peer);

    /** Return how many entries exist in the orphange */
    size_t OrphanageSize();

    /** Deletes all announcements for a given peer. */
    void TxRequestDisconnectedPeer(NodeId peer);

    /** Adds a new CANDIDATE announcement. */
    void TxRequestReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred,
        std::chrono::microseconds reqtime);

    /** Deletes all announcements for a given txhash (both txid and wtxid ones). */
    void TxRequestForgetTxHash(const uint256& txhash);

    /** Find the txids to request now from peer. */
    std::vector<GenTxid> TxRequestGetRequestable(NodeId peer, std::chrono::microseconds now,
        std::vector<std::pair<NodeId, GenTxid>>* expired = nullptr);

    /** Marks a transaction as requested, with a specified expiry. */
    void TxRequestRequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry);

    /** Converts a CANDIDATE or REQUESTED announcement to a COMPLETED one. */
    void TxRequestReceivedResponse(NodeId peer, const uint256& txhash);

    /** Count how many REQUESTED announcements a peer has. */
    size_t TxRequestCountInFlight(NodeId peer) const;

    /** Count how many CANDIDATE announcements a peer has. */
    size_t TxRequestCountCandidates(NodeId peer) const;

    /** Count how many announcements a peer has (REQUESTED, CANDIDATE, and COMPLETED combined). */
    size_t TxRequestCount(NodeId peer) const;

    /** Count how many announcements are being tracked in total across all peers and transaction hashes. */
    size_t TxRequestSize() const;
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
