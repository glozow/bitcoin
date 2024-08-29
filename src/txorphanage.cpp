// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txorphanage.h>

#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <util/time.h>

#include <cassert>

void TxOrphanage::AddOrphanBytes(unsigned int size, NodeId peer)
{
    m_peer_bytes_used.try_emplace(peer, 0);
    m_peer_bytes_used.at(peer) += size;
}

void TxOrphanage::SubtractOrphanBytes(unsigned int size, NodeId peer)
{
    // If our accounting is off, control damage by ensuring we clean up m_peer_bytes_used.
    auto it = m_peer_bytes_used.find(peer);
    if (!Assume(it != m_peer_bytes_used.end())) return;
    if (!Assume(it->second >= size)) {
        // Equivalent of bytes going to 0.
        m_peer_bytes_used.erase(it);
        return;
    }

    it->second -= size;
    if (it->second == 0) {
        m_peer_bytes_used.erase(it);
    }
}

bool TxOrphanage::AddTx(const CTransactionRef& tx, NodeId peer, const std::vector<Txid>& parent_txids)
{
    const Txid& hash = tx->GetHash();
    const Wtxid& wtxid = tx->GetWitnessHash();
    auto it = m_orphans.find(wtxid);
    if (it != m_orphans.end()) {
        Assume(!it->second.announcers.empty());
        const auto ret = it->second.announcers.insert(peer);
        if (ret.second) {
            AddOrphanBytes(it->second.tx->GetTotalSize(), peer);
            LogPrint(BCLog::TXPACKAGES, "added peer=%d as announcer of orphan tx %s\n", peer, wtxid.ToString());
        }
        // Even if an announcer was added, no new orphan entry was created.
        return false;
    }

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 100 orphans, each of which is at most 100,000 bytes big is
    // at most 10 megabytes of orphans and somewhat more byprev index (in the worst case):
    unsigned int sz = GetTransactionWeight(*tx);
    if (sz > MAX_STANDARD_TX_WEIGHT)
    {
        LogPrint(BCLog::TXPACKAGES, "ignoring large orphan tx (size: %u, txid: %s, wtxid: %s)\n", sz, hash.ToString(), wtxid.ToString());
        return false;
    }

    auto ret = m_orphans.emplace(wtxid, OrphanTx{tx, {peer}, {}, Now<NodeSeconds>() + ORPHAN_TX_EXPIRE_TIME, static_cast<int32_t>(m_orphan_list.size()), parent_txids});
    assert(ret.second);
    m_orphan_list.push_back(ret.first);
    for (const CTxIn& txin : tx->vin) {
        m_outpoint_to_orphan_it[txin.prevout].insert(ret.first);
    }

    LogPrint(BCLog::TXPACKAGES, "stored orphan tx %s (wtxid=%s), weight: %u (mapsz %u outsz %u)\n", hash.ToString(), wtxid.ToString(), sz,
             m_orphans.size(), m_outpoint_to_orphan_it.size());
    AddOrphanBytes(tx->GetTotalSize(), peer);
    m_total_orphan_bytes += tx->GetTotalSize();
    return true;
}

bool TxOrphanage::AddAnnouncer(const Wtxid& wtxid, NodeId peer)
{
    const auto it = m_orphans.find(wtxid);
    if (it != m_orphans.end()) {
        Assume(!it->second.announcers.empty());
        const auto ret = it->second.announcers.insert(peer);
        if (ret.second) {
            AddOrphanBytes(it->second.tx->GetTotalSize(), peer);
            LogPrint(BCLog::TXPACKAGES, "added peer=%d as announcer of orphan tx %s\n", peer, wtxid.ToString());
            return true;
        }
    }
    return false;
}

unsigned int TxOrphanage::GetOrphanSize(const Wtxid& wtxid) const
{
    const auto it = m_orphans.find(wtxid);
    return it != m_orphans.end() ? it->second.tx->GetTotalSize() : 0;
}

int TxOrphanage::EraseTx(const Wtxid& wtxid)
{
    std::map<Wtxid, OrphanTx>::iterator it = m_orphans.find(wtxid);
    if (it == m_orphans.end())
        return 0;

    m_total_orphan_bytes -= it->second.tx->GetTotalSize();
    for (const auto fromPeer : it->second.announcers) {
        SubtractOrphanBytes(it->second.tx->GetTotalSize(), fromPeer);
    }

    for (const CTxIn& txin : it->second.tx->vin)
    {
        auto itPrev = m_outpoint_to_orphan_it.find(txin.prevout);
        if (itPrev == m_outpoint_to_orphan_it.end())
            continue;
        itPrev->second.erase(it);
        if (itPrev->second.empty())
            m_outpoint_to_orphan_it.erase(itPrev);
    }

    if (it->second.IsProtected()) {
        m_total_protected_orphan_bytes -= it->second.tx->GetTotalSize();
    } else {
        size_t old_pos = it->second.list_pos;
        assert(m_orphan_list[old_pos] == it);
        if (old_pos + 1 != m_orphan_list.size()) {
            // Unless we're deleting the last entry in m_orphan_list, move the last
            // entry to the position we're deleting.
            auto it_last = m_orphan_list.back();
            m_orphan_list[old_pos] = it_last;
            it_last->second.list_pos = old_pos;
        }
        m_orphan_list.pop_back();
    }
    const auto& txid = it->second.tx->GetHash();
    // Time spent in orphanage = difference between current and entry time.
    // Entry time is equal to ORPHAN_TX_EXPIRE_TIME earlier than entry's expiry.
    LogPrint(BCLog::TXPACKAGES, "   removed orphan tx %s (wtxid=%s) after %ds\n", txid.ToString(), wtxid.ToString(),
             Ticks<std::chrono::seconds>(NodeClock::now() + ORPHAN_TX_EXPIRE_TIME - it->second.nTimeExpire));

    m_orphans.erase(it);
    return 1;
}

void TxOrphanage::EraseForPeer(NodeId peer)
{
    m_peer_work_set.erase(peer);

    int nErased = 0;
    std::map<Wtxid, OrphanTx>::iterator iter = m_orphans.begin();
    while (iter != m_orphans.end())
    {
        // increment to avoid iterator becoming invalid after erasure
        auto& [wtxid, orphan] = *iter++;
        if (orphan.announcers.contains(peer)) {
            if (orphan.announcers.size() == 1) {
                nErased += EraseTx(orphan.tx->GetWitnessHash());
            } else {
                // Don't erase this orphan. Another peer has also announced it, so it may still be useful.
                UndoProtectOrphan(wtxid, peer);
                orphan.announcers.erase(peer);
                SubtractOrphanBytes(orphan.tx->GetTotalSize(), peer);
            }
        }
    }
    if (nErased > 0) LogPrint(BCLog::TXPACKAGES, "Erased %d orphan transaction(s) from peer=%d\n", nErased, peer);

    // Belt-and-suspenders if our accounting is off. We shouldn't keep an entry for a disconnected
    // peer as we will have no other opportunity to delete it.
    if (!Assume(m_peer_bytes_used.count(peer) == 0)) m_peer_bytes_used.erase(peer);
}

std::vector<Wtxid> TxOrphanage::LimitOrphans(unsigned int max_orphans, FastRandomContext& rng)
{
    std::vector<Wtxid> erased_and_evicted;
    unsigned int nEvicted = 0;
    auto nNow{Now<NodeSeconds>()};
    if (m_next_sweep <= nNow) {
        // Sweep out expired orphan pool entries:
        auto nMinExpTime{nNow + ORPHAN_TX_EXPIRE_TIME - ORPHAN_TX_EXPIRE_INTERVAL};
        std::map<Wtxid, OrphanTx>::iterator iter = m_orphans.begin();
        while (iter != m_orphans.end())
        {
            std::map<Wtxid, OrphanTx>::iterator maybeErase = iter++;
            if (maybeErase->second.nTimeExpire <= nNow) {
                const auto& wtxid = maybeErase->second.tx->GetWitnessHash();
                erased_and_evicted.emplace_back(wtxid);
                EraseTx(wtxid);
            } else {
                nMinExpTime = std::min(maybeErase->second.nTimeExpire, nMinExpTime);
            }
        }
        // Sweep again 5 minutes after the next entry that expires in order to batch the linear scan.
        m_next_sweep = nMinExpTime + ORPHAN_TX_EXPIRE_INTERVAL;
        if (!erased_and_evicted.empty()) LogPrint(BCLog::TXPACKAGES, "Erased %d orphan tx due to expiration\n", erased_and_evicted.size());
    }

    // Only consider the non-protected orphans for eviction. This means that m_orphans.size() may
    // still be larger than max_orphans after evictions.
    while (m_orphan_list.size() > max_orphans)
    {
        // Evict a random orphan:
        size_t randompos = rng.randrange(m_orphan_list.size());
        const auto& wtxid = m_orphan_list[randompos]->second.tx->GetWitnessHash();
        erased_and_evicted.emplace_back(wtxid);
        ++nEvicted;
        EraseTx(wtxid);
    }
    if (nEvicted > 0) LogPrint(BCLog::TXPACKAGES, "orphanage overflow, removed %u tx\n", nEvicted);
    return erased_and_evicted;
}

void TxOrphanage::AddChildrenToWorkSet(const CTransaction& tx)
{
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(tx.GetHash(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto& elem : it_by_prev->second) {
                // Belt and suspenders, each orphan should always have at least 1 announcer.
                if (!Assume(!elem->second.announcers.empty())) break;
                for (const auto announcer: elem->second.announcers) {
                    // Get this source peer's work set, emplacing an empty set if it didn't exist
                    // (note: if this peer wasn't still connected, we would have removed the orphan tx already)
                    std::set<Wtxid>& orphan_work_set = m_peer_work_set.try_emplace(announcer).first->second;
                    // Add this tx to the work set
                    orphan_work_set.insert(elem->first);
                    LogPrint(BCLog::TXPACKAGES, "added %s (wtxid=%s) to peer %d workset\n",
                             tx.GetHash().ToString(), tx.GetWitnessHash().ToString(), announcer);
                }
            }
        }
    }
}

bool TxOrphanage::HaveTx(const Wtxid& wtxid) const
{
    return m_orphans.count(wtxid);
}

bool TxOrphanage::HaveTxAndPeer(const Wtxid& wtxid, NodeId peer) const
{
    auto it = m_orphans.find(wtxid);
    return (it != m_orphans.end() && it->second.announcers.count(peer) > 0);
}

CTransactionRef TxOrphanage::GetTxToReconsider(NodeId peer)
{
    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        auto& work_set = work_set_it->second;
        while (!work_set.empty()) {
            Wtxid wtxid = *work_set.begin();
            work_set.erase(work_set.begin());

            const auto orphan_it = m_orphans.find(wtxid);
            if (orphan_it != m_orphans.end()) {
                return orphan_it->second.tx;
            }
        }
    }
    return nullptr;
}

bool TxOrphanage::HaveTxToReconsider(NodeId peer)
{
    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        auto& work_set = work_set_it->second;
        return !work_set.empty();
    }
    return false;
}

std::vector<Wtxid> TxOrphanage::EraseForBlock(const CBlock& block)
{
    std::vector<Wtxid> vOrphanErase;

    for (const CTransactionRef& ptx : block.vtx) {
        const CTransaction& tx = *ptx;

        // Which orphan pool entries must we evict?
        for (const auto& txin : tx.vin) {
            auto itByPrev = m_outpoint_to_orphan_it.find(txin.prevout);
            if (itByPrev == m_outpoint_to_orphan_it.end()) continue;
            for (auto mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi) {
                const CTransaction& orphanTx = *(*mi)->second.tx;
                vOrphanErase.push_back(orphanTx.GetWitnessHash());
            }
        }
    }

    // Erase orphan transactions included or precluded by this block
    if (vOrphanErase.size()) {
        int nErased = 0;
        for (const auto& orphanHash : vOrphanErase) {
            nErased += EraseTx(orphanHash);
        }
        LogPrint(BCLog::TXPACKAGES, "Erased %d orphan transaction(s) included or conflicted by block\n", nErased);
    }

    return vOrphanErase;
}

std::vector<CTransactionRef> TxOrphanage::GetChildrenFromSamePeer(const CTransactionRef& parent, NodeId nodeid) const
{
    // First construct a vector of iterators to ensure we do not return duplicates of the same tx
    // and so we can sort by nTimeExpire.
    std::vector<OrphanMap::iterator> iters;

    // For each output, get all entries spending this prevout, filtering for ones from the specified peer.
    for (unsigned int i = 0; i < parent->vout.size(); i++) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(parent->GetHash(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto& elem : it_by_prev->second) {
                if (elem->second.announcers.contains(nodeid)) {
                    iters.emplace_back(elem);
                }
            }
        }
    }

    // Sort by address so that duplicates can be deleted. At the same time, sort so that more recent
    // orphans (which expire later) come first.  Break ties based on address, as nTimeExpire is
    // quantified in seconds and it is possible for orphans to have the same expiry.
    std::sort(iters.begin(), iters.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs->second.nTimeExpire == rhs->second.nTimeExpire) {
            return &(*lhs) < &(*rhs);
        } else {
            return lhs->second.nTimeExpire > rhs->second.nTimeExpire;
        }
    });
    // Erase duplicates
    iters.erase(std::unique(iters.begin(), iters.end()), iters.end());

    // Convert to a vector of CTransactionRef
    std::vector<CTransactionRef> children_found;
    children_found.reserve(iters.size());
    for (const auto& child_iter : iters) {
        children_found.emplace_back(child_iter->second.tx);
    }
    return children_found;
}

std::optional<std::vector<Txid>> TxOrphanage::GetParentTxids(const Wtxid& wtxid)
{
    const auto it = m_orphans.find(wtxid);
    if (it != m_orphans.end()) return it->second.parent_txids;
    return std::nullopt;
}

void TxOrphanage::EraseOrphanOfPeer(const Wtxid& wtxid, NodeId peer)
{
    // Nothing to do if this tx doesn't exist.
    const auto it = m_orphans.find(wtxid);
    if (it == m_orphans.end()) return;

    // It wouldn't make sense for the orphan to show up in GetTxToReconsider after we gave up on
    // this orphan with this peer. If this tx is in the peer's workset, delete it, because the
    // transaction may persist in the orphanage with a different peer.
    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        work_set_it->second.erase(wtxid);
    }

    if (it->second.announcers.count(peer) > 0) {
        if (it->second.announcers.size() == 1) {
            EraseTx(wtxid);
        } else {
            // Don't erase this orphan. Another peer has also announced it, so it may still be useful.
            UndoProtectOrphan(wtxid, peer);
            it->second.announcers.erase(peer);
            SubtractOrphanBytes(it->second.tx->GetTotalSize(), peer);
        }
    }
}

std::optional<unsigned int> TxOrphanage::ProtectOrphan(const Wtxid& wtxid, NodeId peer, unsigned int max_size)
{
    const auto it = m_orphans.find(wtxid);
    if (it == m_orphans.end()) return std::nullopt;

    // Tx is larger than max_size, don't protect.
    if (it->second.tx->GetTotalSize() > max_size) return std::nullopt;

    // Already protected by this peer.
    if (it->second.protectors.contains(peer)) return std::nullopt;

    // Can't protect a peer you didn't announce.
    if (!it->second.announcers.contains(peer)) return std::nullopt;

    // Already protected, increase its protection
    if (it->second.IsProtected()) {
        it->second.protectors.insert(peer);
        return it->second.tx->GetTotalSize();
    }

    it->second.protectors.insert(peer);
    auto old_pos = it->second.list_pos;
    assert(m_orphan_list.at(old_pos) == it);
    if (old_pos + 1 != static_cast<int32_t>(m_orphan_list.size())) {
        // Unless we're deleting the last entry in m_orphan_list, move the last
        // entry to the position we're deleting.
        auto it_last = m_orphan_list.back();
        m_orphan_list[old_pos] = it_last;
        it_last->second.list_pos = old_pos;
    }
    m_orphan_list.pop_back();
    m_total_protected_orphan_bytes += it->second.tx->GetTotalSize();
    // Set list_pos to -1 to indicate this orphan is protected.
    it->second.list_pos = -1;
    return it->second.tx->GetTotalSize();
}

void TxOrphanage::UndoProtectOrphan(const Wtxid& wtxid, NodeId peer)
{
    auto it = m_orphans.find(wtxid);
    if (it == m_orphans.end()) return;
    // Already not protected, nothing to do
    if (!it->second.IsProtected()) {
        return;
    }

    it->second.protectors.erase(peer);

    // Wasn't protected by this peer or protected by more than one peer.
    if (!it->second.protectors.empty()) return;

    // Going from protected to unprotected. Add to the end or m_orphan_list.
    it->second.list_pos = static_cast<int32_t>(m_orphan_list.size());
    m_orphan_list.push_back(it);
    m_total_protected_orphan_bytes -= it->second.tx->GetTotalSize();
}

std::optional<std::pair<unsigned int, std::vector<NodeId>>> TxOrphanage::GetProtectors(const Wtxid& wtxid) const
{
    auto it = m_orphans.find(wtxid);
    if (it == m_orphans.end()) return std::nullopt;
    if (!it->second.IsProtected()) {
        return std::nullopt;
    }

    return std::make_pair(it->second.tx->GetTotalSize(),
                          std::vector<NodeId>(it->second.protectors.cbegin(), it->second.protectors.cend()));
}
