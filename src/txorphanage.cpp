// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txorphanage.h>

#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>

#include <cassert>

/** Expiration time for orphan transactions in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_TIME = 20 * 60;
/** Minimum time between orphan transactions expire time checks in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_INTERVAL = 5 * 60;

void TxOrphanage::SubtractOrphanBytes(unsigned int size, NodeId peer)
{
    AssertLockHeld(m_mutex);
    if (!Assume(m_peer_bytes_used.count(peer) > 0)) return;
    if (!Assume(m_peer_bytes_used.at(peer) >= size)) return;
    m_peer_bytes_used.at(peer) -= size;
    if (m_peer_bytes_used.at(peer) == 0) {
        m_peer_bytes_used.erase(peer);
    }
}

bool TxOrphanage::AddTx(const CTransactionRef& tx, NodeId peer, const std::vector<uint256>& parent_txids)
{
    LOCK(m_mutex);

    const uint256& hash = tx->GetHash();
    const uint256& wtxid = tx->GetWitnessHash();
    if (m_orphans.count(hash)) {
        Assume(m_orphans.at(hash).announcers.size() > 0);
        const auto ret = m_orphans.at(hash).announcers.insert(peer);
        if (ret.second) {
            m_peer_bytes_used.try_emplace(peer, 0);
            m_peer_bytes_used.at(peer) += tx->GetTotalSize();
        }
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

    auto ret = m_orphans.emplace(hash, OrphanTx{tx, GetTime() + ORPHAN_TX_EXPIRE_TIME, m_orphan_list.size(), {peer}, parent_txids});
    assert(ret.second);
    m_orphan_list.push_back(ret.first);
    // Allow for lookups in the orphan pool by wtxid, as well as txid
    m_wtxid_to_orphan_it.emplace(tx->GetWitnessHash(), ret.first);
    for (const CTxIn& txin : tx->vin) {
        m_outpoint_to_orphan_it[txin.prevout].insert(ret.first);
    }

    m_peer_bytes_used.try_emplace(peer, 0);
    m_peer_bytes_used.at(peer) += tx->GetTotalSize();
    m_total_orphan_bytes += tx->GetTotalSize();
    LogPrint(BCLog::TXPACKAGES, "stored orphan tx %s (wtxid=%s) (mapsz %u outsz %u)\n", hash.ToString(), wtxid.ToString(),
             m_orphans.size(), m_outpoint_to_orphan_it.size());
    return true;
}
void TxOrphanage::AddAnnouncer(const uint256& wtxid, NodeId peer)
{
    LOCK(m_mutex);
    const auto it = m_wtxid_to_orphan_it.find(wtxid);
    if (it != m_wtxid_to_orphan_it.end()) {
        Assume(!it->second->second.announcers.empty());
        const auto ret = it->second->second.announcers.insert(peer);
        if (ret.second) {
            LogPrint(BCLog::TXPACKAGES, "added peer=%d as announcer of orphan tx %s\n", peer, wtxid.ToString());
            m_peer_bytes_used.try_emplace(peer, 0);
            m_peer_bytes_used.at(peer) += it->second->second.tx->GetTotalSize();
        }
    }
}

CTransactionRef TxOrphanage::GetTx(const uint256& wtxid)
{
   LOCK(m_mutex);
   const auto it = m_wtxid_to_orphan_it.find(wtxid);
   return it == m_wtxid_to_orphan_it.end() ? nullptr : it->second->second.tx;
}

int TxOrphanage::EraseTx(const uint256& wtxid)
{
    LOCK(m_mutex);
    return EraseTxNoLock(wtxid);
}

int TxOrphanage::EraseTxNoLock(const uint256& wtxid)
{
    AssertLockHeld(m_mutex);
    const auto wtxid_it = m_wtxid_to_orphan_it.find(wtxid);
    if (wtxid_it == m_wtxid_to_orphan_it.end()) return 0;
    std::map<uint256, OrphanTx>::iterator it = wtxid_it->second;
    m_total_orphan_bytes -= it->second.tx->GetTotalSize();
    for (const auto peer : it->second.announcers) {
        SubtractOrphanBytes(it->second.tx->GetTotalSize(), peer);
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

    size_t old_pos = it->second.list_pos;
    assert(m_orphan_list[old_pos] == it);
    if (old_pos + 1 != m_orphan_list.size()) {
        // Unless we're deleting the last entry in m_orphan_list, move the last
        // entry to the position we're deleting.
        auto it_last = m_orphan_list.back();
        m_orphan_list[old_pos] = it_last;
        it_last->second.list_pos = old_pos;
    }
    const auto& txid = it->second.tx->GetHash();
    LogPrint(BCLog::TXPACKAGES, "   removed orphan tx %s (wtxid=%s)\n", txid.ToString(), wtxid.ToString());

    m_orphan_list.pop_back();
    m_wtxid_to_orphan_it.erase(it->second.tx->GetWitnessHash());

    m_orphans.erase(it);
    return 1;
}

std::vector<uint256> TxOrphanage::EraseForPeer(NodeId peer)
{
    LOCK(m_mutex);

    m_peer_work_set.erase(peer);
    std::vector<uint256> wtxids;

    int nErased = 0;
    std::map<uint256, OrphanTx>::iterator iter = m_orphans.begin();
    while (iter != m_orphans.end())
    {
        std::map<uint256, OrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.announcers.count(peer) > 0) {
            wtxids.push_back(maybeErase->second.tx->GetWitnessHash());
            if (maybeErase->second.announcers.size() == 1) {
                nErased += EraseTxNoLock(maybeErase->second.tx->GetWitnessHash());
            } else {
                // Don't erase this orphan. Another peer has also announced it, so it may still be useful.
                maybeErase->second.announcers.erase(peer);
                SubtractOrphanBytes(maybeErase->second.tx->GetTotalSize(), peer);
            }
        }
    }
    if (nErased > 0) LogPrint(BCLog::TXPACKAGES, "Erased %d orphan tx from peer=%d\n", nErased, peer);
    Assume(m_peer_bytes_used.count(peer) == 0);
    m_peer_bytes_used.erase(peer);
    return wtxids;
}

void TxOrphanage::LimitOrphans(unsigned int max_orphans)
{
    LOCK(m_mutex);

    unsigned int nEvicted = 0;
    static int64_t nNextSweep;
    int64_t nNow = GetTime();
    if (nNextSweep <= nNow) {
        // Sweep out expired orphan pool entries:
        int nErased = 0;
        int64_t nMinExpTime = nNow + ORPHAN_TX_EXPIRE_TIME - ORPHAN_TX_EXPIRE_INTERVAL;
        std::map<uint256, OrphanTx>::iterator iter = m_orphans.begin();
        while (iter != m_orphans.end())
        {
            std::map<uint256, OrphanTx>::iterator maybeErase = iter++;
            if (maybeErase->second.nTimeExpire <= nNow) {
                nErased += EraseTxNoLock(maybeErase->second.tx->GetWitnessHash());
            } else {
                nMinExpTime = std::min(maybeErase->second.nTimeExpire, nMinExpTime);
            }
        }
        // Sweep again 5 minutes after the next entry that expires in order to batch the linear scan.
        nNextSweep = nMinExpTime + ORPHAN_TX_EXPIRE_INTERVAL;
        if (nErased > 0) LogPrint(BCLog::TXPACKAGES, "Erased %d orphan tx due to expiration\n", nErased);
    }
    FastRandomContext rng;
    while (m_orphans.size() > max_orphans)
    {
        // Evict a random orphan:
        size_t randompos = rng.randrange(m_orphan_list.size());
        EraseTxNoLock(m_orphan_list[randompos]->second.tx->GetWitnessHash());
        ++nEvicted;
    }
    if (nEvicted > 0) LogPrint(BCLog::TXPACKAGES, "orphanage overflow, removed %u tx\n", nEvicted);
}

void TxOrphanage::AddChildrenToWorkSet(const CTransaction& tx)
{
    LOCK(m_mutex);

    FastRandomContext rng;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(tx.GetHash(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto& elem : it_by_prev->second) {
                // Belt and suspenders, each orphan should always have at least 1 announcer.
                if (!Assume(!elem->second.announcers.empty())) break;
                // Pick a random peer from announcers set.
                auto rand_peer_iter = elem->second.announcers.begin();
                std::advance(rand_peer_iter, rng.randrange(elem->second.announcers.size()));
                // Get this source peer's work set, emplacing an empty set if it didn't exist
                // (note: if this peer wasn't still connected, we would have removed the orphan tx already)
                std::set<uint256>& orphan_work_set = m_peer_work_set.try_emplace(*rand_peer_iter).first->second;
                // Add this tx to the work set
                orphan_work_set.insert(elem->first);
                LogPrint(BCLog::TXPACKAGES, "added %s (wtxid=%s) to peer %d workset\n",
                         tx.GetHash().ToString(), tx.GetWitnessHash().ToString(), *rand_peer_iter);
            }
        }
    }
}

bool TxOrphanage::HaveTx(const GenTxid& gtxid) const
{
    LOCK(m_mutex);
    if (gtxid.IsWtxid()) {
        return m_wtxid_to_orphan_it.count(gtxid.GetHash());
    } else {
        return m_orphans.count(gtxid.GetHash());
    }
}

CTransactionRef TxOrphanage::GetTxToReconsider(NodeId peer)
{
    LOCK(m_mutex);

    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        auto& work_set = work_set_it->second;
        while (!work_set.empty()) {
            uint256 txid = *work_set.begin();
            work_set.erase(work_set.begin());

            const auto orphan_it = m_orphans.find(txid);
            if (orphan_it != m_orphans.end()) {
                return orphan_it->second.tx;
            }
        }
    }
    return nullptr;
}

bool TxOrphanage::HaveTxToReconsider(NodeId peer)
{
    LOCK(m_mutex);

    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        auto& work_set = work_set_it->second;
        return !work_set.empty();
    }
    return false;
}

void TxOrphanage::EraseForBlock(const CBlock& block)
{
    LOCK(m_mutex);

    std::vector<uint256> vOrphanErase;

    for (const CTransactionRef& ptx : block.vtx) {
        const CTransaction& tx = *ptx;

        // Which orphan pool entries must we evict?
        for (const auto& txin : tx.vin) {
            auto itByPrev = m_outpoint_to_orphan_it.find(txin.prevout);
            if (itByPrev == m_outpoint_to_orphan_it.end()) continue;
            for (auto mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi) {
                const CTransaction& orphanTx = *(*mi)->second.tx;
                const uint256& orphanHash = orphanTx.GetWitnessHash();
                vOrphanErase.push_back(orphanHash);
            }
        }
    }

    // Erase orphan transactions included or precluded by this block
    if (vOrphanErase.size()) {
        int nErased = 0;
        for (const uint256& orphanHash : vOrphanErase) {
            nErased += EraseTxNoLock(orphanHash);
        }
        LogPrint(BCLog::TXPACKAGES, "Erased %d orphan tx included or conflicted by block\n", nErased);
    }
}
void TxOrphanage::EraseOrphanOfPeer(const uint256& wtxid, NodeId peer)
{
    AssertLockNotHeld(m_mutex);
    LOCK(m_mutex);
    // Nothing to do if this peer isn't storing any orphans.
    if (m_peer_bytes_used.count(peer) == 0) return;

    // Nothing to do if this tx doesn't exist.
    const auto wtxid_it = m_wtxid_to_orphan_it.find(wtxid);
    if (wtxid_it == m_wtxid_to_orphan_it.end()) return;

    if (wtxid_it->second->second.announcers.count(peer) > 0) {
        if (wtxid_it->second->second.announcers.size() == 1) {
            EraseTxNoLock(wtxid);
        } else {
            // Don't erase this orphan. Another peer has also announced it, so it may still be useful.
            wtxid_it->second->second.announcers.erase(peer);
            SubtractOrphanBytes(wtxid_it->second->second.tx->GetTotalSize(), peer);
        }
    }
}

std::optional<std::vector<uint256>> TxOrphanage::GetParentTxids(const uint256& wtxid)
{
    AssertLockNotHeld(m_mutex);
    LOCK(m_mutex);
    const auto it = m_wtxid_to_orphan_it.find(wtxid);
    if (it != m_wtxid_to_orphan_it.end()) return it->second->second.parent_txids;
    return std::nullopt;
}
