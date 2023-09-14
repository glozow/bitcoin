// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txorphanage.h>

#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>
#include <primitives/transaction.h>

#include <cassert>

/** Expiration time for orphan transactions in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_TIME = 20 * 60;
/** Minimum time between orphan transactions expire time checks in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_INTERVAL = 5 * 60;

void TxOrphanage::AddOrphanBytes(unsigned int size, NodeId peer)
{
    AssertLockHeld(m_mutex);
    m_peer_bytes_used.try_emplace(peer, 0);
    m_peer_bytes_used.at(peer) += size;
}

void TxOrphanage::SubtractOrphanBytes(unsigned int size, NodeId peer)
{
    AssertLockHeld(m_mutex);
    // If our accounting is off, control damage by ensuring we clean up m_peer_bytes_used.
    if (!Assume(m_peer_bytes_used.count(peer) > 0)) return;
    if (!Assume(m_peer_bytes_used.at(peer) >= size)) {
        // Equivalent of bytes going to 0.
        m_peer_bytes_used.erase(peer);
        return;
    }

    m_peer_bytes_used.at(peer) -= size;
    if (m_peer_bytes_used.at(peer) == 0) {
        m_peer_bytes_used.erase(peer);
    }
}

bool TxOrphanage::AddTx(const CTransactionRef& tx, NodeId peer, const std::vector<Txid>& parent_txids)
{
    LOCK(m_mutex);

    const Txid& hash = tx->GetHash();
    const Wtxid& wtxid = tx->GetWitnessHash();
    if (m_orphans.count(hash))
        return false;

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

    auto ret = m_orphans.emplace(hash, OrphanTx{tx, peer, GetTime() + ORPHAN_TX_EXPIRE_TIME, m_orphan_list.size(), parent_txids});
    assert(ret.second);
    m_orphan_list.push_back(ret.first);
    // Allow for lookups in the orphan pool by wtxid, as well as txid
    m_wtxid_to_orphan_it.emplace(wtxid, ret.first);
    for (const CTxIn& txin : tx->vin) {
        m_outpoint_to_orphan_it[txin.prevout].insert(ret.first);
    }

    AddOrphanBytes(tx->GetTotalSize(), peer);
    m_total_orphan_bytes += tx->GetTotalSize();
    LogPrint(BCLog::TXPACKAGES, "stored orphan tx %s (wtxid=%s) (mapsz %u outsz %u)\n", hash.ToString(), wtxid.ToString(),
             m_orphans.size(), m_outpoint_to_orphan_it.size());
    return true;
}

CTransactionRef TxOrphanage::GetTx(const Wtxid& wtxid)
{
   LOCK(m_mutex);
   const auto it = m_wtxid_to_orphan_it.find(wtxid);
   return it == m_wtxid_to_orphan_it.end() ? nullptr : it->second->second.tx;
}

int TxOrphanage::EraseTx(const Wtxid& wtxid)
{
    LOCK(m_mutex);
    return EraseTxNoLock(wtxid);
}

int TxOrphanage::EraseTxNoLock(const Wtxid& wtxid)
{
    AssertLockHeld(m_mutex);
    const auto wtxid_it = m_wtxid_to_orphan_it.find(wtxid);
    if (wtxid_it == m_wtxid_to_orphan_it.end()) return 0;
    std::map<Txid, OrphanTx>::iterator it = wtxid_it->second;
    m_total_orphan_bytes -= it->second.tx->GetTotalSize();
    SubtractOrphanBytes(it->second.tx->GetTotalSize(), it->second.fromPeer);
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
    m_wtxid_to_orphan_it.erase(wtxid);

    m_orphans.erase(it);
    return 1;
}

void TxOrphanage::EraseForPeer(NodeId peer)
{
    LOCK(m_mutex);

    m_peer_work_set.erase(peer);

    int nErased = 0;
    std::map<Txid, OrphanTx>::iterator iter = m_orphans.begin();
    while (iter != m_orphans.end())
    {
        std::map<Txid, OrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer)
        {
            nErased += EraseTxNoLock(maybeErase->second.tx->GetWitnessHash());
        }
    }
    if (nErased > 0) LogPrint(BCLog::TXPACKAGES, "Erased %d orphan tx from peer=%d\n", nErased, peer);
    // Belt-and-suspenders if our accounting is off. We shouldn't keep an entry for a disconnected
    // peer as we will have no other opportunity to delete it.
    if (!Assume(m_peer_bytes_used.count(peer) == 0)) m_peer_bytes_used.erase(peer);
}

void TxOrphanage::LimitOrphans(unsigned int max_orphans, unsigned int max_total_size, FastRandomContext& rng)
{
    LOCK(m_mutex);

    unsigned int nEvicted = 0;
    static int64_t nNextSweep;
    int64_t nNow = GetTime();
    if (nNextSweep <= nNow) {
        // Sweep out expired orphan pool entries:
        int nErased = 0;
        int64_t nMinExpTime = nNow + ORPHAN_TX_EXPIRE_TIME - ORPHAN_TX_EXPIRE_INTERVAL;
        std::map<Txid, OrphanTx>::iterator iter = m_orphans.begin();
        while (iter != m_orphans.end())
        {
            std::map<Txid, OrphanTx>::iterator maybeErase = iter++;
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
    while (m_orphans.size() > max_orphans || m_total_orphan_bytes > max_total_size)
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


    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(tx.GetHash(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto& elem : it_by_prev->second) {
                // Get this source peer's work set, emplacing an empty set if it didn't exist
                // (note: if this peer wasn't still connected, we would have removed the orphan tx already)
                std::set<Txid>& orphan_work_set = m_peer_work_set.try_emplace(elem->second.fromPeer).first->second;
                // Add this tx to the work set
                orphan_work_set.insert(elem->first);
                LogPrint(BCLog::TXPACKAGES, "added %s (wtxid=%s) to peer %d workset\n",
                         tx.GetHash().ToString(), tx.GetWitnessHash().ToString(), elem->second.fromPeer);
            }
        }
    }
}

bool TxOrphanage::HaveTx(const GenTxid& gtxid) const
{
    LOCK(m_mutex);
    if (gtxid.IsWtxid()) {
        return m_wtxid_to_orphan_it.count(Wtxid::FromUint256(gtxid.GetHash()));
    } else {
        return m_orphans.count(Txid::FromUint256(gtxid.GetHash()));
    }
}

CTransactionRef TxOrphanage::GetTxToReconsider(NodeId peer)
{
    LOCK(m_mutex);

    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        auto& work_set = work_set_it->second;
        while (!work_set.empty()) {
            Txid txid = *work_set.begin();
            work_set.erase(work_set.begin());

            const auto orphan_it = m_orphans.find(txid);
            if (orphan_it != m_orphans.end()) {
                return orphan_it->second.tx;
            }
        }
    }
    return nullptr;
}

bool TxOrphanage::HaveTxToReconsider(NodeId peer) const
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
        for (const Wtxid& orphan_wtxid : vOrphanErase) {
            nErased += EraseTxNoLock(orphan_wtxid);
        }
        LogPrint(BCLog::TXPACKAGES, "Erased %d orphan tx included or conflicted by block\n", nErased);
    }
}

std::vector<CTransactionRef> TxOrphanage::GetChildren(const CTransactionRef& parent, NodeId peer) const
{
    LOCK(m_mutex);
    std::vector<CTransactionRef> children_found;

    for (unsigned int i = 0; i < parent->vout.size(); i++) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(parent->GetHash(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto& elem : it_by_prev->second) {
                children_found.emplace_back(elem->second.tx);
            }
        }
    }
    return children_found;
}

std::optional<std::vector<Txid>> TxOrphanage::GetParentTxids(const Wtxid& wtxid)
{
    AssertLockNotHeld(m_mutex);
    LOCK(m_mutex);
    const auto it = m_wtxid_to_orphan_it.find(wtxid);
    if (it != m_wtxid_to_orphan_it.end()) return it->second->second.parent_txids;
    return std::nullopt;
}
