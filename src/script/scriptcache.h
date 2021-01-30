// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPTCACHE_H
#define BITCOIN_SCRIPT_SCRIPTCACHE_H

#include <script/sigcache.h>

#include <cuckoocache.h>
#include <random.h>
#include <uint256.h>

namespace {
/**
 * Valid script cache used to avoid doing expensive script checks twice for
 * every transaction (once when accepted into memory pool, and again when
 * included a block).
 */
class CScriptCache
{
    private:
        //! Entries are SHA256(nonce || transaction witness hash || script verification flags):
        CSHA256 m_salted_hasher;
        CuckooCache::cache<uint256, SignatureCacheHasher> m_set_scripts;

    public:
        CScriptCache()
        {
            // Setup the salted hasher
            uint256 nonce = GetRandHash();
            // We want the nonce to be 64 bytes long to force the hasher to process
            // this chunk, which makes later hash computations more efficient. We
            // just write our 32-byte entropy twice to fill the 64 bytes.
            m_salted_hasher.Write(nonce.begin(), 32);
            m_salted_hasher.Write(nonce.begin(), 32);
        }
        uint256 ComputeEntry(const uint256 &hash, const unsigned int flags) const
        {
            uint256 entry;
            CSHA256 hasher = m_salted_hasher;
            hasher.Write(hash.begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(entry.begin());
            return entry;
        }

        bool Get(const uint256& entry, const bool erase)
        {
            return m_set_scripts.contains(entry, erase);
        }

        void Add(const uint256& entry)
        {
            m_set_scripts.insert(entry);
        }

        uint32_t setup_bytes(size_t n)
        {
            return m_set_scripts.setup_bytes(n);
        }
};
} // namespace

#endif // BITCOIN_SCRIPT_SCRIPTCACHE_H
