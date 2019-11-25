// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERNALMINER_H
#define BITCOIN_INTERNALMINER_H

#include "primitives/block.h"

#include <stdint.h>
#include <txmempool.h>
#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>

#define THREAD_PRIORITY_LOWEST 20

class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;

namespace internal_miner
{
struct ExtNonce
{
    uint32_t tip_block_height;
    uint32_t tip_block_hash;
    uint32_t nonce;

    bool isSet() const {
        return tip_block_height == 0 && tip_block_hash == 0 && nonce == 0;
    }
};

bool verifyTransactionHash(const CTransaction &txn, bool checkTxInTip);

class Miner {
    boost::mutex m_minerMutex;
    bool m_foundHash = false;
    int m_numThreads;
    boost::thread_group m_minerThreads;

    void mineTransactionWorker(CMutableTransaction& inputTxn, ExtNonce& inputExtNonce);
public:
    explicit Miner(int numThreads);
    Miner(const Miner&) = delete;
    Miner& operator=(const Miner&) = delete;
    ~Miner();

    void mineTransaction(CMutableTransaction& txn, ExtNonce& extNonce);
};

}

#endif // BITCOIN_INTERNALMINER_H
