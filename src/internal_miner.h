// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERNALMINER_H
#define BITCOIN_INTERNALMINER_H

#include "primitives/block.h"

#include <stdint.h>
#include <map>
#include <txmempool.h>
#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>

class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;
class CChain;

namespace internal_miner
{

enum TxPoWCheck {
    FOR_BLOCK,      // checks performed to verify txn in new block
    FOR_MEMPOOL,    // checks performed to verify if txn should remain in mempool or be discarded
    FOR_DB          // checks if hash and height in txn match, e.g. used in verify db
};

struct ExtNonce
{
    uint32_t tip_block_height;
    uint32_t tip_block_hash;
    uint32_t nonce;

    bool isNull() const {
        return tip_block_height == 0 && tip_block_hash == 0 && nonce == 0;
    }
};

bool CheckMsgTxnSize(const CTransaction& txn);
CAmount getMsgFee(const CTransaction& txn);
bool getTxnCost(const CTransaction& txn, CAmount& cost);
bool verifyTransactionHash(const CTransaction &txn, CValidationState& state, TxPoWCheck powCheck);
bool readExtNonce(const CTransaction& txn, ExtNonce& extNonce);

class RecentMsgTxnsCache {
    std::map<uint256, int> m_recentMsgTxns;
public:
    RecentMsgTxnsCache() = default;
    ~RecentMsgTxnsCache() = default;
    RecentMsgTxnsCache(const RecentMsgTxnsCache&) = delete;
    RecentMsgTxnsCache& operator=(const RecentMsgTxnsCache&) = delete;

    bool VerifyMsgTxn(const uint256& txn) const;
    bool LoadRecentMsgTxns(const CChain& pchainActive);
    bool ReloadRecentMsgTxns(const CChain& pchainActive);
    void UpdateMsgTxns(std::vector<CTransactionRef> txns, const CChain& pchainActive);
};

class Miner {
    CWallet& m_wallet;
    uint32_t m_numThreads;
    boost::mutex m_minerMutex;
    bool m_foundHash = false;
    boost::thread_group m_minerThreads;

    void mineTransactionWorker(CMutableTransaction& inputTxn, ExtNonce& inputExtNonce, uint32_t nonceStart);
public:
    Miner(CWallet& pwallet, uint32_t numThreads);
    Miner(const Miner&) = delete;
    Miner& operator=(const Miner&) = delete;
    ~Miner();

    void mineTransaction(CMutableTransaction& txn, ExtNonce& extNonce);
};

}

#endif // BITCOIN_INTERNALMINER_H
