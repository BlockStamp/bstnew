// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "internal_miner.h"

#include "arith_uint256.h"
#include "messages/message_encryption.h"
#include "wallet/wallet.h"
#include "streams.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "consensus/validation.h"
#include "validation.h"
#include "pow.h"
#include "chainparams.h"
#include "shutdown.h"
#include "chain.h"

#include <boost/thread.hpp>
#include <openssl/sha.h>

using namespace std;

namespace internal_miner
{

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
//

bool RecentMsgTxnsCache::VerifyMsgTxn(const uint256& txn) const {
    return m_recentMsgTxns.find(txn) == m_recentMsgTxns.end();
}

bool RecentMsgTxnsCache::LoadRecentMsgTxns(const CChain& pchainActive) {
    AssertLockHeld(cs_main);
    const int lastToReadHeight = (pchainActive.Height() > MSG_TXN_ACCEPTED_DEPTH) ? (pchainActive.Height() - MSG_TXN_ACCEPTED_DEPTH) : 0;

    for (int height=pchainActive.Height(); height > lastToReadHeight; --height){
        CBlock block;
        if (!ReadBlockFromDisk(block, pchainActive[height], Params().GetConsensus())) {
            return false;
        }

        for (const CTransactionRef& txn : block.vtx) {
            if (txn->IsMsgTx()) {
                m_recentMsgTxns.insert({txn->GetHash(), height});
            }
        }
    }

    return true;
}

bool RecentMsgTxnsCache::ReloadRecentMsgTxns(const CChain& pchainActive) {
    AssertLockHeld(cs_main);
    m_recentMsgTxns.clear();
    if (!LoadRecentMsgTxns(pchainActive)) {
        StartShutdown();
        LogPrintf("Failed to read recent msg txn during disconnecting tip, new tip\n");
        return false;
    }
    return true;
}


void RecentMsgTxnsCache::UpdateMsgTxns(std::vector<CTransactionRef> txns, const CChain& pchainActive) {
    AssertLockHeld(cs_main);
    const int lastToReadHeight = (pchainActive.Height() > MSG_TXN_ACCEPTED_DEPTH) ? (pchainActive.Height() - MSG_TXN_ACCEPTED_DEPTH) : 0;

    //Remove too old msg transactions
    auto it = m_recentMsgTxns.begin();
    while (it != m_recentMsgTxns.end()) {
        if (it->second <= lastToReadHeight) {
            it = m_recentMsgTxns.erase(it);
        }
        else {
            ++it;
        }
    }

    //Add msg transactions from a new block
    for (const CTransactionRef& txn : txns) {
        if (txn->IsMsgTx()) {
            m_recentMsgTxns.insert({txn->GetHash(), pchainActive.Height()});
        }
    }
}

bool ScanHash(CMutableTransaction& txn, ExtNonce &extNonce, uint256 *phash)
{
    CObjHash cHash;
    txn.SerializeMsg(cHash);
    cHash.updateBlockInfo(extNonce.tip_block_height, extNonce.tip_block_hash);

    while (true)
    {
        ++extNonce.nonce;
        if (cHash.updateNonce(extNonce.nonce, 0x8000))
        {

            // Return the nonce if the hash has at least some zero bits,
            // caller will check if it has enough to reach the target
            *phash = cHash.getHash();
            return true;
        }

        // If nothing found after trying for a while, return -1
        if ((extNonce.nonce & 0xfff) == 0)
            return false;
    }
    return false;
}

CAmount getMsgFee(const CTransaction& txn) {
    CAmount fee = 0;
    getTxnCost(txn, fee);
    return fee*0.25;
}

bool getTxnCost(const CTransaction& txn, CAmount& cost) {
    const unsigned int txSize = txn.GetTotalSize();

    // Msg transaction can have at most 100 characters for subject
    // and 1000 characters for content
    constexpr unsigned int minSize = 1078, maxSize = 2182;

    if (txSize < minSize || txSize > maxSize) {
        return false;
    }

    //TODO: Find what feePerByte should be
    constexpr CAmount feePerByte = 1;
    cost = txSize * feePerByte;
    return true;
}

static bool getTarget(const CTransaction& txn, const CBlockIndex* indexPrev, arith_uint256& target)
{
    const CAmount blockReward = GetBlockSubsidy(indexPrev->nHeight, Params().GetConsensus());
    CAmount txnCost = 0;
    if (!getTxnCost(txn, txnCost)) {
        LogPrintf("Error: Failed to calculate message transaction cost\n");
        return false;
    }

    const uint32_t ratio = (blockReward / txnCost);

    // Only for regtest
    if (Params().GetConsensus().fPowAllowMinDifficultyBlocks) {
        arith_uint256 dummyBlockTarget= arith_uint256("0000000000ffff00000000000000000000000000000000000000000000000000");
        arith_uint256 dummyTxnTarget = dummyBlockTarget * ratio;

        uint256 txnTargetUint256 = ArithToUint256(dummyTxnTarget);
        txnTargetUint256.flip_bit(PICO_BIT_POS);

        target = UintToArith256(txnTargetUint256);
        LogPrintf("Dummy target: %s\n", dummyTxnTarget.ToString());
        return true;
    }

    arith_uint256 blockTarget = arith_uint256().SetCompact(indexPrev->nBits);
    arith_uint256 txnTarget = blockTarget * ratio;

    uint256 txnTargetUint256 = ArithToUint256(txnTarget);
    txnTargetUint256.flip_bit(PICO_BIT_POS);

    target = UintToArith256(txnTargetUint256);
    return true;
}

bool readExtNonce(const CTransaction& txn, ExtNonce& extNonce)
{
    //TODO: there should be a faster way of getting tx height
    std::vector<char> opReturn = txn.loadOpReturn();
    size_t size = opReturn.size();

    const uint32_t minSize = ENCR_MARKER_SIZE + 3 * sizeof(uint32_t);
    if (size < minSize)
        return false;

    std::memcpy(&extNonce.tip_block_height, opReturn.data()+size-12, sizeof(uint32_t));
    std::memcpy(&extNonce.tip_block_hash, opReturn.data()+size-8, sizeof(uint32_t));
    std::memcpy(&extNonce.nonce, opReturn.data()+size-4, sizeof(uint32_t));
    return true;
}

bool verifyTransactionHash(const CTransaction& txn, CValidationState& state, TxPoWCheck powCheck)
{
    assert(txn.IsMsgTx());

    ExtNonce extNonce;
    if (!readExtNonce(txn, extNonce)) {
        return state.DoS(100, false, REJECT_INVALID, "msg-txn-bad-extra-nonce", false, "Msg txn with incorrect ext nonce");
    }

    CBlockIndex* prevBlock = chainActive[extNonce.tip_block_height];
    if (!prevBlock) {
        return state.DoS(100, false, REJECT_INVALID, "msg-txn-with-bad-prev-block", false, "Msg txn with bad prev block");
    }

    arith_uint256 hashTarget;
    if (!getTarget(txn, prevBlock, hashTarget)) {
        LogPrintf("proof-of-work verification failed, could not calculate target\n");
        return state.DoS(100, false, REJECT_INVALID, "msg-txn-no-get-target", false, "Could not get target of msg txn");
    }

    uint256 hash = CMutableTransaction(txn).GetMsgHash();
    LogPrintf("proof-of-work verification  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    LogPrintf("  tip_block hash: %u\t tip_block height: %d\n", extNonce.tip_block_hash, extNonce.tip_block_height);
    LogPrintf("  tip_block hash: %u\t tip_block height: %d\n", (uint32_t)prevBlock->GetBlockHash().GetUint64(0), (uint32_t)prevBlock->nHeight);

    if (((uint8_t*)&hash)[31] != 0x80) {
        return state.DoS(100, false, REJECT_INVALID, "msg-txn-bad-hash", false, "Msg txn with bad hash");
    }
    if (UintToArith256(hash) > hashTarget) {
        return state.DoS(100, false, REJECT_INVALID, "msg-txn-hash-above-target", false, "Msg txn with bad hash");
    }
    if ((uint32_t)prevBlock->nHeight != extNonce.tip_block_height) {
        return state.DoS(100, false, REJECT_INVALID, "msg-txn-bad-prev-block-height", false, "Msg txn with bad previous block height");
    }
    if ((uint32_t)prevBlock->GetBlockHash().GetUint64(0) != extNonce.tip_block_hash) {
        return state.DoS(100, false, REJECT_INVALID, "msg-txn-bad-prev-block-hash", false, "Msg txn with bad previous block hash");
    }

    // When verifying txn in mempool or block, check that txn was added during the last 6 blocks
    // and is not already added to blockchain
    if (powCheck == FOR_BLOCK || powCheck == FOR_MEMPOOL) {
        //TODO: Check if depth of 6 is correct for all places this function is called
        const uint32_t currHeight = chainActive.Height();
        const uint32_t minAcceptedHeight =
            (currHeight > MSG_TXN_ACCEPTED_DEPTH) ? (currHeight-MSG_TXN_ACCEPTED_DEPTH) : 0;

        if (extNonce.tip_block_height < minAcceptedHeight) {
            return state.DoS(100, false, REJECT_INVALID, "msg-txn-too-old", false, "Msg txn is too old");
        }

        if (!recentMsgTxnCache.VerifyMsgTxn(txn.GetHash())) {
            return state.DoS(100, false, REJECT_INVALID, "msg-txn-among-recent", false, "Msg txn is among recent msg transactions");
        }
    }

    return true;
}



void Miner::mineTransactionWorker(CMutableTransaction& inputTxn, internal_miner::ExtNonce& inputExtNonce, uint32_t nonceStart)
{
    RenameThread("bst-msg-txn-miner");

    CMutableTransaction txn;
    {
        boost::lock_guard<boost::mutex> lock(m_minerMutex);
        if (m_foundHash) {
            return;
        }

        // work on copy
        txn = inputTxn;
    }


    if (txn.vout.size() != 1) {
        return;
    }

    int start = GetTime();
    CScript& txn_script = txn.vout[0].scriptPubKey;

    while (true) {
        CBlockIndex *prevBlock = chainActive.Tip();
        LogPrintf("block hash: %s, height: %u\n", prevBlock->GetBlockHash().ToString().c_str(), prevBlock->nHeight);

        arith_uint256 hashTarget;
        if (!getTarget(txn, prevBlock, hashTarget))
            throw std::runtime_error("Failed to mine transaction");
        LogPrintf("Hash target: %s\n", hashTarget.GetHex().c_str());

        uint256 hash;
        ExtNonce extNonce{(uint32_t)prevBlock->nHeight, (uint32_t)prevBlock->GetBlockHash().GetUint64(0), nonceStart};
        std::memcpy(txn_script.data()+txn_script.size() - 12, &extNonce.tip_block_height, sizeof(extNonce.tip_block_height));
        std::memcpy(txn_script.data()+txn_script.size() - 8, &extNonce.tip_block_hash, sizeof(extNonce.tip_block_hash));

        while (true) {
            // Check if something found
            try {
                if (ScanHash(txn, extNonce, &hash))
                {
                    if (UintToArith256(hash) <= hashTarget)
                    {
                        // Found a solution
                        std::memcpy(txn_script.data()+txn_script.size() - 4, &extNonce.nonce, sizeof(extNonce.nonce));
                        boost::lock_guard<boost::mutex> lock(m_minerMutex);
                        if (!m_foundHash) {
                            m_foundHash = true;
                            inputTxn = txn;
                            inputExtNonce = extNonce;

                            LogPrintf("InternalMiner:\n");
                            LogPrintf("proof-of-work for transaction found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                            LogPrintf("Block height:%u Block hash:%u nonce:%u\n", extNonce.tip_block_height, extNonce.tip_block_hash, extNonce.nonce);
                            LogPrintf("Duration: %ldseconds\n", GetTime() - start);
                        }
                        return;
                    }
                }
            } catch (std::exception& e)
            {
                LogPrintf("Internal Miner Exception: %s\n", e.what());
                return;
            }

            {
                boost::lock_guard<boost::mutex> lock(m_minerMutex);
                if (m_foundHash) { // Hash found on another thread
                    return;
                }
            }

            if (ShutdownRequested()) {
                return;
            }

            if (m_wallet.IsAbortingMsgTxns()) {
                return;
            }

            if (extNonce.nonce >= 0xffff0000) {
                break;
            }
            if (prevBlock != chainActive.Tip()) {
                printf("Internal miner: New block detected\n");
                break;
            }
        }
    }
}

Miner::Miner(CWallet& pwallet, uint32_t numThreads) : m_wallet(pwallet), m_numThreads(numThreads) {
}

Miner::~Miner() {
    m_minerThreads.join_all();
}

void Miner::mineTransaction(CMutableTransaction& txn, ExtNonce& extNonce) {
    m_wallet.ResetAbortingMsgTxns();

    const uint32_t nonceOffset = std::numeric_limits<uint32_t>::max() / m_numThreads;
    for (uint32_t i=0; i<m_numThreads; ++i) {
        m_minerThreads.create_thread(boost::bind(&Miner::mineTransactionWorker, this, boost::ref(txn), boost::ref(extNonce), i*nonceOffset));
    }
}

}
