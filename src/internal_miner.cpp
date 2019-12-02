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
#include "validation.h"
#include "pow.h"
#include "chainparams.h"
#include "shutdown.h"
#include "chain.h"

#include <boost/thread.hpp>

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

bool RecentMsgTxnsCache::CheckMsgTransaction(const uint256& txn) const {
    return m_recentMsgTxns.find(txn) == m_recentMsgTxns.end();
}

bool RecentMsgTxnsCache::LoadRecentMsgTxns(const CChain& pchainActive) {
    AssertLockHeld(cs_main);
    const int lastToReadHeight = (pchainActive.Height() > MSG_TXN_ACCEPTED_DEPTH) ? (pchainActive.Height() - MSG_TXN_ACCEPTED_DEPTH) : 0;

    for (int height=pchainActive.Height(); height > lastToReadHeight; --height){
        CBlock block;
        if (!ReadBlockFromDisk(block, pchainActive[height], Params().GetConsensus())) {
            std::cout << "Failed to read block in loadRecentMsgTxns!!!\n";
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

bool ScanHash(CMutableTransaction& txn, ExtNonce &extNonce, uint256 *phash, std::vector<unsigned char>& opReturnData)
{
    while (true)
    {
        ++extNonce.nonce;

        CScript& txn_script = txn.vout[0].scriptPubKey;
        auto it = std::search(txn_script.begin(), txn_script.end(), ENCR_FREE_MARKER.begin(), ENCR_FREE_MARKER.end());
        if (it != txn_script.end())
        {
            int extNonceShift = std::distance(txn_script.begin(), it) + ENCR_MARKER_SIZE;
            if (txn_script.size() >= extNonceShift+sizeof(ExtNonce))
            {
                std::memcpy(txn_script.data()+extNonceShift,   &extNonce.tip_block_height, sizeof(uint32_t));
                std::memcpy(txn_script.data()+extNonceShift+4, &extNonce.tip_block_hash,  sizeof(uint32_t));
                std::memcpy(txn_script.data()+extNonceShift+8, &extNonce.nonce, sizeof(uint32_t));
            }
        }

        *phash = txn.GetHash();

         // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint8_t*)phash)[31] == 0x80)
            return true;

        // If nothing found after trying for a while, return -1
        if ((extNonce.nonce & 0xfff) == 0)
            return false;
    }
    return false;
}

CAmount getMsgFee(const CTransaction& txn) {
    CAmount fee = 0;
    getTxnCost(txn, fee);
    return fee*0.5;
}

bool getTxnCost(const CTransaction& txn, CAmount& cost) {
    const unsigned int txSize = txn.GetTotalSize();

    // Msg transaction can have at most 100 characters for subject
    // and 1000 characters for content
    constexpr unsigned int minSize = 1078, maxSize = 2182;

    if (txSize < minSize || txSize > maxSize) {
        std::cout << "ERROR getTxnCost - size " << txSize << std::endl;
        return false;
    }

    //TODO: Find what feePerByte should be
    constexpr CAmount feePerByte = 10;
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
    const uint32_t ratio = blockReward / txnCost;

    std::cout << "blockReward: " << blockReward << std::endl;
    std::cout << "txnCost: " << txnCost << std::endl;
    std::cout << "ratio: " << ratio << std::endl;

    arith_uint256 blockTarget = arith_uint256().SetCompact(indexPrev->nBits);
    arith_uint256 txnTarget = blockTarget * ratio;

    uint256 txnTargetUint256 = ArithToUint256(txnTarget);
    txnTargetUint256.flip_bit(PICO_BIT_POS);

    std::cout << "Target for block = " << blockTarget.ToString() << " = " << blockTarget.getdouble() << std::endl;
    std::cout << "Target for txn = "<< txnTarget.ToString() << " = " << txnTarget.getdouble() << std::endl;

    target = UintToArith256(txnTargetUint256);
    return true;
}

bool readExtNonce(const CTransaction& txn, ExtNonce& extNonce)
{
    //TODO: there should be a faster way of getting tx height
    std::vector<char> opReturn = txn.loadOpReturn();

    const uint32_t minSize = ENCR_MARKER_SIZE + 3 * sizeof(uint32_t);
    if (opReturn.size() < minSize)
        return false;

    std::memcpy(&extNonce.tip_block_height, opReturn.data()+ENCR_MARKER_SIZE, sizeof(uint32_t));
    std::memcpy(&extNonce.tip_block_hash, opReturn.data()+ENCR_MARKER_SIZE+4, sizeof(uint32_t));
    std::memcpy(&extNonce.nonce, opReturn.data()+ENCR_MARKER_SIZE+8, sizeof(uint32_t));
    return true;
}

bool verifyTransactionHash(const CTransaction& txn, TxPoWCheck powCheck)
{
    if (!txn.IsMsgTx()) {
        LogPrintf("Error: proof-of-work verification failed, non message transaction\n");
        return false;
    }

    ExtNonce extNonce;
    if (!readExtNonce(txn, extNonce)) {
        std::cout << "Could not read extNonce\n";
        return false;
    }

    CBlockIndex* prevBlock = chainActive[extNonce.tip_block_height];
    if (!prevBlock) {
        std::cout << "Error: verifyTransactionHash - prevBlock is null\n";
        return false;
    }

    arith_uint256 hashTarget;
    if (!getTarget(txn, prevBlock, hashTarget)) {
        LogPrintf("proof-of-work verification failed, could not calculate target\n");
        return false;
    }

    uint256 hash = txn.GetHash();
    LogPrintf("proof-of-work verification  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    LogPrintf("  tip_block hash: %u\t tip_block height: %d\n", extNonce.tip_block_hash, extNonce.tip_block_height);
    LogPrintf("  tip_block hash: %u\t tip_block height: %d\n", (uint32_t)prevBlock->GetBlockHash().GetUint64(0), (uint32_t)prevBlock->nHeight);

    if (((uint8_t*)&hash)[31] != 0x80) {
        std::cout << "\tError: verifyTransactionHash - hash does not start with 0x80" << std::endl;
        return false;
    }
    if (UintToArith256(hash) > hashTarget) {
        std::cout << "\tError: verifyTransactionHash - hash > hashTarget " << std::endl;
        return false;
    }
    if ((uint32_t)prevBlock->nHeight != extNonce.tip_block_height) {
        printf("\tError: verifyTransactionHash - height not correct. prevBlock.height:%d, tip_block_height:%u \n", prevBlock->nHeight, extNonce.tip_block_height);
        return false;
    }
    if ((uint32_t)prevBlock->GetBlockHash().GetUint64(0) != extNonce.tip_block_hash) {
        std::cout << "\tError: verifyTransactionHash - hash part not correct " << std::endl;
        return false;
    }

    // When verifying txn in mempool or block, check txn was added during the last 6 blocks
    // and is not already added to blockchain
    if (powCheck == FOR_BLOCK || powCheck == FOR_MEMPOOL) {
        //TODO: Check if depth of 6 is correct for all places this function is called
        const uint32_t currHeight = chainActive.Height();
        const uint32_t minAcceptedHeight =
            (currHeight > MSG_TXN_ACCEPTED_DEPTH) ? (currHeight-MSG_TXN_ACCEPTED_DEPTH) : 0;

        if (extNonce.tip_block_height < minAcceptedHeight) {
            std::cout << "\tTxn " << txn.GetHash().ToString() << " too old!!!!\n";
            return false;
        }

        if (!precentMsgTxnCache->CheckMsgTransaction(txn.GetHash())) {
            std::cout << "\t!!!!Txn " << txn.GetHash().ToString() << " among recent transactions!!!!\n";
            return false;
        }
    }

    return true;
}



void Miner::mineTransactionWorker(CMutableTransaction& inputTxn, internal_miner::ExtNonce& inputExtNonce, uint32_t nonceStart)
{
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
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

    std::vector<unsigned char> opReturn = txn.loadOpReturn();

    while (true) {

        CBlockIndex *prevBlock = chainActive.Tip();
        LogPrintf("block hash: %s, height: %u\n", prevBlock->GetBlockHash().ToString().c_str(), prevBlock->nHeight);

        arith_uint256 hashTarget;
        if (!getTarget(txn, prevBlock, hashTarget))
            throw std::runtime_error("Failed to mine transaction");
        LogPrintf("Hash target: %s\n", hashTarget.GetHex().c_str());

        uint256 hash;
        ExtNonce extNonce{(uint32_t)prevBlock->nHeight, (uint32_t)prevBlock->GetBlockHash().GetUint64(0), nonceStart};

        while (true) {
            // Check if something found
            if (ScanHash(txn, extNonce, &hash, opReturn))
            {
                if (UintToArith256(txn.GetHash()) <= hashTarget)
                {
                    // Found a solution
                    boost::lock_guard<boost::mutex> lock(m_minerMutex);
                    if (!m_foundHash) {
                        m_foundHash = true;
                        inputTxn = txn;
                        inputExtNonce = extNonce;

                        LogPrintf("InternalMiner:\n");
                        LogPrintf("proof-of-work for transaction found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                        LogPrintf("Block height:%u Block hash:%u nonce:%u\n", extNonce.tip_block_height, extNonce.tip_block_hash, extNonce.nonce);
                    }
                    return;
                }
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
