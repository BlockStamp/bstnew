// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "internal_miner.h"

#include "arith_uint256.h"
#include "messages/message_encryption.h"
#include "streams.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "validation.h"
#include "pow.h"
#include "chainparams.h"

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
bool ScanHash(CMutableTransaction& txn, ExtNonce &extNonce, uint256 *phash, std::vector<unsigned char>& opReturnData)
{
    // Write the first 76 bytes of the block header to a double-SHA256 state.
//    CHash256 hasher;
//    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
//    ss << txn->GetHash();
//    hasher.Write((unsigned char*)&ss[0], 76);

    while (true)
    {
        ++extNonce.nonce;

        std::memcpy(opReturnData.data()+ENCR_MARKER_SIZE , &extNonce.tip_block_height, sizeof(uint32_t));
        std::memcpy(opReturnData.data()+ENCR_MARKER_SIZE+4, &extNonce.tip_block_hash, sizeof(uint32_t));
        std::memcpy(opReturnData.data()+ENCR_MARKER_SIZE+8, &extNonce.nonce, sizeof(uint32_t));

        CScript nScript;
        nScript << OP_RETURN << opReturnData;
        txn.vout[0].scriptPubKey = nScript;

        *phash = txn.GetHash();

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result.
//        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint16_t*)phash)[15] == 0x8000)
            return true;

        // If nothing found after trying for a while, return -1
        if ((extNonce.nonce & 0xfff) == 0)
            return false;
    }
    return false;
}

static bool getTxnCost(const CTransaction& txn, CAmount& cost) {
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

static bool getTarget(const CTransaction& txn, arith_uint256& target)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);

    const CAmount blockReward = GetBlockSubsidy(chainActive.Height(), Params().GetConsensus());
    CAmount txnCost = 0;
    if (!getTxnCost(txn, txnCost)) {
        LogPrintf("Error: Failed to calculate message transaction cost\n");
        return false;
    }
    const uint32_t ratio = blockReward / txnCost;

    std::cout << "blockReward: " << blockReward << std::endl;
    std::cout << "txnCost: " << txnCost << std::endl;
    std::cout << "ratio: " << ratio << std::endl;

    unsigned int nBits = GetNextWorkRequired(pindexPrev, nullptr, Params().GetConsensus());
    arith_uint256 blockTarget = arith_uint256().SetCompact(nBits);
    arith_uint256 txnTarget = blockTarget * ratio;

    uint256 txnTargetUint256 = ArithToUint256(txnTarget);
    txnTargetUint256.flip_bit(PICO_BIT_POS);

    std::cout << "Target for block = " << blockTarget.ToString() << " = " << blockTarget.getdouble() << std::endl;
    std::cout << "Target for txn = "<< txnTarget.ToString() << " = " << txnTarget.getdouble() << std::endl;

    target = UintToArith256(txnTargetUint256);
    return true;
}

ExtNonce mineTransaction(CMutableTransaction& txn)
{
    int64_t nStart = GetTime();
    arith_uint256 hashTarget;
    if (!getTarget(txn, hashTarget))
        throw std::runtime_error("Failed to mine transaction");

    LogPrintf("Hash target: %s\n", hashTarget.GetHex().c_str());

    if (txn.vout.size() != 1)
        return {0,0,0};

    std::vector<unsigned char> opReturn = txn.loadOpReturn();

    while (true) {

        CBlockIndex *prevBlock = chainActive.Tip();
        LogPrintf("block hash: %s, height: %u\n", prevBlock->GetBlockHash().ToString().c_str(), prevBlock->nHeight);
        uint256 hash;
        ExtNonce extNonce{(uint32_t)prevBlock->nHeight, (uint32_t)prevBlock->GetBlockHash().GetUint64(0), 0};

        while (true) {
            // Check if something found
            if (ScanHash(txn, extNonce, &hash, opReturn))
            {
                if (UintToArith256(txn.GetHash()) <= hashTarget)
                {
                    // Found a solution
                    LogPrintf("InternalMiner:\n");
                    LogPrintf("proof-of-work for transaction found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                    LogPrintf("Block height:%u Block hash:%u nonce:%u\n", extNonce.tip_block_height, extNonce.tip_block_hash, extNonce.nonce);
                    LogPrintf("\nDuration: %ld seconds\n\n", GetTime() - nStart);
                    return extNonce;
                }
            }
//            printf("\rTransaction hash: %s", txn.GetHash().ToString().c_str());

            // Check for stop
            boost::this_thread::interruption_point();
            if (extNonce.nonce >= 0xffff0000)
                break;
            if (prevBlock != chainActive.Tip()) {
                printf("Internal miner: New block detected\n");
                break;
            }
        }
    }

    return {0,0,0};
}

bool verifyTransactionHash(const CTransaction& txn, bool checkTxInTip)
{
    if (!txn.IsMsgTx()) {
        LogPrintf("Error: proof-of-work verification failed, non message transaction\n");
        return false;
    }

    arith_uint256 hashTarget;
    if (!getTarget(txn, hashTarget)) {
        LogPrintf("proof-of-work verification failed, could not calculate target\n");
        return false;
    }

    uint256 hash = txn.GetHash();
    std::vector<char> opReturn = txn.loadOpReturn();

    assert(opReturn.size() >= (unsigned int)(ENCR_MARKER_SIZE + 12));

    ExtNonce extNonce;
    std::memcpy(&extNonce.tip_block_height, opReturn.data()+ENCR_MARKER_SIZE, sizeof(uint32_t));
    std::memcpy(&extNonce.tip_block_hash, opReturn.data()+ENCR_MARKER_SIZE+4, sizeof(uint32_t));
    std::memcpy(&extNonce.nonce, opReturn.data()+ENCR_MARKER_SIZE+8, sizeof(uint32_t));

    CBlockIndex *prevBlock = checkTxInTip ? chainActive.Tip() : chainActive[extNonce.tip_block_height];
    if (!prevBlock) {
        std::cout << "Error: verifyTransactionHash - prevBlock is null\n";
        return false;
    }

    LogPrintf("proof-of-work verification  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    LogPrintf("  tip_block hash: %u\t tip_block height: %d\n", extNonce.tip_block_hash, extNonce.tip_block_height);
    LogPrintf("  tip_block hash: %u\t tip_block height: %d\n", (uint32_t)prevBlock->GetBlockHash().GetUint64(0), (uint32_t)prevBlock->nHeight);

    if (((uint16_t*)&hash)[15] != 0x8000) {
        std::cout << "\tError: verifyTransactionHash - hash does not start with 0x80" << std::endl;
        return false;
    }
    if (UintToArith256(hash) > hashTarget) {
        std::cout << "\tError: verifyTransactionHash - hash > hashTarget " << std::endl;
        return false;
    }
    if ((uint32_t)prevBlock->nHeight != extNonce.tip_block_height) {
        std::cout << "\tError: verifyTransactionHash - height not correct " << std::endl;
        return false;
    }
    if ((uint32_t)prevBlock->GetBlockHash().GetUint64(0) != extNonce.tip_block_hash) {
        std::cout << "\tError: verifyTransactionHash - hash part not correct " << std::endl;
        return false;
    }

    return true;
}

}
