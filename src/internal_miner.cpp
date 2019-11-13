// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "internal_miner.h"

#include "arith_uint256.h"
#include "streams.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"

#include <boost/thread.hpp>

using namespace std;

namespace internal_miner
{

const std::string TARGET = "8000000FFFFF0000000000000000000000000000000000000000000000000000";

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
bool static ScanHash(CTransaction *txn, uint32_t& nNonce, uint256 *phash)
{
    // Write the first 76 bytes of the block header to a double-SHA256 state.
    CHash256 hasher;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << txn->GetHash();
//    hasher.Write((unsigned char*)&ss[0], 76);

    while (true)
    {
        nNonce++;

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result.
        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint16_t*)phash)[15] == 0x8000)
            return true;

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xfff) == 0)
            return false;
    }
    return false;
}

uint64_t mineTransaction(CTransaction txn)
{
    uint64_t result = 0;
    unsigned int nExtraNonce = 0;
    int64_t nStart = GetTime();
    arith_uint256 hashTarget;
    hashTarget.SetHex(TARGET);
    printf("Hash target: %s\n", hashTarget.GetHex().c_str());

    while (true) {
        uint256 hash;
        uint32_t nNonce = 0;

        while (true) {
            // Check if something found
            if (ScanHash(&txn, nNonce, &hash))
            {
                if (UintToArith256(hash) <= hashTarget)
                {
                    // Found a solution
                    LogPrintf("BitcoinMiner:\n");
                    LogPrintf("proof-of-work for transaction found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex());
                    printf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                    printf("\nNonce: %u, extra nonce: %u\n", nNonce, nExtraNonce);
                    result =(uint64_t)nExtraNonce << 32 | nNonce;
                    printf("\nDuration: %ld seconds\n\n", GetTime() - nStart);
                    return result;
                }
            }

            // Check for stop
            boost::this_thread::interruption_point();
            if (nNonce >= 0xffff0000)
                break;
        }

        ++nExtraNonce;
        if (nExtraNonce == 0)
            break;
    }

    return result;
}

bool verifyTransactionHash(CTransaction& txn, uint64_t nonce)
{
    ///TODO: nonce should be obtain from CTransaction OP_RETURN

    arith_uint256 hashTarget;
    hashTarget.SetHex(TARGET);
    uint256 hash;

    CHash256 hasher;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << txn.GetHash();
    CHash256(hasher).Write((unsigned char*)&nonce, 4).Finalize((unsigned char*)&hash);

    printf("proof-of-work verification  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());

    if ((((uint16_t*)&hash)[15] == 0x8000) && UintToArith256(hash) <= hashTarget)
        return true;

    return false;
}

}
