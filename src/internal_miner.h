// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERNALMINER_H
#define BITCOIN_INTERNALMINER_H

#include "primitives/block.h"

#include <stdint.h>
#include <txmempool.h>

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
};

/** Run the miner threads */
ExtNonce mineTransaction(CMutableTransaction &txn);

bool verifyTransactionHash(const CTransaction &txn, uint64_t nonce);
}

#endif // BITCOIN_INTERNALMINER_H
