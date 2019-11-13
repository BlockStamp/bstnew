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
/** Run the miner threads */
uint64_t mineTransaction(CTransaction txn);

bool verifyTransactionHash(CTransaction& txn, uint64_t nonce);
}

#endif // BITCOIN_INTERNALMINER_H
