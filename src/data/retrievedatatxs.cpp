// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <core_io.h>

#include <key_io.h>
#include <net.h>

#include <rpc/rawtransaction.h>
#include <index/txindex.h>
#include <rpc/server.h>
#include <validation.h>
#include <data/datautils.h>
#include <data/retrievedatatxs.h>


RetrieveDataTxs::RetrieveDataTxs(const std::string& txid, CWallet* const pwallet, const std::string& blockHash)
{
    uint256 hash;
    hash.SetHex(txid);
    CBlockIndex* blockindex = nullptr;

    pwallet->BlockUntilSyncedToCurrentChain();
    if(pwallet)
    {
        LOCK2(cs_main, pwallet->cs_wallet);
        
        auto it = pwallet->mapWallet.find(hash);
        if (it != pwallet->mapWallet.end()) 
        {
            const CWalletTx& wtx = it->second;
            tx=wtx.tx;
            return;
        }
    }
    
    LOCK(cs_main);

    if (hash == Params().GenesisBlock().hashMerkleRoot) 
    {
        // Special exception for the genesis block coinbase transaction
        throw std::runtime_error(std::string("The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved"));
    }

    if (!blockHash.empty()) 
    {
        uint256 blockhash = uint256S(blockHash);
        blockindex = LookupBlockIndex(blockhash);
        if (!blockindex) 
        {
            throw std::runtime_error(std::string("Block hash not found"));
        }
    }

    bool f_txindex_ready = false;
    if (g_txindex && !blockindex) 
    {
        f_txindex_ready = g_txindex->BlockUntilSyncedToCurrentChain();
    }

    uint256 hash_block;
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hash_block, true, blockindex)) 
    {
        std::string errmsg;
        if (blockindex) 
        {
            if (!(blockindex->nStatus & BLOCK_HAVE_DATA)) 
            {
                throw std::runtime_error(std::string("Block not available"));
            }
            errmsg = "No such transaction found in the provided block";
        } else if (!g_txindex) {
            errmsg = "No such mempool transaction. Use -txindex to enable blockchain transaction queries";
        } else if (!f_txindex_ready) {
            errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
        } else {
            errmsg = "No such mempool or blockchain transaction";
        }
        throw std::runtime_error(errmsg + std::string(". Use gettransaction for wallet transactions."));
    }
}


RetrieveDataTxs::~RetrieveDataTxs() {}

std::vector<char> RetrieveDataTxs::getTxData()
{
    return tx->loadOpReturn();
}
