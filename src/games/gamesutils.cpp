// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <key_io.h>
#include <logging.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <uint256.h>
#include <univalue.h>
#include <validation.h>

#include <games/gamesutils.h>
#include <games/modulo/modulotxs.h>
#include <games/modulo/moduloverify.h>
#include <data/datautils.h>

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);

ArgumentOperation::ArgumentOperation() : argument(0)
{
};

ArgumentOperation::ArgumentOperation(unsigned int argument_) : argument(argument_)
{
};

void ArgumentOperation::setArgument(unsigned int argument_)
{
    argument=argument_;
};

UniValue findTx(const std::string& txid)
{
    LOCK(cs_main);

    bool in_active_chain = true;
    uint256 hash = ParseHashV(txid, "parameter 1");
    CBlockIndex* blockindex = nullptr;
    CTransactionRef tx;
    uint256 hash_block;
    UniValue result(UniValue::VOBJ);

    int i;
    for(i=chainActive.Height();i>=0;--i)
    {
        blockindex = chainActive[i];

        if (hash == Params().GenesisBlock().hashMerkleRoot)
        {
            // Special exception for the genesis block coinbase transaction
            throw std::runtime_error(std::string("The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved"));
        }

        if (GetTransaction(hash, tx, Params().GetConsensus(), hash_block, true, blockindex)) 
        {
            if(blockindex)
            {
                result.pushKV("in_active_chain", in_active_chain);
            }
            TxToJSON(*tx, hash_block, result);
            result.pushKV("blockhash", hash_block.ToString());
            break;
        }
    }

    if(i<0)
    {
        throw std::runtime_error(std::string("Transaction not in blockchain"));
    }

    return result;
}

CKeyID getTxKeyID(const CTransaction& tx, int inputIdx)
{
    //<-----TODO what if funding transacton is neither p2pkh nor p2sh-wittness?
    if(!tx.vin[inputIdx].scriptWitness.IsNull())
    {
        return CKeyID(Hash160(tx.vin[inputIdx].scriptWitness.stack[1].begin(), tx.vin[inputIdx].scriptWitness.stack[1].end()));
    }

    return CKeyID(Hash160(tx.vin[inputIdx].scriptSig.end()-33, tx.vin[inputIdx].scriptSig.end()));
}

CScript createScriptPubkey(const CTransaction& prevTx)
{
    const CKeyID keyID = getTxKeyID(prevTx);
    return CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
}

std::string getBetType(const CTransaction& tx)
{
    size_t index{};
    return getBetType(tx, index);
}

std::string getBetType(const CTransaction& tx, size_t& idx)
{
    idx=0;
    for(size_t i=0;i<tx.vout.size();++i)
    {
        CScript::const_iterator it_beg=tx.vout[i].scriptPubKey.begin();
        CScript::const_iterator it_end=tx.vout[i].scriptPubKey.end();

        const int dist = std::distance(it_beg, it_end);
        if (dist <= 0) {
            continue;
        }

        std::string hexStr;
        unsigned int length = 0;

        if(*it_beg==OP_RETURN)
        {
            if (dist < 2) {
                return std::string("");
            }

            int order = *(it_beg+1);

            if(order<=0x4b)
            {
                if (dist < 3) {
                    return std::string("");
                }

                hexStr=std::string(it_beg+2, it_end);
                memcpy((char*)&length, std::string(it_beg+1, it_beg+2).c_str(), 1);
            }
            else if(order==0x4c)
            {
                if (dist < 4) {
                    return std::string("");
                }

                hexStr=std::string(it_beg+3, it_end);
                memcpy((char*)&length, std::string(it_beg+2, it_beg+3).c_str(), 1);
            }
            else if(order==0x4d)
            {
                if (dist < 5) {
                    return std::string("");
                }

                hexStr=std::string(it_beg+4, it_end);
                memcpy((char*)&length, std::string(it_beg+2, it_beg+4).c_str(), 2);
            }
            else if(order==0x4e)
            {
                if (dist < 7) {
                    return std::string("");
                }

                hexStr=std::string(it_beg+6, it_end);
                memcpy((char*)&length, std::string(it_beg+2, it_beg+6).c_str(), 4);
            }
            else
            {
                LogPrintf("getBetType length is too-large\n");
                return std::string("");
            }

            idx=i;
            if (hexStr.length() != length)
            {
                LogPrintf("%s ERROR: length difference %u, script: %s\n", length, hexStr.c_str());
                return std::string("");
            }
            return hexStr;
        }
    }

    LogPrintf("getBetType no op-return\n");
    return std::string("");
}

unsigned int blockHashStr2Int(const std::string& hashStr)
{
    unsigned int hash;
    std::vector<unsigned char> binaryBlockHash(hashStr.length()/2, 0);
    hex2bin(binaryBlockHash, hashStr);
    std::vector<unsigned char> blockhashVector(binaryBlockHash.end()-4, binaryBlockHash.end());
    array2typeRev(blockhashVector, hash);

    return hash;
}

unsigned int getArgumentFromBetType(std::string& betType, unsigned int max_limit)
{
    size_t pos_=betType.find("_");
    if(pos_==std::string::npos)
    {
        LogPrintf("VerifyBlockReward::getArgumentFromBetType() find _ failed");
        throw std::runtime_error(std::string("VerifyBlockReward::getArgumentFromBetType() find _ failed"));
    }
    std::string opReturnArg=betType.substr(0,pos_);
    betType=betType.substr(pos_+1);

    unsigned int opReturnArgNum;
    sscanf(opReturnArg.c_str(), "%x", &opReturnArgNum);

    if (opReturnArgNum == 0 || opReturnArgNum > max_limit)
    {
        throw std::runtime_error(std::string("VerifyBlockReward::getArgumentFromBetType() incorrect OP_RETURN argument format: " + opReturnArg));
    }

    return opReturnArgNum;
}

CAmount applyFee(CMutableTransaction& tx, int64_t nTxWeight, int64_t sigOpCost)
{
    if(tx.vout.size()==0)
    {
        return 0;
    }

    //compute fee for this transaction and equally subtract it from each output
    int64_t virtualSize = GetVirtualTransactionSize(nTxWeight, sigOpCost);
    CAmount totalFee = ::minRelayTxFee.GetFee(virtualSize);
    
    CAmount fee = totalFee / tx.vout.size();
    CAmount feeReminder = totalFee % tx.vout.size();
    
    for(auto& txOut : tx.vout)
    {
        if(txOut.nValue>fee)
        {
            txOut.nValue-=fee;
        }
        else
        {
            totalFee-=fee;
            txOut.nValue=0;
        }
    }

    auto& txOut = tx.vout.back();
    if(txOut.nValue>feeReminder)
    {
        txOut.nValue-=feeReminder;
    }
    else
    {
        totalFee-=feeReminder;
        txOut.nValue=0;
    }
    
    return totalFee;
}
