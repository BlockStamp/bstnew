// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>
#include <algorithm>
#include <chainparams.h>
#include <games/gamestxs.h>
#include <games/gamesverify.h>
#include <games/modulo/moduloverify.h>
#include <games/modulo/modulotxs.h>
#include <games/modulo/moduloutils.h>

namespace modulo
{

    int GetModuloReward::operator()(const std::string& betType, unsigned int modulo)
    {
        if(betType.find("straight_")==0 || betType.find("STRAIGHT_")==0 || (betType.find_first_not_of( "0123456789" ) == std::string::npos))
        {
            return modulo;
        }
        else if((betType.find("split_")==0 || betType.find("SPLIT_")==0) && modulo==36)
        {
            return modulo/2;
        }
        else if((betType.find("street_")==0 || betType.find("STREET_")==0) && modulo==36)
        {
            return modulo/3;
        }
        else if((betType.find("corner_")==0 || betType.find("CORNER_")==0) && modulo==36)
        {
            return modulo/4;
        }
        else if((betType.find("line_")==0 || betType.find("LINE_")==0) && modulo==36)
        {
            return modulo/6;
        }
        else if((betType.find("column_")==0 || betType.find("COLUMN_")==0) && modulo==36)
        {
            return modulo/12;
        }
        else if((betType.find("dozen_")==0 || betType.find("DOZEN_")==0) && modulo==36)
        {
            return modulo/12;
        }
        else if((betType.find("low")==0 || betType.find("LOW")==0) && modulo==36)
        {
            return modulo/18;
        }
        else if((betType.find("high")==0 || betType.find("HIGH")==0) && modulo==36)
        {
            return modulo/18;
        }
        else if((betType.find("even")==0 || betType.find("EVEN")==0) && modulo==36)
        {
            return modulo/18;
        }
        else if((betType.find("odd")==0 || betType.find("ODD")==0) && modulo==36)
        {
            return modulo/18;
        }
        else if((betType.find("red")==0 || betType.find("RED")==0) && modulo==36)
        {
            return modulo/18;
        }
        else if((betType.find("black")==0 || betType.find("BLACK")==0) && modulo==36)
        {
            return modulo/18;
        }
        return 0;
    }

    bool VerifyMakeModuloBetTx::isWinning(const std::string& betType, unsigned int maxArgument, unsigned int argument)
    {
        int* bet;
        int len=1;
        if(betType.find_first_not_of( "0123456789" ) == std::string::npos)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType);
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            if(betNum<1 || betNum>maxArgument)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: ")+std::to_string(maxArgument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            straight = betNum;
            bet = const_cast<int* >(&straight);
            len = 1;
        }
        else if((betType.find("straight_")==0 || betType.find("STRAIGHT_")==0) && maxArgument==36)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType.substr(std::string("straight_").length()));
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            if(betNum<1 || betNum>36)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: 36")+std::string(" betNum: ")+std::to_string(betNum));
            }
            straight = betNum;
            bet = const_cast<int* >(&straight);
            len = 1;
        }
        else if((betType.find("split_")==0 || betType.find("SPLIT_")==0) && maxArgument==36)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType.substr(std::string("split_").length()));
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            if(betNum<1 || betNum>57)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: 36")+std::string(" betNum: ")+std::to_string(betNum));
            }
            bet = const_cast<int* >(split[betNum-1]);
            len = 2;
        }
        else if((betType.find("street_")==0 || betType.find("STREET_")==0) && maxArgument==36)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType.substr(std::string("street_").length()));
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }        
            if(betNum<1 || betNum>12)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: 36")+std::string(" betNum: ")+std::to_string(betNum));
            }
            bet = const_cast<int* >(street[betNum-1]);
            len = 3;
        }
        else if((betType.find("corner_")==0 || betType.find("CORNER_")==0) && maxArgument==36)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType.substr(std::string("corner_").length()));
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            if(betNum<1 || betNum>22)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: 36")+std::string(" betNum: ")+std::to_string(betNum));
            }
            bet = const_cast<int* >(corner[betNum-1]);
            len = 4;
        }
        else if((betType.find("line_")==0 || betType.find("LINE_")==0) && maxArgument==36)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType.substr(std::string("line_").length()));
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            if(betNum<1 || betNum>11)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: 36")+std::string(" betNum: ")+std::to_string(betNum));
            }
            bet = const_cast<int* >(line[betNum-1]);
            len = 6;
        }
        else if((betType.find("column_")==0 || betType.find("COLUMN_")==0) && maxArgument==36)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType.substr(std::string("column_").length()));
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            if(betNum<1 || betNum>3)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: 36")+std::string(" betNum: ")+std::to_string(betNum));
            }
            bet = const_cast<int* >(column[betNum-1]);
            len = 12;
        }
        else if((betType.find("dozen_")==0 || betType.find("DOZEN_")==0) && maxArgument==36)
        {
            int betNum;
            try
            {
                betNum=std::stoi(betType.substr(std::string("dozen_").length()));
            }
            catch(...)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" betNum: ")+std::to_string(betNum));
            }
            if(betNum<1 || betNum>3)
            {
                throw std::runtime_error(std::string("VerifyMakeModuloBetTx::isWinning argument failed: ")+std::to_string(argument)+std::string(" maxArgument: 36")+std::string(" betNum: ")+std::to_string(betNum));
            }
            bet = const_cast<int* >(dozen[betNum-1]);
            len = 12;
        }
        else if((betType.find("low")==0 || betType.find("LOW")==0) && maxArgument==36)
        {
            bet = const_cast<int* >(low);
            len = 18;
        }
        else if((betType.find("high")==0 || betType.find("HIGH")==0) && maxArgument==36)
        {
            bet = const_cast<int* >(high);
            len = 18;
        }
        else if((betType.find("even")==0 || betType.find("EVEN")==0) && maxArgument==36)
        {
            bet = const_cast<int* >(even);
            len = 18;
        }
        else if((betType.find("odd")==0 || betType.find("ODD")==0) && maxArgument==36)
        {
            bet = const_cast<int* >(odd);
            len = 18;
        }
        else if((betType.find("red")==0 || betType.find("RED")==0) && maxArgument==36)
        {
            bet = const_cast<int* >(red);
            len = 18;
        }
        else if((betType.find("black")==0 || betType.find("BLACK")==0) && maxArgument==36)
        {
            bet = const_cast<int* >(black);
            len = 18;
        }
        else
        {
            return false;
        }

        int *item = std::find(bet, bet+len, argument);
        if (item != bet+len) 
        {
            return true;
        }
        return false;
    }

    bool CompareModuloBet2Vector::operator()(int nSpendHeight, const std::string& betTypePattern, const std::vector<int>& betNumbers)
    {
        //bioinfo hardfork due to roulette bets definition change
        if(nSpendHeight < Params().GetConsensus().RouletteNewDefs)
        {
            return true;
        }

        std::vector<int> opReturnBet;
        if(!bet2Vector(betTypePattern, opReturnBet))
        {
            LogPrintf("CompareModuloBet2Vector::operator(): bet2Vector() failed");
            return false;
        }

        try
        {
            std::reverse(std::begin(opReturnBet), std::end(opReturnBet));
        }
        catch(...)
        {
            LogPrintf("CompareModuloBet2Vector::operator(): std::reverse() failed");
            return false;
        }

        if(betNumbers.size()!=opReturnBet.size())
        {
            LogPrintf("CompareModuloBet2Vector: vectors size mismatch\n");
            return false;
        }

        if(!std::equal( betNumbers.begin(), betNumbers.end(), opReturnBet.begin() ))
        {
            LogPrintf("CompareModuloBet2Vector: vectors are different\n");
            LogPrintf("betTypePattern: %s\n", betTypePattern);

            for(size_t i=0;i<betNumbers.size();++i)
            {
                LogPrintf("betNumbers: %d, %d\n", betNumbers[i], opReturnBet[i]);
            }
            LogPrintf("\n");

            return false;
        }

        return true;
    }

    namespace ver_1
    {

        VerifyBlockReward::VerifyBlockReward(const Consensus::Params& params, const CBlock& block_, ArgumentOperation* argumentOperation_, GetReward* getReward_, VerifyMakeBetTx* verifyMakeBetTx_, int32_t makeBetIndicator_, CAmount maxPayoff_) : 
                                             block(block_), argumentOperation(argumentOperation_), getReward(getReward_), verifyMakeBetTx(verifyMakeBetTx_), makeBetIndicator(makeBetIndicator_), maxPayoff(maxPayoff_)
        {
            blockSubsidy=GetBlockSubsidy(chainActive.Height(), params);
            uint256 hash=block.GetHash();
            blockHash=blockHashStr2Int(hash.ToString());
        }

        unsigned int VerifyBlockReward::getArgument(std::string& betType)
        {
            size_t pos_=betType.find("_");
            if(pos_==std::string::npos)
            {
                LogPrintf("VerifyBlockReward::getArgument() find _ failed");
                throw std::runtime_error(std::string("VerifyBlockReward::getArgument() find _ failed"));
            }
            std::string opReturnArg=betType.substr(0,pos_);
            betType=betType.substr(pos_+1);

            unsigned int opReturnArgNum;
            sscanf(opReturnArg.c_str(), "%x", &opReturnArgNum);

            return opReturnArgNum;
        }

        bool VerifyBlockReward::isBetPayoffExceeded()
        {
            //bioinfo hardfork due to roulette bets definition change
            if(chainActive.Height() < Params().GetConsensus().GamesVersion2)
            {
                return false;
            }

            CAmount inAcc=0;
            CAmount payoffAcc=0;
            for (const auto& tx : block.vtx)
            {
                try
                {
                    if(isBetTx(*tx, makeBetIndicator))
                    {
                        size_t idx;
                        std::string betType=getBetType(*tx, idx);
                        if(betType.empty())
                        {
                            LogPrintf("isBetPayoffExceeded: empty betType");
                            continue;
                        }

                        unsigned int argument=getArgument(betType);
                        argumentOperation->setArgument(argument);
                        argumentResult=(*argumentOperation)(blockHash);
                        for(size_t i=0;true;++i)//all tx.otputs
                        {
                            size_t pos=betType.find("+");
                            if(verifyMakeBetTx->isWinning(betType.substr(0,pos), argument, argumentResult))
                            {
                                int reward=(*getReward)(betType.substr(0,pos), argument);
                                CAmount payoff=tx->vout[i].nValue * reward;
                                payoffAcc+=payoff;
                            }
                            inAcc+=tx->vout[i].nValue;

                            if(pos==std::string::npos)
                            {
                                break;
                            }
                            betType=betType.substr(pos+1);
                        }
                    }
                }
                catch(...)
                {
                    LogPrintf("isBetPayoffExceeded: argumentOperation failed");
                    continue;
                }
            }

            if(inAcc >= blockSubsidy)
            {
                if(payoffAcc>inAcc+blockSubsidy)
                {
                    LogPrintf("payoffAcc: %d, inAcc: %d, blockSubsidy: %d\n", payoffAcc, inAcc, blockSubsidy);
                    return true;
                }
            }

            if(payoffAcc>maxPayoff)
            {
                LogPrintf("payoffAcc: %d, maxPayoff: %d\n", payoffAcc, maxPayoff);
                return true;
            }

            return false;
        }

        bool isMakeBetTx(const CTransaction& tx)
        {
            return isBetTx(tx, MAKE_MODULO_GAME_INDICATOR);
        }

        static unsigned int getMakeTxBlockHash(const std::string& makeTxBlockHash, unsigned int argument, ArgumentOperation* operation)
        {
            unsigned int blockhashTmp=blockHashStr2Int(makeTxBlockHash);
            operation->setArgument(argument);
            return (*operation)(blockhashTmp);
        }

        bool isInputBet(const CTxIn& input) {
            int numOfBetsNumbers=0;
            CScript::const_iterator it_end=input.scriptSig.end()-1;

            if(*it_end!=OP_DROP)
            {
                return false;
            }
            it_end-=6;
            if(*it_end!=OP_ENDIF)
            {
                return false;
            }
            --it_end;
            if(*it_end!=OP_FALSE)
            {
                return false;
            }
            --it_end;
            if(*it_end!=OP_DROP)
            {
                return false;
            }
            --it_end;
            if(*it_end!=OP_ELSE)
            {
                return false;
            }
            --it_end;
            for(CScript::const_iterator it=it_end;it>it_end-18;--it)
            {
                if(OP_TRUE==*it)
                {
                    numOfBetsNumbers=it_end-it+1;
                    it_end=it;
                    break;
                }
                else if(OP_ENDIF!=*it)
                {
                    return false;
                }
            }
            --it_end;
            if(*it_end!=OP_EQUALVERIFY)
            {
                return false;
            }

            std::vector<unsigned char> betNumber_(it_end-4, it_end);
            int betNumber=0;
            array2type(betNumber_, betNumber);
            std::vector<int> betNumbers(1, betNumber);
            it_end-=6;

            for(int i=0;i<numOfBetsNumbers-1;++i)
            {
                if(*it_end!=OP_ELSE)
                {
                    return false;
                }
                --it_end;
                if(*it_end!=OP_TRUE)
                {
                    return false;
                }
                --it_end;
                if(*it_end!=OP_DROP)
                {
                    return false;
                }
                --it_end;
                if(*it_end!=OP_IF)
                {
                    return false;
                }
                --it_end;
                if(*it_end!=OP_EQUAL)
                {
                    return false;
                }
                --it_end;
                betNumber_[3]=*it_end--;
                betNumber_[2]=*it_end--;
                betNumber_[1]=*it_end--;
                betNumber_[0]=*it_end--;
                --it_end;
                if(*it_end!=OP_DUP)
                {
                    return false;
                }
                --it_end;

               array2type(betNumber_, betNumber);
               betNumbers.push_back(betNumber);
            }

            if(*it_end!=OP_IF)
            {
                return false;
            }
            --it_end;
            if(*it_end!=OP_CHECKSIG)
            {
                return false;
            }
            --it_end;
            if(*it_end!=OP_EQUALVERIFY)
            {
                return false;
            }

            if(*(it_end-22)!=OP_HASH160)
            {
                return false;
            }
            if(*(it_end-23)!=OP_DUP)
            {
                return false;
            }

            CScript::const_iterator it_begin=input.scriptSig.begin();
            it_begin+=(*it_begin)+1;
            it_begin+=(*it_begin)+1;
            it_begin+=(*it_begin)+1;
            if(*it_begin==0x4c)
            {
                it_begin++;
            }
            it_begin++;

            if((it_end-23)!=it_begin)
            {
                return false;
            }

            return true;
        }

        static bool txGetBetVerify(int nSpendHeight, const CTransaction& tx, CAmount in, CAmount out, CAmount& fee, ArgumentOperation* operation, GetReward* getReward, CompareBet2Vector* compareBet2Vector, int32_t indicator, CAmount maxPayoff, int32_t maxReward)
        {
            fee=0;
            UniValue txPrev(UniValue::VOBJ);
            try
            {
                txPrev=findTx(tx.vin[0].prevout.hash.GetHex());
            }
            catch(...)
            {
                LogPrintf("txVerify findTx() failed\n");
                return false;
            }
            int32_t txVersion=txPrev["version"].get_int();

            int32_t makeBetIndicator = txVersion ^ indicator;
            if(makeBetIndicator > CTransaction::MAX_STANDARD_VERSION || makeBetIndicator < 1)
            {
                return false;
            }

            std::string blockhashStr=txPrev["blockhash"].get_str();
            CScript redeemScript(tx.vin[0].scriptSig.begin(), tx.vin[0].scriptSig.end());
            unsigned int argument = getArgument(redeemScript);
            unsigned int blockhash=getMakeTxBlockHash(blockhashStr, argument, operation);

            CScript::const_iterator it_beg=tx.vin[0].scriptSig.begin()+1;
            std::vector<unsigned char> blockhashFromScript_(it_beg, it_beg+4);

            unsigned int blockhashFromScript;
            array2type(blockhashFromScript_, blockhashFromScript);

            if(blockhash!=blockhashFromScript)
            {
                LogPrintf("txVerify: blockhash-mismatch\n");
                return false;
            }

            std::string betType;
            try
            {
                bool isOpReturnFlag=false;
                for(size_t i=1; i<txPrev["vout"].size();++i)
                {
                    if(txPrev["vout"][i][std::string("scriptPubKey")][std::string("asm")].get_str().find(std::string("OP_RETURN"))==0)
                    {
                        int length=0;
                        int offset=0;
                        std::string hexStr=txPrev["vout"][i][std::string("scriptPubKey")][std::string("hex")].get_str();
                        int order=std::stoi(hexStr.substr(2,2),nullptr,16);
                        if(order<=0x4b)
                        {
                            length=order;
                            offset=4;
                        }
                        else if(order==0x4c)
                        {
                            length=std::stoi(hexStr.substr(4,2),nullptr,16);
                            offset=6;
                        }
                        else if(order==0x4d)
                        {
                            std::string strLength=hexStr.substr(4,4);
                            reverseEndianess(strLength);
                            length=std::stoi(strLength,nullptr,16);
                            offset=8;
                        }
                        else if(order==0x4e)
                        {
                            std::string strLength=hexStr.substr(4,8);
                            reverseEndianess(strLength);
                            length=std::stoi(strLength,nullptr,16);
                            offset=12;
                        }
                        else
                        {
                            LogPrintf("txVerify: betType length is too-large\n");
                            return false;
                        }

                        length*=2;
                        std::string betTypeHex=hexStr.substr(offset, length);
                        hex2ascii(betTypeHex, betType);
                        //LogPrintf("txVerify: betType: %s\n", betType);
                        isOpReturnFlag=true;
                        break;
                    }
                }
                if(!isOpReturnFlag)
                {
                    LogPrintf("txVerify: betType length is empty\n");
                    return false;
                }
                else
                {
                    size_t pos_=betType.find("_");
                    std::string opReturnArg=betType.substr(0,pos_);
                    betType=betType.substr(pos_+1);

                    unsigned int opReturnArgNum;
                    sscanf(opReturnArg.c_str(), "%x", &opReturnArgNum);
                    if(opReturnArgNum != argument)
                    {
                        LogPrintf("txVerify: opReturnArgNum: %x != argument: %x \n", opReturnArgNum, argument);
                        return false;
                    }

                    uint32_t nPrevOut=tx.vin[0].prevout.n;
                    for(uint32_t n=0;n<nPrevOut;++n)
                    {
                        size_t pos=betType.find("+");
                        betType=betType.substr(pos+1);
                    }
                    size_t pos=betType.find("+");
                    betType=betType.substr(0,pos);
                    //LogPrintf("txVerify: betType: %s\n", betType);
                }
            }
            catch(const std::out_of_range& oor)
            {
                LogPrintf("txVerify: betType is out-of-range\n");
                return false;
            }
            if(betType.empty())
            {
                LogPrintf("txVerify: betType is empty\n");
                return false;
            }

            int opReturnReward=(*getReward)(betType, argument);

            //LogPrintf("txVerify opReturnReward: %d\n", opReturnReward);

            int numOfBetsNumbers=0;
            CScript::const_iterator it_end=tx.vin[0].scriptSig.end()-1;

            if(*it_end!=OP_DROP)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            it_end-=6;
            if(*it_end!=OP_ENDIF)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            --it_end;
            if(*it_end!=OP_FALSE)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            --it_end;
            if(*it_end!=OP_DROP)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            --it_end;
            if(*it_end!=OP_ELSE)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            --it_end;
            for(CScript::const_iterator it=it_end;it>it_end-18;--it)
            {
                if(OP_TRUE==*it)
                {
                    numOfBetsNumbers=it_end-it+1;
                    it_end=it;
                    break;
                }
                else if(OP_ENDIF!=*it)
                {
                    LogPrintf("txVerify: transaction format check failed\n");
                    return false;
                }
            }
            --it_end;
            if(*it_end!=OP_EQUALVERIFY)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }

            const int scriptReward=argument/numOfBetsNumbers;
            //LogPrintf("txVerify scriptReward: %d\n", scriptReward);
            if(opReturnReward != scriptReward)
            {
                LogPrintf("txVerify: opReturnReward != scriptReward\n");
                return false;
            }

            std::vector<unsigned char> betNumber_(it_end-4, it_end);
            int betNumber=0;
            array2type(betNumber_, betNumber);
            std::vector<int> betNumbers(1, betNumber);
            it_end-=6;
            for(int i=0;i<numOfBetsNumbers-1;++i)
            {
                //OP_DUP << betNumberArray << OP_EQUAL << OP_IF << OP_DROP << OP_TRUE << OP_ELSE
                if(*it_end!=OP_ELSE)
                {
                    LogPrintf("txVerify: transaction format check failed\n");
                    return false;
                }
                --it_end;
                if(*it_end!=OP_TRUE)
                {
                    LogPrintf("txVerify: transaction format check failed\n");
                    return false;
                }
                --it_end;
                if(*it_end!=OP_DROP)
                {
                    LogPrintf("txVerify: transaction format check failed\n");
                    return false;
                }
                --it_end;
                if(*it_end!=OP_IF)
                {
                    LogPrintf("txVerify: transaction format check failed\n");
                    return false;
                }
                --it_end;
                if(*it_end!=OP_EQUAL)
                {
                    LogPrintf("txVerify: transaction format check failed\n");
                    return false;
                }
                --it_end;
                betNumber_[3]=*it_end--;
                betNumber_[2]=*it_end--;
                betNumber_[1]=*it_end--;
                betNumber_[0]=*it_end--;
                --it_end;
                if(*it_end!=OP_DUP)
                {
                    LogPrintf("txVerify: transaction format check failed\n");
                    return false;
                }
                --it_end;

               array2type(betNumber_, betNumber);
               betNumbers.push_back(betNumber);
            }

            if(!(*compareBet2Vector)(nSpendHeight, betType, betNumbers))
            {
                LogPrintf("txVerify: compareBet2Vector check failed\n");
                return false;
            }

            //OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG << OP_IF;
            if(*it_end!=OP_IF)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            --it_end;
            if(*it_end!=OP_CHECKSIG)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            --it_end;
            if(*it_end!=OP_EQUALVERIFY)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }

            if(*(it_end-22)!=OP_HASH160)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }
            if(*(it_end-23)!=OP_DUP)
            {
                LogPrintf("txVerify: transaction format check failed\n");
                return false;
            }

            CScript::const_iterator it_begin=tx.vin[0].scriptSig.begin();
            it_begin+=(*it_begin)+1;
            it_begin+=(*it_begin)+1;
            it_begin+=(*it_begin)+1;
            if(*it_begin==0x4c)
            {
                it_begin++;
            }
            it_begin++;

            if((it_end-23)!=it_begin)
            {
                LogPrintf("txVerify: script length check failed\n");
                return false;
            }

            fee=(scriptReward*in)-out;
            if(out > scriptReward*in)
            {
                LogPrintf("txVerify: out > scriptReward*in\n");
                return false;
            }

            if(out>maxPayoff)
            {
                LogPrintf("txVerify: out > maxPayoff\n");
                return false;
            }

            if(opReturnReward>maxReward || scriptReward>maxReward)
            {
                LogPrintf("txVerify: maxReward exceeded\n");
                return false;
            }

            return true;
        }

        bool txGetBetVerify(int nSpendHeight, const CTransaction& tx, CAmount in, CAmount out, CAmount& fee)
        {
            try
            {
                ModuloOperation moduloOperation;
                GetModuloReward getModuloReward;
                CompareModuloBet2Vector compareModulobet2Vector;
                return txGetBetVerify(nSpendHeight, tx, in, out, fee, &moduloOperation, &getModuloReward, &compareModulobet2Vector, MAKE_MODULO_GAME_INDICATOR, MAX_PAYOFF, MAX_REWARD);
            }
            catch(...)
            {
                LogPrintf("modulo::txVerify exception occured");
                return false;
            }
        };

        bool isBetPayoffExceeded(const Consensus::Params& params, const CBlock& block)
        {
            try
            {
                VerifyMakeModuloBetTx verifyMakeModuloBetTx;
                ModuloOperation moduloOperation;
                GetModuloReward getModuloReward;
                VerifyBlockReward verifyBlockReward(params, block, &moduloOperation, &getModuloReward, &verifyMakeModuloBetTx, MAKE_MODULO_GAME_INDICATOR, MAX_PAYOFF);
                return verifyBlockReward.isBetPayoffExceeded();
            }
            catch(...)
            {
                LogPrintf("modulo::isBetPayoffExceeded exception occured");
                return false;
            }
        };

        bool txMakeBetVerify(const CTransaction& tx)
        {
            try
            {
                //bioinfo hardfork due to incorrect format of makebet transactions version 1
                if (chainActive.Height() < Params().GetConsensus().MakebetFormatVerify)
                {
                    return true;
                }
                if(chainActive.Height() >= Params().GetConsensus().GamesVersion2)
                {
                    LogPrintf("%s ERROR: not supported makebet version 1\n", __func__);
                    return false;
                }

                if(tx.vout.size()<2)
                {
                    LogPrintf("modulo::txMakeBetVerify: tx.size too small: %d\n", tx.vout.size());
                    return false;
                }

                size_t opReturnIdx;
                if(getBetType(tx, opReturnIdx).empty())
                {
                    LogPrintf("modulo::txMakeBetVerify: betType is empty\n");
                    return false;
                }

                for(size_t i=0;i<opReturnIdx;++i)
                {
                   if(!tx.vout[i].scriptPubKey.IsPayToScriptHash(false))
                   {
                       LogPrintf("modulo::txMakeBetVerify: not P2SH before opReturn\n");
                   }
                }

                return true;
            }
            catch(...)
            {
                LogPrintf("modulo::txMakeBetVerify exception occured");
                return false;
            }

        };

    };


    namespace ver_2
    {

        bool MakeBetWinningProcess::isMakeBetWinning()
        {
            try{
                //example bet: 00000024_black@200000000+red@100000000
                size_t idx;
                std::string betType = getBetType(m_tx, idx);
                if (betType.empty()) {
                    throw std::runtime_error("Improper bet type");
                }
                //LogPrintf("betType = %s\n", betType.c_str());

                if(idx) {
                    throw std::runtime_error(strprintf("Bet type idx is not zero: %d\n", idx));
                }

                const unsigned argument = getArgumentFromBetType(betType);
                //LogPrintf("argument = %u\n", argument);

                const std::string blockhashStr = m_hash.ToString();
                //LogPrintf("blockhashStr = %s\n", blockhashStr.c_str());

                const unsigned int blockhashTmp = blockHashStr2Int(blockhashStr);
                //LogPrintf("blockhashTmp = %u\n", blockhashTmp);

                ModuloOperation moduloOperation;
                moduloOperation.setArgument(argument);
                const unsigned argumentResult = moduloOperation(blockhashTmp);
                //LogPrintf("argumenteResult = %u\n", argumentResult);

                while (true) {
                    const size_t typePos = betType.find("@");
                    if (typePos == std::string::npos) {
                        throw std::runtime_error("Improper bet type");
                    }

                    const std::string type = betType.substr(0, typePos);
                    betType = betType.substr(typePos+1);

                    const size_t amountPos = betType.find("+");
                    const std::string amountStr = betType.substr(0, amountPos);

                    CAmount amount = std::stoll(amountStr);
                    if (amount<=0) {
                        throw std::runtime_error("Improper bet amount");
                    }

                    if (VerifyMakeModuloBetTx().isWinning(type, argument, argumentResult)) {
                        const unsigned reward = GetModuloReward()(type, argument);
                        //LogPrintf("reward = %u\n", reward);

                        const CAmount wonAmount = reward*amount;
                        if (wonAmount>MAX_CAMOUNT-m_payoff) {
                            throw std::runtime_error("Improper bet amount");
                        }
                        m_payoff += wonAmount;
                        //LogPrintf("%s is winning\n", type.c_str());
                    }

                    if (amountPos == std::string::npos) {
                        break;
                    }
                    betType = betType.substr(amountPos+1);
                }

                //LogPrintf("m_payoff = %d\n", m_payoff);
                if (m_payoff <= 0) {
                    return false;
                }

                return true;
            }
            catch(const std::exception& e) {
                LogPrintf("Error while processing bet transaction: %s\n", e.what());
            }
            catch(...) {
                LogPrintf("Unknown error while processing bet transaction\n");
            }
            return false;
        }

        CAmount MakeBetWinningProcess::getMakeBetPayoff()
        {
            return m_payoff;
        }

        bool isMakeBetTx(const CTransaction& tx)
        {
            return isBetTx(tx, MAKE_MODULO_NEW_GAME_INDICATOR);
        }

        bool isGetBetTx(const CTransaction& tx)
        {
            return isBetTx(tx, GET_MODULO_NEW_GAME_INDICATOR);
        }

        bool txGetBetVerify(const uint256& hashPrevBlock, const CBlock& currentBlock, const Consensus::Params& params, CAmount& fee)
        {
            struct MakeBetData {
                CTxOut out;
                CAmount payoff;
                CKeyID keyID;
            };

            std::map<uint256, MakeBetData> prevBlockWinningBets;
            const CBlockIndex* pindexPrev = LookupBlockIndex(hashPrevBlock);
            CBlock prevBlock;

            if (ReadBlockFromDisk(prevBlock, pindexPrev, params)) {
                for (unsigned int i = 0; i < prevBlock.vtx.size(); i++) {
                    const CTransaction& tx = *(prevBlock.vtx[i]);

                    if (modulo::ver_2::isMakeBetTx(tx)) {
                        MakeBetWinningProcess makeBetWinningProcess(tx, hashPrevBlock);
                        if (makeBetWinningProcess.isMakeBetWinning()) {
                            const CAmount payoff = makeBetWinningProcess.getMakeBetPayoff();
                            const CKeyID keyID = getTxKeyID(tx);
                            prevBlockWinningBets[tx.GetHash()] = MakeBetData{tx.vout[0], payoff, keyID};
                        }
                    }
                }
            }
            else {
                LogPrintf("Error: could not read previous block: %s\n", hashPrevBlock.ToString().c_str());
                return false;
            }

            CTransactionRef getBet;
            for (const CTransactionRef& tx: currentBlock.vtx) {
                if (modulo::ver_2::isGetBetTx(*tx)) {
                    if (getBet == nullptr) {
                        getBet = tx;
                    }
                    else {
                        LogPrintf("Error: more than one get bet in block: %s\n", currentBlock.GetHash().ToString().c_str());
                        return false;
                    }
                }
            }

            if (getBet == nullptr) {
                if (prevBlockWinningBets.size() == 0) {
                    return true;
                }
                LogPrintf("Error: prevBlockWinningBets not empty, but getbet transaction not found for block: %s\n",
                          currentBlock.GetHash().ToString().c_str());
                return false;
            }

            if ((*getBet).vout.size() != prevBlockWinningBets.size()) {
                LogPrintf("Error: mismatch for getbet outputs and prevBlockWinningBets sizes for block: %s\n",
                          currentBlock.GetHash().ToString().c_str());
                return false;
            }

            for (unsigned idx=0; idx<(*getBet).vout.size(); ++idx) {
                const CTxOut& output = (*getBet).vout[idx];
                const uint256 makeBetHash = (*getBet).vin[idx].prevout.hash;
                const auto iter = prevBlockWinningBets.find(makeBetHash);
                if (iter == prevBlockWinningBets.end()) {
                    LogPrintf("Error: could not find makebet: %s in prevBlockWinningBets for block: %s\n",
                              makeBetHash.ToString().c_str(), currentBlock.GetHash().ToString().c_str());
                    return false;
                }

                MakeBetData& makeBetData = iter->second;
                const int NoFeeGetBetOffset = 121;
                if (chainActive.Height() > params.GamesVersion2 + NoFeeGetBetOffset) {
                    if (makeBetData.payoff != output.nValue) {
                        LogPrintf("Error: makeBetData.payoff(%d) != output.nValue(%d) for block: %s\n",
                                  makeBetData.payoff, output.nValue, currentBlock.GetHash().ToString().c_str());
                        return false;
                    }
                }
                else {
                    if (makeBetData.payoff < output.nValue) {
                        LogPrintf("Error: makeBetData.payoff(%d) < output.nValue(%d) for block: %s\n",
                                  makeBetData.payoff, output.nValue, currentBlock.GetHash().ToString().c_str());
                        return false;
                    }
                }

                std::vector<unsigned char> vpubkeyHash(output.scriptPubKey.begin()+3, output.scriptPubKey.end()-2);
                uint160 pubkeyHash(vpubkeyHash);
                CKeyID keyID(pubkeyHash);
                if (makeBetData.keyID != keyID)
                {
                    LogPrintf("Error: keyIDs don't match for block %s\n", currentBlock.GetHash().ToString().c_str());
                    return false;
                }

                fee += makeBetData.payoff - output.nValue;

                prevBlockWinningBets.erase(iter);
            }

            if (!prevBlockWinningBets.empty()) {
                LogPrintf("Error: prevBlockWinningBets is not empty after getbet verification of block: %s\n",
                          currentBlock.GetHash().ToString().c_str());
                return false;
            }

            return true;
        }

        bool is_lottery(const std::string& betStr)
        {
            return betStr.find_first_not_of("0123456789") == std::string::npos;
        }

        bool checkBetNumberLimit(int mod_argument, const std::string& bet_type)
        {
            if (is_lottery(bet_type))
            {
                unsigned int betAmount = 0;
                try {
                    betAmount = std::stoi(bet_type);
                } catch (...) {}
                if (betAmount == 0)
                {
                    LogPrintf("%s:ERROR bet amount below limit %u\n", __func__, betAmount);
                    return false;
                }
                if ((int)betAmount > mod_argument)
                {
                    LogPrintf("%s:ERROR bet amount: %u above game limit %u\n", __func__, betAmount, mod_argument);
                    return false;
                }
            } else
            {
                size_t pos_ = bet_type.find_last_of("_");
                if (pos_ != std::string::npos && pos_ < bet_type.length()-1)
                {
                    unsigned int betAmount = std::stoi(bet_type.substr(pos_+1, std::string::npos));
                    if (betAmount == 0)
                    {
                        LogPrintf("%s:ERROR bet amount below limit %u\n", __func__, betAmount);
                        return false;
                    }
                }
            }
            return true;
        }

        bool txMakeBetVerify(const CTransaction& tx)
        {
            try
            {
                //bioinfo hardfork due to incorrect format of makebet transactions
                if(chainActive.Height() < Params().GetConsensus().GamesVersion2)
                {
                    return true;
                }

                if (!isMakeBetTx(tx))
                {
                    return true;
                }

                if(tx.vout.size()!=1 && tx.vout.size()!=2)
                {
                    LogPrintf("modulo_ver_2::txMakeBetVerify: tx.size incorrect: %d\n", tx.vout.size());
                    return false;
                }
                
                size_t opReturnIdx;
                std::string betType = getBetType(tx, opReturnIdx);
                if(betType.empty())
                {
                    LogPrintf("modulo_ver_2::txMakeBetVerify: betType is empty\n");
                    return false;
                }
                
                if(opReturnIdx)
                {
                    LogPrintf("modulo_ver_2::txMakeBetVerify: opReturnIdx is not zero\n");
                    return false;
                }

                unsigned int argument = getArgumentFromBetType(betType, MAX_REWARD);

                // check does reward of each single bet is not over limit
                CAmount amountSum = 0;
                while (true)
                {
                    const size_t typePos = betType.find("@");
                    if (typePos == std::string::npos)
                    {
                        LogPrintf("%s: Incorrect bet type: %s\n", __func__, betType.c_str());
                        return false;
                    }

                    const std::string type = betType.substr(0, typePos);
                    betType = betType.substr(typePos + 1);

                    const size_t amountPos = betType.find("+");
                    const std::string amountStr = betType.substr(0, amountPos);
                    CAmount amount = std::stoll(amountStr);
                    const unsigned reward = GetModuloReward()(type, argument);
                    amountSum += amount;

                    if (reward == 0)
                    {
                        LogPrintf("%s:ERROR unknown bet type %s\n", __func__, betType.c_str());
                        return false;
                    }

                    if (reward > MAX_REWARD)
                    {
                        LogPrintf("%s: ERROR reward of one bet %ld higher than admissible limit: %ld\n", __func__, reward, MAX_REWARD);
                        return false;
                    }

                    if (amount == 0)
                    {
                        LogPrintf("%s:ERROR amount below limit %u\n", __func__, amount);
                        return false;
                    }

                    if (!checkBetNumberLimit(argument, type))
                    {
                        return false;
                    }

                    if (amountPos == std::string::npos)
                    {
                        break;
                    }

                    betType = betType.substr(amountPos + 1);
                }
                
                if (amountSum != tx.vout[0].nValue)
                {
                    LogPrintf("%s:ERROR amount mismatch between script: %d and nValue: %d\n", __func__, amountSum, tx.vout[0].nValue);
                    return false;
                }

                return true;
            }
            catch(...)
            {
                LogPrintf("modulo_ver_2::txMakeBetVerify exception occured\n");
                return false;
            }
        }

        bool isBetPayoffExceeded(const Consensus::Params& params, const CBlock& block)
        {
            try
            {
                VerifyMakeModuloBetTx verifyMakeModuloBetTx;
                ModuloOperation moduloOperation;
                GetModuloReward getModuloReward;
                VerifyBlockReward verifyBlockReward(params, block, &moduloOperation, &getModuloReward, &verifyMakeModuloBetTx);
                return verifyBlockReward.isBetPayoffExceeded();
            }
            catch(...)
            {
                LogPrintf("modulo::isBetPayoffExceeded exception occured\n");
                return false;
            }
        };

        bool checkBetsPotentialReward(CAmount &rewardSum, CAmount &betsSum, const CTransaction& txn)
        {
            if (isMakeBetTx(txn))
            {
                try
                {
                    CBlock block;
                    VerifyMakeModuloBetTx verifyMakeModuloBetTx;
                    ModuloOperation moduloOperation;
                    GetModuloReward getModuloReward;
                    VerifyBlockReward verifyBlockReward(Params().GetConsensus(), block, &moduloOperation, &getModuloReward, &verifyMakeModuloBetTx);
                    return verifyBlockReward.checkPotentialRewardLimit(rewardSum, betsSum, txn);
                }
                catch(...)
                {
                    LogPrintf("modulo::checkPotentialReward exception occured\n");
                    return false;
                }
            }
            return true;
        };

        CAmount getSumOfTxnBets(const CTransaction& txn)
        {
            try
            {
                CBlock block;
                VerifyMakeModuloBetTx verifyMakeModuloBetTx;
                ModuloOperation moduloOperation;
                GetModuloReward getModuloReward;
                VerifyBlockReward verifyBlockReward(Params().GetConsensus(), block, &moduloOperation, &getModuloReward, &verifyMakeModuloBetTx);
                return verifyBlockReward.getSumOfTxnBets(txn);
            }
            catch(...)
            {
                LogPrintf("modulo::isSumOfBetsOverSubsidyLimit exception occured\n");
                return false;
            }
        }

        
        MakeBetWinningProcess::MakeBetWinningProcess(const CTransaction& tx, uint256 hash) :
            m_tx(tx),
            m_hash(hash)
        {
        }


        VerifyBlockReward::VerifyBlockReward(const Consensus::Params& params, const CBlock& block_, ArgumentOperation* argumentOperation_, GetReward* getReward_, VerifyMakeBetTx* verifyMakeBetTx_) :
                                             block(block_), argumentOperation(argumentOperation_), getReward(getReward_), verifyMakeBetTx(verifyMakeBetTx_)
        {
            blockSubsidy=GetBlockSubsidy(chainActive.Height(), params);
            uint256 hash=block.GetHash();
            blockHash=blockHashStr2Int(hash.ToString());
        }

        bool VerifyBlockReward::isBetPayoffExceeded()
        {
            //bioinfo hardfork due to roulette bets definition change
            if(chainActive.Height() < Params().GetConsensus().GamesVersion2)
            {
                return false;
            }

            CAmount inAcc=0;
            CAmount payoffAcc=0;
            for (const auto& tx : block.vtx)
            {
                try
                {
                    if(isMakeBetTx(*tx))
                    {
                        std::string betType=getBetType(*tx);
                        if(betType.empty())
                        {
                            LogPrintf("isBetPayoffExceeded: empty betType\n");
                            continue;
                        }

                        unsigned int argument=getArgumentFromBetType(betType);
                        ModuloOperation moduloOperation;
                        moduloOperation.setArgument(argument);
                        argumentResult = moduloOperation(blockHash);

                        while (true)
                        {
                            const size_t typePos = betType.find("@");
                            if (typePos == std::string::npos)
                            {
                                LogPrintf("%s: Incorrect bet type: %s\n", __func__, betType.c_str());
                                return true;
                            }

                            const std::string type = betType.substr(0, typePos);
                            betType = betType.substr(typePos + 1);

                            const size_t amountPos = betType.find("+");
                            const std::string amountStr = betType.substr(0, amountPos);
                            CAmount amount = std::stoll(amountStr);
                            const unsigned reward = GetModuloReward()(type, argument);

                            CAmount payoff{};
                            if (verifyMakeBetTx->isWinning(type, argument, argumentResult))
                            {
                                payoff = amount * reward;
                                payoffAcc += payoff;
                            }
                            inAcc += amount;

                            if (amountPos == std::string::npos)
                            {
                                break;
                            }

                            betType = betType.substr(amountPos + 1);
                        }
                    }
                }
                catch(...)
                {
                    LogPrintf("isBetPayoffExceeded: argumentOperation failed\n");
                    continue;
                }
            }

            // sum of all bets higher than block subsidy
            if(inAcc >= blockSubsidy)
            {
                LogPrintf("%s:ERROR Sum of all bets: %d higher than 90%% of blockSubsidy: %d\n", __func__, inAcc, blockSubsidy);
                return true;
            }

            return false;
        }

        bool VerifyBlockReward::checkPotentialRewardLimit(CAmount &rewardSum, CAmount &betsSum, const CTransaction &txn)
        {
            if (chainActive.Height() < Params().GetConsensus().GamesVersion2)
            {
                return true;
            }

            if (!isMakeBetTx(txn))
            {
                return true;
            }

            std::string betType = getBetType(txn);
            if (betType.empty())
            {
                LogPrintf("%s: Bet type empty\n", __func__);
                return false;
            }
            unsigned int argument = getArgumentFromBetType(betType);

            while (true)
            {
                const size_t typePos = betType.find("@");
                if (typePos == std::string::npos)
                {
                    LogPrintf("%s: Incorrect bet type: %s\n", __func__, betType.c_str());
                    return false;
                }

                const std::string type = betType.substr(0, typePos);
                betType = betType.substr(typePos + 1);

                const size_t amountPos = betType.find("+");
                const std::string amountStr = betType.substr(0, amountPos);

                CAmount amount = std::stoll(amountStr);
                const unsigned reward = GetModuloReward()(type, argument);
                if (reward > MAX_REWARD)
                {
                    LogPrintf("%s: ERROR potential reward of one bet %ld higher than admissible limit: %ld\n", __func__, reward, MAX_REWARD);
                    return false;
                }

                CAmount payoff = reward * amount;
                betsSum += amount;
                rewardSum += payoff;

                if (amountPos == std::string::npos)
                {
                    break;
                }

                betType = betType.substr(amountPos + 1);

            }

            // sum of all potential wins in block should be less than MAX_PAYOFF
            if (rewardSum > MAX_PAYOFF)
            {
                LogPrintf("%s: ERROR potential:%ld max:%ld\n", __func__, rewardSum, MAX_PAYOFF);
                return false;
            }
            // sum of all bets higher than block subsidy
            if (betsSum > blockSubsidy)
            {
                LogPrintf("%s:ERROR Sum of all bets: %d higher than 90%% of blockSubsidy: %d\n", __func__, betsSum, blockSubsidy);
                return false;
            }

            return true;
        }

        CAmount VerifyBlockReward::getSumOfTxnBets(const CTransaction& txn)
        {
            CAmount sumOfBets{};
            if(isMakeBetTx(txn))
            {
                std::string betType=getBetType(txn);
                if(betType.empty())
                {
                    LogPrintf("%s ERROR: empty betType\n", __func__);
                    return sumOfBets;
                }
                for(size_t i=0;true;++i)//all tx.otputs
                {
                    size_t pos=betType.find("+");
                    sumOfBets+=txn.vout[i].nValue;
                    if(pos==std::string::npos)
                    {
                        break;
                    }
                    betType=betType.substr(pos+1);
                }
            }
            return sumOfBets;
        }






    };

}
