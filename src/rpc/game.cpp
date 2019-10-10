// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <numeric>
#include <rpc/server.h>
#include <rpc/client.h>
#include <consensus/validation.h>
#include <validation.h>
#include <policy/policy.h>
#include <utilstrencodings.h>
#include <stdint.h>
#include <amount.h>
#include <chainparams.h>
#include <net.h>
#include <rpc/mining.h>
#include <utilmoneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>

#include <univalue.h>
#include <boost/algorithm/string.hpp>

#include <data/datautils.h>
#include <data/processunspent.h>

#include <games/gamestxs.h>
#include <games/modulo/modulotxs.h>
#include <games/gamesutils.h>
#include <games/modulo/moduloutils.h>
#include <games/modulo/moduloverify.h>

using namespace modulo;

static std::string changeAddress("");

static UniValue callRPC(std::string args)
{
    std::vector<std::string> vArgs;
    boost::split(vArgs, args, boost::is_any_of(" \t"));
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    JSONRPCRequest request;
    request.strMethod = strMethod;
    request.params = RPCConvertValues(strMethod, vArgs);
    request.fHelp = false;

    rpcfn_type method = tableRPC[strMethod]->actor;
    try {
        UniValue result = (*method)(request);
        return result;
    }
    catch (const UniValue& objError) {
        throw std::runtime_error(find_value(objError, "message").get_str());
    }
}

UniValue makebet(const JSONRPCRequest& request)
{
	if (request.fHelp || request.params.size() < 1 || request.params.size() > 5)
	throw std::runtime_error(
        "makebet \n"
        "\nCreates a bet transaction.\n"
        "Before this command walletpassphrase is required. \n"

        "\nArguments:\n"
        "1. \"type_of_bet\"                 (string, required) Defines a combination of bet type and number along with the bet amount. Roulette specific bets are available for default range\n"
        "2. \"range\"                       (numeric, optional) Defines a range of numbers <1, range> to be drawn. For lottery it must be greater than 1. Default range is set to 36 meaning a roulette\n"
        "3. replaceable                     (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
        "4. conf_target                     (numeric, optional) Confirmation target (in blocks)\n"
        "5. \"estimate_mode\"               (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
        "       \"UNSET\"\n"
        "       \"ECONOMICAL\"\n"
        "       \"CONSERVATIVE\"\n"

        "\nResult:\n"
        "\"txid\"                           (string) A hex-encoded transaction id\n"


        "\nExamples:\n"
        + HelpExampleCli("makebet", "straight_2@0.1+street_3@0.05")
        + HelpExampleRpc("makebet", "straight_2@0.1+street_3@0.05")
	);

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if(wallet==nullptr)
    {
        throw std::runtime_error(std::string("No wallet found"));
    }
    CWallet* const pwallet=wallet.get();
    std::vector<CAmount> betAmounts;
    std::vector<std::string> betTypes;

    std::string betTypePattern=request.params[0].get_str();

    bool isRoulette=true;
    int range=36;//by default roulette range
    if(!request.params[1].isNull())
    {
        range=request.params[1].get_int();
        if (range <= 1) {
            throw std::runtime_error(std::string("Range must be greater than 1"));
        }
        isRoulette=false;
    }

    parseBetType(betTypePattern, range, betAmounts, betTypes, isRoulette);
    const CAmount betSum = betAmountsSum(betAmounts);

    CCoinControl coin_control;
    if (!request.params[2].isNull())
    {
        coin_control.m_signal_bip125_rbf = request.params[3].get_bool();
    }

    if (!request.params[3].isNull())
    {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[4]);
    }

    if (!request.params[4].isNull())
    {
        if (!FeeModeFromString(request.params[4].get_str(), coin_control.m_fee_mode)) {
            throw std::runtime_error("Invalid estimate_mode parameter");
        }
    }

    std::string arg=int2hex(range)+std::string("_");
    std::string msg=HexStr(arg.begin(), arg.end());
    const std::string plus_msg("+");
    const std::string at_msg("@");

    for(size_t i=0;i<betTypes.size();++i)
    {
        msg+=HexStr(betTypes[i].begin(), betTypes[i].end());
        std::string amountStr = at_msg + std::to_string(betAmounts[i]);
        msg+=HexStr(amountStr.begin(), amountStr.end());
        if(i<betTypes.size()-1)
        {
            msg+=HexStr(plus_msg.begin(), plus_msg.end());
        }
    }
    
    const CRecipient recipient = createMakeBetDestination(betSum, msg);
    LOCK2(cs_main, pwallet->cs_wallet);

    CAmount curBalance = pwallet->GetBalance();
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    int nChangePosInOut=1;
    std::string strFailReason;
    CTransactionRef tx;

    EnsureWalletIsUnlocked(pwallet);

    if(!pwallet->CreateTransaction({recipient}, nullptr, tx, reservekey, nFeeRequired, nChangePosInOut, strFailReason, coin_control, true, true))
    {
        if (nFeeRequired > curBalance)
        {
            strFailReason = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        }        
        throw std::runtime_error(std::string("CreateTransaction failed with reason: ")+strFailReason);
    }

    CAmount rewardSum{}, betsSum{};
    if (!modulo::ver_2::checkBetsPotentialReward(rewardSum, betsSum, *tx))
    {
        throw std::runtime_error("checkBetsPotentialReward failed with reason: potential reward or sum of bets over limit");
    }

    CValidationState state;
    if(!pwallet->CommitTransaction(tx, {}, {}, reservekey, g_connman.get(), state))
    {
        throw std::runtime_error(std::string("CommitTransaction failed with reason: ")+FormatStateMessage(state));
    }

    std::string txid=tx->GetHash().GetHex();
    return UniValue(UniValue::VSTR, txid);
}


static const CRPCCommand commands[] =
{ //  category              name                            actor (function)            argNames
  //  --------------------- ------------------------        -----------------------     ----------
    { "games",             "makebet",                      &makebet,                   {"type_of_bet", "range", "replaceable", "conf_target", "estimate_mode"} },
};

void RegisterGameRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
