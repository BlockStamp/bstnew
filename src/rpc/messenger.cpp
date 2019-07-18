// Copyright (c) 2019 Michal Siek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <rpc/server.h>
#include <rpc/client.h>
#include <rpc/util.h>
#include <consensus/validation.h>
#include <validation.h>
#include <policy/policy.h>
#include <utilstrencodings.h>
#include <stdint.h>
#include <amount.h>
#include <hash.h>
#include <net.h>
#include <rpc/mining.h>
#include <utilmoneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <univalue.h>
#include <memory>
#include "messages/message_encryption.h"
#include <data/retrievedatatxs.h>

#include <boost/algorithm/string.hpp>

static constexpr size_t maxDataSize=MAX_OP_RETURN_RELAY-6;

bool checkRSApublicKey(const std::string& rsaPublicKey) {
    const std::string keyBeg = "-----BEGIN PUBLIC KEY-----\n";
    const std::string keyEnd = "-----END PUBLIC KEY-----";

    auto posbeg = rsaPublicKey.find(keyBeg);
    if (posbeg != 0) {
        return false;
    }

    auto posend = rsaPublicKey.find(keyEnd);
    if (posend == std::string::npos) {
        return false;
    }
    std::size_t encodingLength = posend - keyBeg.length();

    // RSA 1024
    if (encodingLength == 220) {
        return true;
    }

    // RSA 2048
    if (encodingLength == 399) {
        return true;
    }

    // RSA 4096
    if (encodingLength == 748) {
        return true;
    }

    return false;
}

UniValue sendmessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5 || !checkRSApublicKey(request.params[1].get_str()))
    throw std::runtime_error(
        "sendmessage \"string\" \"public_key\" \n"
        "\nStores encrypted message in a blockchain.\n"
        "A transaction fee is computed as a (string length)*(fee rate). \n"
        "Before this command walletpassphrase is required. \n"

        "\nArguments:\n"
        "1. \"message\"                     (string, required) A user message string\n"
        "2. \"public_key\"                  (string, required) Receiver public key (length: 1024, 2048 or 4096)\n"
        "3. replaceable                     (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
        "4. conf_target                     (numeric, optional) Confirmation target (in blocks)\n"
        "5. \"estimate_mode\"               (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
        "       \"UNSET\"\n"
        "       \"ECONOMICAL\"\n"
        "       \"CONSERVATIVE\"\n"

        "\nResult:\n"
        "\"txid\"                           (string) A hex-encoded transaction id\n"


        "\nExamples:\n"

        + HelpExampleCli("sendmessage", "\"mystring\" \"-----BEGIN PUBLIC KEY-----\n"\
                         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApk9zWv53rDBLE1Xh1iuX\n"\
                         "wvY1Zk7HOmcE3kD/hcGjtXQQAKMmf6i2n79fiyJcC43nGaIUAKW2YCJEfuyA97aw\n"\
                         "ye3ccyGsX2sw9tWwfcHZi8P+jI9Zti9dVRiR3D1ClA2ot/U5FG1pR3BUPA/jCuIG\n"\
                         "qT4JeIWAnySuKykMutjuf/5JD7paVlem8EUV4Hmq2yF9ZxS5yi50zBsNZuylhaKC\n"\
                         "oiMQc7ovPhn63zKazPr3v2nyzs0aSEWAssEPZBKFEuWkzOqVHfAV9xiILFF2Cp8D\n"\
                         "i1e3225cLPCpJak6K66t0B1xX+nC9ABABbzuD/gzwXQ2wT97iL6k3YB/c2Ou11v3\n"\
                         "bQIDAQAB\n"
                         "-----END PUBLIC KEY-----\"")

        + HelpExampleRpc("sendmessage", "\"mystring\"  \"-----BEGIN PUBLIC KEY-----\n"\
                         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApk9zWv53rDBLE1Xh1iuX\n"\
                         "wvY1Zk7HOmcE3kD/hcGjtXQQAKMmf6i2n79fiyJcC43nGaIUAKW2YCJEfuyA97aw\n"\
                         "ye3ccyGsX2sw9tWwfcHZi8P+jI9Zti9dVRiR3D1ClA2ot/U5FG1pR3BUPA/jCuIG\n"\
                         "qT4JeIWAnySuKykMutjuf/5JD7paVlem8EUV4Hmq2yF9ZxS5yi50zBsNZuylhaKC\n"\
                         "oiMQc7ovPhn63zKazPr3v2nyzs0aSEWAssEPZBKFEuWkzOqVHfAV9xiILFF2Cp8D\n"\
                         "i1e3225cLPCpJak6K66t0B1xX+nC9ABABbzuD/gzwXQ2wT97iL6k3YB/c2Ou11v3\n"\
                         "bQIDAQAB\n"
                         "-----END PUBLIC KEY-----\"")
    );

    std::string msg=request.params[0].get_str();

    if(msg.length()>maxDataSize)
    {
        throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
    }

    std::string public_key=request.params[1].get_str();
    std::cout << "msg: " << msg << std::endl;
    std::cout << "public_key: " << public_key << std::endl;

    CCoinControl coin_control;
    if (!request.params[2].isNull())
    {
        coin_control.m_signal_bip125_rbf = request.params[1].get_bool();
    }

    if (!request.params[3].isNull())
    {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[2]);
    }

    if (!request.params[4].isNull())
    {
        if (!FeeModeFromString(request.params[4].get_str(), coin_control.m_fee_mode)) {
            throw std::runtime_error("Invalid estimate_mode parameter");
        }
    }

    std::vector<unsigned char> data = createEncryptedMessage((unsigned char*)msg.c_str(), msg.length()+1, public_key.c_str());
    std::cout << "data.size(): " << data.size() << std::endl;
    return setOPreturnData(data, coin_control);
}

UniValue readmessage(const JSONRPCRequest& request)
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    if (request.fHelp || request.params.size() != 1)
    throw std::runtime_error(
        "readmessage \"txid\" \n"
        "\nDecode and print user message from blockchain.\n"

        "\nArguments:\n"
        "1. \"txid\"                        (string, required) A hex-encoded transaction id string\n"

        "\nResult:\n"
        "\"string\"                         (string) A decoded user data string\n"


        "\nExamples:\n"
        + HelpExampleCli("readmessage", "\"txid\"")
        + HelpExampleRpc("readmessage", "\"txid\"")
    );

    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid);
    if(!OPreturnData.empty())
    {
        return UniValue(UniValue::VSTR, std::string("\"")+std::string(OPreturnData.begin(), OPreturnData.end())+std::string("\""));
    }

    return UniValue(UniValue::VSTR, std::string("\"\""));
}

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)            argNames
  //  --------------------- ------------------------        -----------------------     ----------
    { "blockstamp",         "sendmessage",                  &sendmessage,               {"message", "public_key", "replaceable", "conf_target", "estimate_mode"} },
    { "blockstamp",         "readmessage",                  &readmessage,               {"txid"} },
};

void RegisterMessengerRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
