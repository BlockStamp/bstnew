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

    std::vector<unsigned char> data = createEncryptedMessage(
    reinterpret_cast<unsigned char*>(msg.c_str()),
    msg.length(),
    public_key.c_str());

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
        std::string privateRsaKey = "-----BEGIN RSA PRIVATE KEY-----\n"\
                "MIIEogIBAAKCAQEAqZSulRpOGFkqG+ohYaGfiKhYEmQF/qTg9Mtl6ATsXyLSQ9pI\n"\
                "iNQB07lOUEo7vx62U10JoliSbs6xv2v0CcBdYsvWJKzuONckyBGqcZHvSKkscDG0\n"\
                "luzVg1NPXXrH8MMJfs4u3H3HdRFhbxecDSp4QOwquEtyyIcVmSdqgYdmzEm7x4M6\n"\
                "jQURuM9xQrVA7aA0cupS4YalgJj1W1npNkruu4abrhiTGJ7dGbkEtppBdZqLirKO\n"\
                "Wz0Z+OK3aZ8HiZaXlDs0VBz+eK+O3m0aIyVhkW8r13uDYCKOaXLpQjiEWtjoOCU5\n"\
                "6iz+j9dtsio56MIe6npipGbFAN0u+JMjY3V6LQIDAQABAoIBAGu2V8m3IqGOiROf\n"\
                "/EICIc3wd7h+tdwPqB90zi64adbnzDxy+p2GY/6ydg7Dh/2WKWL79nGa5q/hM7+N\n"\
                "dz12ZRqqtEMpYErURLWbmvJ2KlGxutsshzNSDTBUC1Yp9bN0fqR/m/5LGhS+zG9+\n"\
                "xI0MS8OY/m1+5tJ+EvbrtVe+xEm/AZE9mXYdzam46L4jAn87uPkR9+ciUGaJcQwi\n"\
                "IOz0PytY9pVqDUmnJBPkx9gQic9uuDExa8wPcv6uvxw7UHYr4oobn47zya0CO40n\n"\
                "foOQFT1zVLa0qHU8SzievEdHNcJBjTvA1YJNlAAN+Hr3SKTOTIsun06S2hkr1gDI\n"\
                "TV1+pqECgYEA/z9iVkZItrVt6mJPGGnMKdU1mNaNaHnBnZ7J7WUFG4Dolr4jSHAX\n"\
                "UtzraVgEVdHfZdGBfx32GgkIOIZcatr6Ao6CyISqpwlYgIf5xn+lYUe/yS9hd6FN\n"\
                "8cGKs5JMwTWEOGY5meW8mGh3NYxSIfzzEn4MzzJNqbZbp8AtTNp2H9kCgYEAqhSm\n"\
                "0aTdIrbWG1cE24X/ciTbBBFq1D2CGiX9Agc/vGpevNpB8Gk4X+OvvRo1jZJS3dgt\n"\
                "TuS/qNkYL6WhQQixTYF3fjabu3tk84QLlKkl5pvha2nvzTCUarzwmUchbPozMRHS\n"\
                "uQJvBQTk0CRSBdowltdtpyR5P9IvOT+nGwPYzHUCgYBazh7a2Ig3z9W5o53F7qV+\n"\
                "YGZ/6BxIhcBWpc3qkZy+ix6zuhLtS0tQ5F0vjeuE6HQUUfNC2NLbskjlaw9nyF1X\n"\
                "GYH3ehMH97AvkbBPaMvaDt9w4FVJbO5Aynzgo3SA69wNAHkPggaVJdz7BN+XTdjf\n"\
                "xE4kTB4K+WAkDp9PDw0lCQKBgC1XKg2TVLxPX46USSA4fZuxRY21EvSXnRpZbDRh\n"\
                "OFWDSdQwnwl3E2dErHHODd661kp7ucBhbNKXZUI2dmF+7r1JuVA1QJjfUU81sVyl\n"\
                "JwxuG87lw97Ah6BY1A8Yjkmd/Y2kQbe+dVgyMMloFVGoE/HyZjH7oDMqVhp95I9o\n"\
                "HCCNAoGAOlHZRK68QM4+20YMTlYy/dFRAtruu7NjmzpVd3xh356QpXfLTWOs5OzF\n"\
                "o/y4deFoOrz1QQoxv1LaD1DmRsqIrnDiSrmJHzIIOFrEk+8S0nkmr10k6JpqCJHG\n"\
                "UCLtsPgJ8/lejk8AkzQaM7AuG6p/YJHnpVQHe6zkA1HXX0SZt+M=\n"\
                "-----END RSA PRIVATE KEY-----\n";

        std::vector<unsigned char> decryptedData = createDecryptedMessage(
            reinterpret_cast<unsigned char*>(OPreturnData.data()),
            OPreturnData.size(),
            privateRsaKey.c_str());

        return UniValue(UniValue::VSTR, std::string("\"")+std::string(decryptedData.begin(), decryptedData.end())+std::string("\""));
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
