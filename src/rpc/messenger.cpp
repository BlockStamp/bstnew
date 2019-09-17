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
#include <wallet/crypter.h>
#include <univalue.h>
#include <memory>
#include <messages/message_encryption.h>
#include <messages/message_utils.h>
#include <data/retrievedatatxs.h>

#include <boost/algorithm/string.hpp>

static constexpr size_t maxDataSize=MAX_OP_RETURN_RELAY-6;

UniValue sendmessage(const JSONRPCRequest& request)
{   
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
    {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 6 || !checkRSApublicKey(request.params[2].get_str()))
    throw std::runtime_error(
        "sendmessage \"subject\" \"string\" \"public_key\" \n"
        "\nStores encrypted message in a blockchain.\n"
        "A transaction fee is computed as a (string length)*(fee rate). \n"
        "Before this command walletpassphrase is required. \n"

        "\nArguments:\n"
        "1. \"subject\"                     (string, required) A user message string\n"
        "2. \"message\"                     (string, required) A user message string\n"
        "3. \"public_key\"                  (string, required) Receiver public key (length: 1024, 2048 or 4096)\n"
        "4. replaceable                     (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
        "5. conf_target                     (numeric, optional) Confirmation target (in blocks)\n"
        "6. \"estimate_mode\"               (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
        "       \"UNSET\"\n"
        "       \"ECONOMICAL\"\n"
        "       \"CONSERVATIVE\"\n"

        "\nResult:\n"
        "\"txid\"                           (string) A hex-encoded transaction id\n"


        "\nExamples:\n"

        + HelpExampleCli("sendmessage", " \"subject\" \"mystring\" \"-----BEGIN PUBLIC KEY-----\n"\
                         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqZSulRpOGFkqG+ohYaGf\n"\
                         "iKhYEmQF/qTg9Mtl6ATsXyLSQ9pIiNQB07lOUEo7vx62U10JoliSbs6xv2v0CcBd\n"\
                         "YsvWJKzuONckyBGqcZHvSKkscDG0luzVg1NPXXrH8MMJfs4u3H3HdRFhbxecDSp4\n"\
                         "QOwquEtyyIcVmSdqgYdmzEm7x4M6jQURuM9xQrVA7aA0cupS4YalgJj1W1npNkru\n"\
                         "u4abrhiTGJ7dGbkEtppBdZqLirKOWz0Z+OK3aZ8HiZaXlDs0VBz+eK+O3m0aIyVh\n"\
                         "kW8r13uDYCKOaXLpQjiEWtjoOCU56iz+j9dtsio56MIe6npipGbFAN0u+JMjY3V6\n"\
                         "LQIDAQAB\n"
                         "-----END PUBLIC KEY-----\"")

        + HelpExampleRpc("sendmessage", " \"subject\" \"mystring\"  \"-----BEGIN PUBLIC KEY-----\n"\
                         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqZSulRpOGFkqG+ohYaGf\n"\
                         "iKhYEmQF/qTg9Mtl6ATsXyLSQ9pIiNQB07lOUEo7vx62U10JoliSbs6xv2v0CcBd\n"\
                         "YsvWJKzuONckyBGqcZHvSKkscDG0luzVg1NPXXrH8MMJfs4u3H3HdRFhbxecDSp4\n"\
                         "QOwquEtyyIcVmSdqgYdmzEm7x4M6jQURuM9xQrVA7aA0cupS4YalgJj1W1npNkru\n"\
                         "u4abrhiTGJ7dGbkEtppBdZqLirKOWz0Z+OK3aZ8HiZaXlDs0VBz+eK+O3m0aIyVh\n"\
                         "kW8r13uDYCKOaXLpQjiEWtjoOCU56iz+j9dtsio56MIe6npipGbFAN0u+JMjY3V6\n"\
                         "LQIDAQAB\n"
                         "-----END PUBLIC KEY-----\"")
    );

    EnsureWalletIsUnlocked(pwallet);

    std::string rsaPrivateKey, rsaPublicKey;
    if (!pwallet->GetMessengerKeys(rsaPrivateKey, rsaPublicKey)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
    }

    std::string msg=MSG_RECOGNIZE_TAG
            + rsaPublicKey
            + MSG_DELIMITER
            + request.params[0].get_str()
            + MSG_DELIMITER
            + request.params[1].get_str();

    if(msg.length()>maxDataSize)
    {
        throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
    }

    std::string public_key=request.params[2].get_str();
    std::cout << "msg: " << msg << std::endl;
    std::cout << "public_key: " << public_key << std::endl;

    CCoinControl coin_control;
    if (!request.params[3].isNull())
    {
        coin_control.m_signal_bip125_rbf = request.params[3].get_bool();
    }

    if (!request.params[4].isNull())
    {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[4]);
    }

    if (!request.params[5].isNull())
    {
        if (!FeeModeFromString(request.params[5].get_str(), coin_control.m_fee_mode)) {
            throw std::runtime_error("Invalid estimate_mode parameter");
        }
    }

    std::vector<unsigned char> data = createEncryptedMessage(
    reinterpret_cast<const unsigned char*>(msg.c_str()),
    msg.length(),
    public_key.c_str());

    std::cout << "data.size(): " << data.size() << std::endl;
    return setOPreturnData(data, coin_control, request);
}

UniValue readmessage(const JSONRPCRequest& request)
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
    {
        return NullUniValue;
    }

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

    EnsureWalletIsUnlocked(pwallet);

    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid, request);

    if(!OPreturnData.empty())
    {
        std::string privateRsaKey, publicRsaKey;
        auto wallet = GetWalletForJSONRPCRequest(request);
        if (!wallet || !wallet->GetMessengerKeys(privateRsaKey, publicRsaKey))
        {
            throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
        }

        std::vector<unsigned char> decryptedData = createDecryptedMessage(
            reinterpret_cast<unsigned char*>(OPreturnData.data()),
            OPreturnData.size(),
            privateRsaKey.c_str());

        // replace msg_delimiter with new line character
        int counter = 0;
        for (auto &it : decryptedData)
        {
            if (it == MSG_DELIMITER)
            {
                it = '\n';
                ++counter;
            }
            if (counter == 2) break;
        }

        return UniValue(UniValue::VSTR, std::string("\"")+std::string(decryptedData.begin(), decryptedData.end())+std::string("\""));
    }

    return UniValue(UniValue::VSTR, std::string("\"\""));
}

UniValue getmsgkey(const JSONRPCRequest& request)
{
    if (request.fHelp)
    throw std::runtime_error(
        "getmsgkey \n"
        "\nGet public key for messenger to share with other users.\n"

        "\nExamples:\n"
        + HelpExampleCli("getmsgkey", "")
        + HelpExampleRpc("getmsgkey", "")
    );

    //TODO: Locking wallet may be needed - to be checked

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(wallet.get(), request.fHelp)) {
        return NullUniValue;
    }

    std::string privateRsaKeys, publicRsaKey;
    if (!wallet->GetMessengerKeys(privateRsaKeys, publicRsaKey))
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
    }

    return UniValue(UniValue::VSTR, publicRsaKey);
}

UniValue exportmsgkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
    throw std::runtime_error(
        "exportmsgkey \n"
        "\nExport pair of keys used in messenger to destination path.\n"

        "\nArguments:\n"
        "1. \"destination_path\"                        (string, required) The destination file path.\n"

        "\nExamples:\n"
        + HelpExampleCli("exportmsgkey", "\"destination_path\"")
        + HelpExampleRpc("exportmsgkey", "\"destination_path\"")
    );

    std::string publicRsaKey, privateRsaKey;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
    {
        return NullUniValue;
    }

    if (!pwallet->GetMessengerKeys(privateRsaKey, publicRsaKey))
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
    }

    std::ofstream file(request.params[0].get_str().c_str(), std::ofstream::trunc);
    file << publicRsaKey << MSG_DELIMITER << privateRsaKey;

    return UniValue(UniValue::VSTR, std::string("Keys exported successful."));
}

UniValue importmsgkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
    throw std::runtime_error(
        "importmsgkey \n"
        "\nImport pair of keys to use in messenger from source path.\n"

        "\nArguments:\n"
        "1. \"source_path\"                        (string, required) The source file path.\n"

        "\nExamples:\n"
        + HelpExampleCli("importmsgkey", "\"source_path\"")
        + HelpExampleRpc("importmsgkey", "\"source_path\"")
    );

    std::ifstream file(request.params[0].get_str().c_str(), std::ifstream::in);
    if (file.is_open())
    {
        std::string publicRsaKey, privateRsaKey;
        std::getline(file, publicRsaKey, MSG_DELIMITER);
        std::getline(file, privateRsaKey, MSG_DELIMITER);

        if (checkRSApublicKey(publicRsaKey)
                && checkRSAprivateKey(privateRsaKey)
                && matchRSAKeys(publicRsaKey, privateRsaKey))
        {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            CWallet* const pwallet = wallet.get();

            if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
            {
                return NullUniValue;
            }

            WalletDatabase& dbh = wallet->GetMsgDBHandle();
            WalletBatch walletBatch(dbh);
            // store key in database
            walletBatch.WritePublicKey(publicRsaKey);
            walletBatch.WritePrivateKey(privateRsaKey);

            ///TODO: Update keys stored in memory
        } else
        {
            return UniValue(UniValue::VSTR, std::string("Import failed. Incorrect key format"));
        }
    } else
    {
        return UniValue(UniValue::VSTR, std::string("Import failed. File open error."));
    }

    return UniValue(UniValue::VSTR, std::string("Keys imported successful."));
}

static void LockMessenger(CWallet* pWallet)
{
    LOCK(pWallet->cs_wallet);
    pWallet->nMessengerRelockTime = 0;
    pWallet->MsgLock();
}

static UniValue messengerpassphrase(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "messengerpassphrase \"passphrase\" timeout\n"
            "\nStores the messenger decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to messenger keys such as sendmessage\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The messenger passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds; capped at 100000000 (~3 years).\n"
            "\nNote:\n"
            "Issuing the messengerpassphrase command while the messenger is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "\nExamples:\n"
            "\nUnlock messenger for 60 seconds\n"
            + HelpExampleCli("messengerpassphrase", "\"my pass phrase\" 60") +
            "\nLock messenger again (before 60 seconds)\n"
            + HelpExampleCli("messengerlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("messengerpassphrase", "\"my pass phrase\", 60")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsMsgCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted messenger, but messengerpassphrase was called.");
    }

    // Note that the messengerpassphrase is stored in request.params[0] which is not mlock()ed
    SecureString strMsgPass;
    strMsgPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    strMsgPass = request.params[0].get_str().c_str();

    // Get the timeout
    int64_t nSleepTime = request.params[1].get_int64();
    // Timeout cannot be negative, otherwise it will relock immediately
    if (nSleepTime < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Timeout cannot be negative.");
    }
    // Clamp timeout
    constexpr int64_t MAX_SLEEP_TIME = 100000000; // larger values trigger a macos/libevent bug?
    if (nSleepTime > MAX_SLEEP_TIME) {
        nSleepTime = MAX_SLEEP_TIME;
    }

    if (strMsgPass.length() > 0)
    {
        if (!pwallet->MsgUnlock(strMsgPass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The messenger passphrase entered was incorrect.");
        }
    }
    else
        throw std::runtime_error(
            "messengerpassphrase <passphrase> <timeout>\n"
            "Stores the messenger decryption key in memory for <timeout> seconds.");

    pwallet->nMessengerRelockTime = GetTime() + nSleepTime;
    RPCRunLater(strprintf("lockmessenger(%s)", pwallet->GetName()), std::bind(LockMessenger, pwallet), nSleepTime);

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)            argNames
  //  --------------------- ------------------------        -----------------------     ----------
    { "blockstamp",         "sendmessage",                  &sendmessage,               {"subject", "message", "public_key", "replaceable", "conf_target", "estimate_mode"} },
    { "blockstamp",         "readmessage",                  &readmessage,               {"txid"} },
    { "blockstamp",         "getmsgkey",                    &getmsgkey,                 {} },
    { "blockstamp",         "exportmsgkey",                 &exportmsgkey,              {"destination_path"} },
    { "blockstamp",         "importmsgkey",                 &importmsgkey,              {"source_path"} },
    { "blockstamp",         "messengerpassphrase",          &messengerpassphrase,       {"passphrase", "timeout"} },
};

void RegisterMessengerRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
