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
#include <internal_miner.h>
#include <util.h>

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
        "3. \"public_key\"                  (string, required) Receiver public key (length: 2048)\n"
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
    EnsureMsgWalletIsUnlocked(pwallet);

    CMessengerKey rsaPrivateKey, rsaPublicKey;

    if (!pwallet->GetMessengerKeys(rsaPrivateKey, rsaPublicKey))
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
    }

    const std::string fromAddress = rsaPublicKey.toString();
    const std::string subject = request.params[0].get_str();
    const std::string message = request.params[1].get_str();
    const std::string toAddress = request.params[2].get_str();

    if (subject.empty())
        throw std::runtime_error("subject cannot be empty");

    if (message.empty())
        throw std::runtime_error("message cannot be empty");

    if (!checkRSApublicKey(toAddress))
        throw std::runtime_error("public key is incorrect");

    const std::string signature = signMessage(rsaPrivateKey.toString(), fromAddress);

    std::string msg=MSG_RECOGNIZE_TAG
            + signature
            + fromAddress
            + MSG_DELIMITER
            + subject
            + MSG_DELIMITER
            + message;

    if(msg.length()>maxDataSize)
    {
        throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
    }

    CMessengerKey public_key(toAddress, CMessengerKey::PUBLIC_KEY);

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
        public_key.toString().c_str());

    UniValue txid = setOPreturnData(data, coin_control, request);

    if (!pwallet->SaveMsgToHistory(uint256S(txid.get_str()), subject, message, fromAddress, toAddress))
    {
        LogPrintf("Error while saving history\n");
    }

    pwallet->NotifyMsgSent(pwallet);

    return txid;
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

    EnsureMsgWalletIsUnlocked(pwallet);

    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid, request);

    if(!OPreturnData.empty())
    {
        CMessengerKey privateRsaKey, publicRsaKey;
        auto wallet = GetWalletForJSONRPCRequest(request);
        if (!wallet || !wallet->GetMessengerKeys(privateRsaKey, publicRsaKey))
        {
            throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
        }

        if (pwallet->IsFreeEncryptedMsg(OPreturnData))
        {
            assert(OPreturnData.size() >= 12);
            // replace ENCR_MARKER text
            std::memcpy(OPreturnData.data(), ENCR_MARKER.data(), ENCR_MARKER_SIZE);
            OPreturnData.erase(OPreturnData.end()-12, OPreturnData.end());
        }

        std::string from, subject, body;
        decryptMessageAndSplit(OPreturnData, privateRsaKey.toString(), from, subject, body);

        std::stringstream msg;
        msg << from << std::endl << subject << std::endl << body << std::endl;
        return UniValue(UniValue::VSTR, std::string("\"")+msg.str()+std::string("\""));
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
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    EnsureMsgWalletIsUnlocked(pwallet);

    CMessengerKey privateRsaKeys, publicRsaKey;
    if (!wallet->GetMessengerKeys(privateRsaKeys, publicRsaKey))
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
    }

    return UniValue(UniValue::VSTR, publicRsaKey.toString());
}

static UniValue encryptmessenger(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "encryptmessenger \"passphrase\"\n"
            "\nEncrypts the messenger with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with messages such as sending or reading\n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the messengerpassphrase call for this, and then messengerlock call.\n"
            "If the messenger is already encrypted, use the messengerpassphrasechange call.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the messenger with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt your messenger\n"
            + HelpExampleCli("encryptmessenger", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the messenger, such as for sending messages\n"
            + HelpExampleCli("messengerpassphrase", "\"my pass phrase\"") +
            "\nNow we can do something like reading and sending messages\n"
            "\nNow lock the messenger again by removing the passphrase\n"
            + HelpExampleCli("messengerlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("encryptmessegner", "\"my pass phrase\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->IsMsgCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted messenger, but encryptmessenger was called.");
    }

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw std::runtime_error(
            "encryptmessenger <passphrase>\n"
            "Encrypts the messenger with <passphrase>.");

    if (!pwallet->EncryptMessenger(strWalletPass)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the messenger.");
    }

    return "messenger encrypted.";
}

static UniValue messengerlock(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "messengerlock\n"
            "\nRemoves the messenger encryption key from memory, locking the messenger.\n"
            "After calling this method, you will need to call messengerpassphrase again\n"
            "before being able to call any methods which require the messenger to be unlocked.\n"
            "\nExamples:\n"
            "\nUnlock the messenger with messengerpassphrase (the messenger is unlocked till the end session\n"
            "i.e. until the program is turned off or messengerlock is called)\n"
            + HelpExampleCli("messengerpassphrase", "\"my pass phrase\"") +
            "\nPerform a messenger command, e.g. getmsgkey (requires messenger passphrase set)\n"
            "\nClear the passphrase since we are already done\n"
            + HelpExampleCli("messengerlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("messengerlock", "")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsMsgCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted messenger, but messengerlock was called.");
    }

    pwallet->MsgLock();
    return NullUniValue;
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

    CMessengerKey publicRsaKey, privateRsaKey;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
    {
        return NullUniValue;
    }

    EnsureMsgWalletIsUnlocked(pwallet);

    if (!pwallet->GetMessengerKeys(privateRsaKey, publicRsaKey))
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
    }

    std::ofstream file(request.params[0].get_str().c_str(), std::ofstream::trunc);
    file << publicRsaKey.toString() << KEY_SEPARATOR << privateRsaKey.toString();

    return UniValue(UniValue::VSTR, std::string("Keys exported successfully."));
}

UniValue importmsgkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
    throw std::runtime_error(
        "importmsgkey \n"
        "\nImport a pair of RSA keys to use in messenger from source path.\n"
        "\nThe keys must be in clear text base64-encoded in OpenSSL format, e.g. contain headers BEGIN PUBLIC KEY/END PUBLIC KEY\n"
        "and BEGIN RSA PRIVATE KEY/END RSA PRIVATE KEY\n"

        "\nArguments:\n"
        "1. \"source_path\"                        (string, required) The source file path.\n"
        "2. rescan                               (boolean, optional, default=false) Rescan the wallet for messenger transactions that can be decoded with these keys\n"
        "\nNote: This call can take a long time to complete if rescan is true, during that time, other rpc calls may not work correctly"
        "\nImporting new messenger keys will clear outgoing messages history, e.g. all sent messages will be removed\n"
        "\nExamples:\n"
        + HelpExampleCli("importmsgkey", "\"source_path\"")
        + HelpExampleRpc("importmsgkey", "\"source_path\"")
    );

    CMessengerKey privateRsaKey, publicRsaKey;
    loadMsgKeysFromFile(request.params[0].get_str(), privateRsaKey, publicRsaKey);

    ///TODO: this can be removed, already check in CMessengerKey cstr
    if (!checkRSApublicKey(publicRsaKey.toString())
        || !checkRSAprivateKey(privateRsaKey.toString())
        || !matchRSAKeys(publicRsaKey.toString(), privateRsaKey.toString()))
    {
        return UniValue(UniValue::VSTR, std::string("Import failed. Incorrect key format"));
    }

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
    {
        return NullUniValue;
    }

    {
        LOCK2(cs_main, pwallet->cs_wallet);
        MessengerRescanReserver reserver(pwallet);
        EnsureMsgWalletIsUnlocked(pwallet);

        // Whether to perform rescan after import
        bool fRescan = false;
        if (!request.params[1].isNull())
            fRescan = request.params[1].get_bool();

        if (fRescan && fPruneMode)
            throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

        if (fRescan && !reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Messenger is currently rescanning. Abort existing rescan or wait.");
        }

        if (!pwallet->SetMessengerKeys(privateRsaKey.get(), publicRsaKey.get()))
        {
            return UniValue(UniValue::VSTR, std::string("Import failed. Can't encrypt new pair of keys."));
        }

        {
            WalletBatch walletBatch(pwallet->GetMsgDBHandle());

            for (const auto& tx : pwallet->encrMsgMapWallet)
                walletBatch.EraseEncrMsgTx(tx.first);
            pwallet->encrMsgMapWallet.clear();

            for (const auto& tx : pwallet->encrMsgHistory)
                walletBatch.EraseMsgTxToHistory(tx.first);
            pwallet->encrMsgHistory.clear();

            if (!pwallet->IsMsgCrypted())
            {
                walletBatch.WritePublicKey(publicRsaKey.toString());
                walletBatch.WritePrivateKey(privateRsaKey.toString());
            }
            pwallet->DelMsgAddressBookForLabel(MY_ADDRESS_LABEL);
            pwallet->SetMsgAddressBook(publicRsaKey.toString(), MY_ADDRESS_LABEL);
        }
        pwallet->NotifyEncrMsgTransactionChanged(pwallet);

        if (fRescan) {
            pwallet->ScanForMessages(chainActive.Genesis(), reserver);
        }
    }

    return UniValue(UniValue::VSTR, std::string("Keys imported successfully."));
}

static UniValue messengerpassphrase(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "messengerpassphrase \"passphrase\"\n"
            "\nStores the messenger decryption key in memory until the node is shutdown\n"
            "This is needed prior to performing transactions related to messenger keys such as sendmessage\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The messenger passphrase\n"
            "\nExamples:\n"
            "\nUnlock messenger\n"
            + HelpExampleCli("messengerpassphrase", "\"my pass phrase\"") +
            "\nLock messenger again\n"
            + HelpExampleCli("messengerlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("messengerpassphrase", "\"my pass phrase\"")
        );
    }

    MessengerRescanReserver reserver(pwallet);

    {
        LOCK2(cs_main, pwallet->cs_wallet);

        if (!pwallet->IsMsgCrypted()) {
            throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted messenger, but messengerpassphrase was called.");
        }

        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Messenger is currently rescanning. Abort unlocking messenger and wait.");
        }

        // Note that the messengerpassphrase is stored in request.params[0] which is not mlock()ed
        SecureString strMsgPass;
        strMsgPass.reserve(100);
        // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
        // Alternately, find a way to make request.params[0] mlock()'d to begin with.
        strMsgPass = request.params[0].get_str().c_str();

        if (strMsgPass.length() > 0)
        {
            if (!pwallet->MsgUnlock(strMsgPass)) {
                throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The messenger passphrase entered was incorrect.");
            }
        }
        else
            throw std::runtime_error(
                "messengerpassphrase <passphrase>\n"
                "Stores the messenger decryption key in memory until the node is shutdown");

        pwallet->ScanForMessagesSinceLastScan(reserver);
    }

    return NullUniValue;
}

static UniValue messengerpassphrasechange(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "messengerpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the messenger passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("messengerpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("messengerpassphrasechange", "\"old one\", \"new one\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsMsgCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted messenger, but messengerpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw std::runtime_error(
            "messengerpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the messenger passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwallet->ChangeMessengerPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The messenger passphrase entered was incorrect.");
    }

    return NullUniValue;
}

UniValue listmsgsinceblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
    throw std::runtime_error(
        "listmsgsinceblock ( \"blockhash\" )\n"
        "\nGet all messenger transactions in blocks since block [blockhash].\n"
        "\nArguments:\n"
        "1. \"blockhash\"            (string, optional) The block hash to list transactions since\n"
        "\nResult:\n"
        "{\n"
        "  \"transactions\": [\n"
        "    \"date\":\"date\",    (string) Date of incomming transaction.\n"
        "    \"from\":\"label\",     (string) Label of sender if exists in address book, otherwise empty.\n"
        "    \"txid\": \"transactionid\",  (string) The transaction id.\n"
        "    \"block hash\": \"blockhash\", (string) Hash of block containing transaction.\n"
        "  ],\n"
        "  \"lastblock\": \"lastblockhash\"     (string) The hash of the block (target_confirmations-1) from the best block on the main chain.\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("listmsgsinceblock", "")
        + HelpExampleRpc("listmsgsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" ")
    );

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    EnsureMsgWalletIsUnlocked(pwallet);

    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);

    const CBlockIndex* pindex = nullptr;

    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        uint256 blockId;

        blockId.SetHex(request.params[0].get_str());
        pindex = LookupBlockIndex(blockId);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (chainActive[pindex->nHeight] != pindex) {
            // the block being asked for is a part of a deactivated chain;
            // we don't want to depend on its perceived height in the block
            // chain, we want to instead use the last common ancestor
            pindex = chainActive.FindFork(pindex);
        }
    }

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    TransactionsMap& transactions = pwallet->encrMsgMapWallet;
    std::map<std::string, std::string> &addressBook = pwallet->mapMessengerAddressBook;
    UniValue txnsList(UniValue::VARR);

    for (auto index = transactions.begin(); index != transactions.end(); ++index)
    {
        const TransactionValue &it = index->second;

        if (depth == -1 || it.wltTx.GetDepthInMainChain() < depth)
        {
            UniValue entry(UniValue::VOBJ);

            time_t t = (it.wltTx.nTimeSmart > 0 ? it.wltTx.nTimeSmart : it.wltTx.nTimeReceived);
            std::tm *ptm = std::localtime(&t);
            char buffer[32];
            std::strftime(buffer, sizeof(buffer), "%d.%m.%Y %H:%M", ptm);
            entry.pushKV("date", buffer);
            entry.pushKV("txid", index->first.ToString().c_str());
            entry.pushKV("block hash", it.wltTx.hashBlock.ToString().c_str());

            auto sender = addressBook.find(it.from);
            if (sender != addressBook.end())
            {
                entry.pushKV("from", sender->second);
            }

            txnsList.push_back(entry);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", txnsList);
    ret.pushKV("lastblock", chainActive[chainActive.Height()]->GetBlockHash().GetHex());

    return ret;
}

static UniValue createmsgtransaction(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
                "createmsgtransaction \"subject\" \"string\" \"public_key\" \"threads\" \n"
                "\nStores encrypted message in a blockchain.\n"
                "Before this command walletpassphrase is required. \n"
                "Message is free (no fee paid), but user needs to perform some work to send it. \n"
                "Note! The work will take some time, depending on the cpu speed."
                "When it's done, sending next message will be available. \n"

                "\nArguments:\n"
                "1. \"subject\"                     (string, required) A user message string\n"
                "2. \"message\"                     (string, required) A user message string\n"
                "3. \"public_key\"                  (string, required) Receiver public key (length: 2048)\n"
                "4. \"threads\"                     (numeric, optional, default="+std::to_string(GetNumCores())+") The number of threads to be used for mining tx\n"

                "\nResult:\n"
                "\"txid\"                           (string) A hex-encoded transaction id\n"


                "\nExamples:\n"

                + HelpExampleCli("createmsgtransaction", " \"subject\" \"mystring\" \"-----BEGIN PUBLIC KEY-----\n"\
                                 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqZSulRpOGFkqG+ohYaGf\n"\
                                 "iKhYEmQF/qTg9Mtl6ATsXyLSQ9pIiNQB07lOUEo7vx62U10JoliSbs6xv2v0CcBd\n"\
                                 "YsvWJKzuONckyBGqcZHvSKkscDG0luzVg1NPXXrH8MMJfs4u3H3HdRFhbxecDSp4\n"\
                                 "QOwquEtyyIcVmSdqgYdmzEm7x4M6jQURuM9xQrVA7aA0cupS4YalgJj1W1npNkru\n"\
                                 "u4abrhiTGJ7dGbkEtppBdZqLirKOWz0Z+OK3aZ8HiZaXlDs0VBz+eK+O3m0aIyVh\n"\
                                 "kW8r13uDYCKOaXLpQjiEWtjoOCU56iz+j9dtsio56MIe6npipGbFAN0u+JMjY3V6\n"\
                                 "LQIDAQAB\n"
                                 "-----END PUBLIC KEY-----\" 4")

                + HelpExampleRpc("createmsgtransaction", " \"subject\" \"mystring\"  \"-----BEGIN PUBLIC KEY-----\n"\
                                 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqZSulRpOGFkqG+ohYaGf\n"\
                                 "iKhYEmQF/qTg9Mtl6ATsXyLSQ9pIiNQB07lOUEo7vx62U10JoliSbs6xv2v0CcBd\n"\
                                 "YsvWJKzuONckyBGqcZHvSKkscDG0luzVg1NPXXrH8MMJfs4u3H3HdRFhbxecDSp4\n"\
                                 "QOwquEtyyIcVmSdqgYdmzEm7x4M6jQURuM9xQrVA7aA0cupS4YalgJj1W1npNkru\n"\
                                 "u4abrhiTGJ7dGbkEtppBdZqLirKOWz0Z+OK3aZ8HiZaXlDs0VBz+eK+O3m0aIyVh\n"\
                                 "kW8r13uDYCKOaXLpQjiEWtjoOCU56iz+j9dtsio56MIe6npipGbFAN0u+JMjY3V6\n"\
                                 "LQIDAQAB\n"
                                 "-----END PUBLIC KEY-----\" 4")
    );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();
    EnsureWalletIsUnlocked(pwallet);
    EnsureMsgWalletIsUnlocked(pwallet);

    CMessengerKey rsaPrivateKey, rsaPublicKey;

    if (!pwallet->GetMessengerKeys(rsaPrivateKey, rsaPublicKey))
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not get messenger keys from wallet");
    }

    const std::string fromAddress = rsaPublicKey.toString();
    const std::string subject = request.params[0].get_str();
    const std::string message = request.params[1].get_str();
    const std::string toAddress = request.params[2].get_str();

    if (subject.empty())
        throw std::runtime_error("subject cannot be empty");

    if (subject.size() > 100)
        throw std::runtime_error("subject cannot be longer than 100 letters");

    if (message.empty())
        throw std::runtime_error("message cannot be empty");

    if (message.size() > 1000)
        throw std::runtime_error("message cannot be longer than 1000 letters");

    if (!checkRSApublicKey(toAddress))
        throw std::runtime_error("public key is incorrect");

    int numThreads = gArgs.GetArg("-msgminingthreads", GetNumCores());
    if (numThreads < 1)
        numThreads = GetNumCores();
    if (!request.params[3].isNull() && request.params[3].get_int() > 0)
    {
        numThreads = request.params[3].get_int();
    }

    const std::string signature = signMessage(rsaPrivateKey.toString(), fromAddress);

    std::string msg=MSG_RECOGNIZE_TAG
            + signature
            + fromAddress
            + MSG_DELIMITER
            + subject
            + MSG_DELIMITER
            + message;

    if(msg.length()>maxDataSize)
    {
        throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
    }

    CMessengerKey public_key(toAddress, CMessengerKey::PUBLIC_KEY);

    std::vector<unsigned char> data = createEncryptedMessage(
                reinterpret_cast<const unsigned char*>(msg.c_str()),
                msg.length(),
                public_key.toString().c_str());

    CTransactionRef tx = CreateMsgTx(pwallet, data, numThreads);
    if (!tx) {
        LogPrintf("Failed to mine transaction\n");
        return "Could not mine transaction. An error occurred or txn cancelled.";
    }

    if (!pwallet->SaveMsgToHistory(tx->GetHash(), subject, message, fromAddress, toAddress))
    {
        LogPrintf("Error while saving history\n");
    }

    return tx->GetHash().GetHex();
}

UniValue cancelmsgtransaction(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "cancelmsgtransaction\n"
            "\nStops all pending mining message transactions.\n"
            "\nExamples:\n"
            "\nStart mining message transaction\n"
            + HelpExampleCli("createmsgtransaction", " \"subject\" \"mystring\" \"-----BEGIN PUBLIC KEY-----\n"\
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqZSulRpOGFkqG+ohYaGf\n"\
                "iKhYEmQF/qTg9Mtl6ATsXyLSQ9pIiNQB07lOUEo7vx62U10JoliSbs6xv2v0CcBd\n"\
                "YsvWJKzuONckyBGqcZHvSKkscDG0luzVg1NPXXrH8MMJfs4u3H3HdRFhbxecDSp4\n"\
                "QOwquEtyyIcVmSdqgYdmzEm7x4M6jQURuM9xQrVA7aA0cupS4YalgJj1W1npNkru\n"\
                "u4abrhiTGJ7dGbkEtppBdZqLirKOWz0Z+OK3aZ8HiZaXlDs0VBz+eK+O3m0aIyVh\n"\
                "kW8r13uDYCKOaXLpQjiEWtjoOCU56iz+j9dtsio56MIe6npipGbFAN0u+JMjY3V6\n"\
                "LQIDAQAB\n"
                "-----END PUBLIC KEY-----\" 4") +
            "\nCancel the transaction that is being mined\n"
            + HelpExampleCli("cancelmsgtransaction", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("cancelmsgtransaction", "")
        );

    if (pwallet->IsAbortingMsgTxns()) {
        return false;
    }

    pwallet->AbortPendingMsgTxns();
    return true;
}


static const CRPCCommand commands[] =
{ //  category              name                            actor (function)            argNames
  //  --------------------- ------------------------        -----------------------     ----------
    { "messenger",         "sendmessage",                  &sendmessage,               {"subject", "message", "public_key", "replaceable", "conf_target", "estimate_mode"} },
    { "messenger",         "readmessage",                  &readmessage,               {"txid"} },
    { "messenger",         "getmsgkey",                    &getmsgkey,                 {} },
    { "messenger",         "exportmsgkey",                 &exportmsgkey,              {"destination_path"} },
    { "messenger",         "importmsgkey",                 &importmsgkey,              {"source_path", "rescan"} },
    { "messenger",         "encryptmessenger",             &encryptmessenger,          {"passphrase"} },
    { "messenger",         "messengerpassphrase",          &messengerpassphrase,       {"passphrase", "timeout"} },
    { "messenger",         "messengerlock",                &messengerlock,             {} },
    { "messenger",         "messengerpassphrasechange",    &messengerpassphrasechange, {"oldpassphrase","newpassphrase"} },
    { "messenger",         "listmsgsinceblock",            &listmsgsinceblock,         {"blockhash"} },
    { "messenger",         "createmsgtransaction",         &createmsgtransaction,      {"subject", "message", "public_key", "threads"} },
    { "messenger",         "cancelmsgtransaction",         &cancelmsgtransaction,      {} },
};

void RegisterMessengerRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
