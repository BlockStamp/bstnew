// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/client.h>
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
#include <wallet/coincontrol.h>
#include <torProxyNode.h>

#include <univalue.h>
#include <boost/algorithm/string.hpp>

#include <data/datautils.h>
#include <data/retrievedatatxs.h>
#include <rpc/util.h>

static constexpr size_t maxDataSize=MAX_OP_RETURN_RELAY-6;
static std::string changeAddress("");

template 
<
        class T
>
struct char_traits { };

template<> struct char_traits
<
        char
> 
{
        typedef char char_type;
};

template<> struct char_traits
<
        unsigned char
> 
{
        typedef unsigned char char_type;
};

template <class T> class FileReader
{
public:
    typedef typename char_traits<T>::char_type char_type;
    FileReader(const std::string& fileName_) : file(fileName_.c_str(), std::ios::in|std::ios::binary|std::ios::ate)
    {
        if(!file.is_open())
        {
            throw std::runtime_error("Couldn't open the file");
        }
        size = file.tellg();
    }

    ~FileReader()
    {
        if(file.is_open())
        {
            file.close();
        }
    }

    void read(std::vector<char_type>& binaryData)
    {
        if(file.is_open())
        {
            binaryData.resize(size);
            file.seekg(0, std::ios::beg);
            file.read(reinterpret_cast<char*>(binaryData.data()), size);
        }
    }

private:
    std::ifstream file;
    std::streampos size;
};

class FileWriter
{
public:
    FileWriter(const std::string& fileName_) : file(fileName_.c_str(), std::ios::out|std::ios::binary|std::ios::trunc)
    {
        if(!file.is_open())
        {
            throw std::runtime_error("Couldn't open the file");
        }
    }

    ~FileWriter()
    {
        if(file.is_open())
        {
            file.close();
        }
    }

    void write(const std::vector<char>& binaryData)
    {
        if(file.is_open())
        {
            file.write(binaryData.data(), binaryData.size());
        }
    }

private:
    std::ofstream file;
};

static std::string computeHash(char* binaryData, size_t size)
{
    constexpr size_t hashSize=CSHA256::OUTPUT_SIZE;
    unsigned char fileHash[hashSize];

    CHash256 fileHasher;

    fileHasher.Write(reinterpret_cast<unsigned char*>(binaryData), size);
    fileHasher.Finalize(fileHash);

    return byte2str(&fileHash[0], static_cast<int>(hashSize));                
}

static void computeHash(char* binaryData, size_t size, std::vector<unsigned char>& hash)
{
    constexpr size_t hashSize=CSHA256::OUTPUT_SIZE;
    unsigned char fileHash[hashSize];

    CHash256 fileHasher;

    fileHasher.Write(reinterpret_cast<unsigned char*>(binaryData), size);
    fileHasher.Finalize(fileHash);

    hash.insert(hash.end(), &fileHash[0], &fileHash[hashSize]);
}

UniValue retrievedata(const JSONRPCRequest& request)
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
    throw std::runtime_error(
        "retrievedata \"txid\" \n"
        "\nRetrieves user data from a blockchain.\n"

        "\nArguments:\n"
        "1. \"txid\"                        (string, required) A hex-encoded transaction id string\n"
        "2. \"path to the file\"            (string, optional) A path to the file\n"

        "\nResult:\n"
        "\"string\"                         (string) A retrieved user data string\n"


        "\nExamples:\n"
        + HelpExampleCli("retrievedata", "\"txid\"")
        + HelpExampleRpc("retrievedata", "\"txid\"")
        + HelpExampleCli("retrievedata", "\"txid\" \"/home/myfile.bin\"")
        + HelpExampleRpc("retrievedata", "\"txid\" \"/home/myfile.bin\"")
    );

    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid, request);

    if(!request.params[1].isNull())
    {
        std::string filePath=request.params[1].get_str();
        FileWriter fileWriter(filePath);
        fileWriter.write(OPreturnData);

        return UniValue(UniValue::VSTR);
    }

    std::string retStr=byte2str(reinterpret_cast<unsigned char*>(OPreturnData.data()), OPreturnData.size());
    return UniValue(UniValue::VSTR, std::string("\"")+retStr+std::string("\""));
}

UniValue retrievemessage(const JSONRPCRequest& request)
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    if (request.fHelp || request.params.size() != 1)
    throw std::runtime_error(
        "retrievemessage \"txid\" \n"
        "\nRetrieves user data string from a blockchain.\n"

        "\nArguments:\n"
        "1. \"txid\"                        (string, required) A hex-encoded transaction id string\n"

        "\nResult:\n"
        "\"string\"                         (string) A retrieved user data string\n"


        "\nExamples:\n"
        + HelpExampleCli("retrievemessage", "\"txid\"")
        + HelpExampleRpc("retrievemessage", "\"txid\"")
    );

    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid, request);
    if(!OPreturnData.empty())
    {
        return UniValue(UniValue::VSTR, std::string("\"")+std::string(OPreturnData.begin(), OPreturnData.end())+std::string("\""));
    }

    return UniValue(UniValue::VSTR, std::string("\"\""));
}

UniValue storemessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
    throw std::runtime_error(
        "storemessage \"string\" \n"
        "\nStores a user data string in a blockchain.\n"
        "A transaction fee is computed as a (string length)*(fee rate). \n"
        "Before this command walletpassphrase is required. \n"

        "\nArguments:\n"
        "1. \"message\"                     (string, required) A user message string\n"
        "2. replaceable                     (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
        "3. conf_target                     (numeric, optional) Confirmation target (in blocks)\n"
        "4. \"estimate_mode\"               (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
        "       \"UNSET\"\n"
        "       \"ECONOMICAL\"\n"
        "       \"CONSERVATIVE\"\n"

        "\nResult:\n"
        "\"txid\"                           (string) A hex-encoded transaction id\n"


        "\nExamples:\n"
        + HelpExampleCli("storemessage", "\"mystring\"")
        + HelpExampleRpc("storemessage", "\"mystring\"")
    );

    std::string msg=request.params[0].get_str();

    if(msg.length()>maxDataSize)
    {
        throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
    }

    CCoinControl coin_control;
    if (!request.params[1].isNull())
    {
        coin_control.m_signal_bip125_rbf = request.params[1].get_bool();
    }

    if (!request.params[2].isNull())
    {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[2]);
    }

    if (!request.params[3].isNull())
    {
        if (!FeeModeFromString(request.params[3].get_str(), coin_control.m_fee_mode)) {
            throw std::runtime_error("Invalid estimate_mode parameter");
        }
    }
    std::vector<unsigned char> data(msg.begin(), msg.end());
    return setOPreturnData(data, coin_control, request);
}

UniValue storesignature(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
    throw std::runtime_error(
        "storesignature \"string\" \n"
        "\nStores a hash of a user file into a blockchain.\n"
        "A transaction fee is computed as a (hash length)*(fee rate). \n"
        "Before this command walletpassphrase is required. \n"

        "\nArguments:\n"
        "1. \"path to the file\"            (string, required) A path to the file\n"
        "2. replaceable                     (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
        "3. conf_target                     (numeric, optional) Confirmation target (in blocks)\n"
        "4. \"estimate_mode\"               (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
        "       \"UNSET\"\n"
        "       \"ECONOMICAL\"\n"
        "       \"CONSERVATIVE\"\n"

        "\nResult:\n"
        "\"txid\"                           (string) A hex-encoded transaction id\n"


        "\nExamples:\n"
        + HelpExampleCli("storesignature", "\"/home/myfile.txt\"")
        + HelpExampleRpc("storesignature", "\"/home/myfile.txt\"")
    );

    UniValue res(UniValue::VARR);

    std::string filePath=request.params[0].get_str();

    std::vector<char> binaryData;
    FileReader<char> fileReader(filePath);
    fileReader.read(binaryData);
    std::vector<unsigned char> data;
    computeHash(binaryData.data(), binaryData.size(), data);

    CCoinControl coin_control;
    if (!request.params[1].isNull())
    {
        coin_control.m_signal_bip125_rbf = request.params[1].get_bool();
    }

    if (!request.params[2].isNull())
    {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[2]);
    }

    if (!request.params[3].isNull())
    {
        if (!FeeModeFromString(request.params[3].get_str(), coin_control.m_fee_mode)) {
            throw std::runtime_error("Invalid estimate_mode parameter");
        }
    }
    return setOPreturnData(data, coin_control, request);
}

UniValue storedata(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
    throw std::runtime_error(
        "storedata \"string\" \n"
        "\nStores content of a user file into a blockchain.\n"
        "A transaction fee is computed as a (file size)*(fee rate). \n"
        "Before this command walletpassphrase is required. \n"

        "\nArguments:\n"
        "1. \"path to the file\"            (string, required) A path to the file\n"
        "2. replaceable                     (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
        "3. conf_target                     (numeric, optional) Confirmation target (in blocks)\n"
        "4. \"estimate_mode\"               (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
        "       \"UNSET\"\n"
        "       \"ECONOMICAL\"\n"
        "       \"CONSERVATIVE\"\n"

        "\nResult:\n"
        "\"txid\"                           (string) A hex-encoded transaction id\n"
 
 
        "\nExamples:\n"
        + HelpExampleCli("storedata", "\"/home/myfile.txt\"")
        + HelpExampleRpc("storedata", "\"/home/myfile.txt\"")
    );

    UniValue res(UniValue::VARR);

    std::string filePath=request.params[0].get_str();

    std::vector<unsigned char> binaryData;

    FileReader<unsigned char> fileReader(filePath);
    fileReader.read(binaryData);

    if(binaryData.size()>maxDataSize)
    {
        throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
    }

    CCoinControl coin_control;
    if (!request.params[1].isNull())
    {
        coin_control.m_signal_bip125_rbf = request.params[1].get_bool();
    }

    if (!request.params[2].isNull())
    {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[2]);
    }

    if (!request.params[3].isNull())
    {
        if (!FeeModeFromString(request.params[3].get_str(), coin_control.m_fee_mode)) {
            throw std::runtime_error("Invalid estimate_mode parameter");
        }
    }
    return setOPreturnData(binaryData, coin_control, request);
}

UniValue checkmessage(const JSONRPCRequest& request)
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR});

    if (request.fHelp || request.params.size() != 2)
    throw std::runtime_error(
        "checkmessage \"txid\" \"message\" \n"
        "\nChecks user data string against the message in a blockchain.\n"

        "\nArguments:\n"
        "1. \"txid\"                        (string, required) A hex-encoded transaction id string\n"
        "2. \"message\"                     (string, required) A user message string\n"

        "\nResult:\n"
        "\"string\"                         (string) PASS or FAIL\n"


        "\nExamples:\n"
        + HelpExampleCli("checkmessage", "\"txid\" \"message\"")
        + HelpExampleRpc("checkmessage", "\"txid\" \"message\"")
    );

    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid, request);
    if(!OPreturnData.empty())
    {
        std::string blockchainHash=computeHash(OPreturnData.data(), OPreturnData.size());

        std::string  message=request.params[1].get_str();
        std::string hexMsg=HexStr(message.begin(), message.end());
        std::vector<char> messageBinaryData;
        messageBinaryData.resize(hexMsg.length()/2);
        hex2bin(messageBinaryData, hexMsg);
        std::string messageHash=computeHash(messageBinaryData.data(), messageBinaryData.size());

        if(messageHash.compare(blockchainHash))
        {
            return UniValue(UniValue::VSTR, std::string("FAIL"));
        }

        return UniValue(UniValue::VSTR, std::string("PASS"));
    }

    return UniValue(UniValue::VSTR, std::string("FAIL"));
}

UniValue checkdata(const JSONRPCRequest& request)
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR});

    if (request.fHelp || request.params.size() != 2)
    throw std::runtime_error(
        "checkdata \"txid\" \"path to the file\" \n"
        "\nChecks user data file content against the data in a blockchain.\n"

        "\nArguments:\n"
        "1. \"txid\"                        (string, required) A hex-encoded transaction id string\n"
        "2. \"path to the file\"            (string, required) A path to the file\n"

        "\nResult:\n"
        "\"string\"                         (string) PASS or FAIL\n"


        "\nExamples:\n"
        + HelpExampleCli("checkdata", "\"txid\" \"path to the file\"")
        + HelpExampleRpc("checkdata", "\"txid\" \"path to the file\"")
    );


    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid, request);

    if(!request.params[1].isNull())
    {
        std::string blockchainHash=computeHash(OPreturnData.data(), OPreturnData.size());

        std::string filePath=request.params[1].get_str();
        std::vector<char> binaryData;

        FileReader<char> fileReader(filePath);
        fileReader.read(binaryData);

        if(binaryData.size()>maxDataSize)
        {
            throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
        }

        std::string dataHash=computeHash(binaryData.data(), binaryData.size());
        if(dataHash.compare(blockchainHash))
        {
            return UniValue(UniValue::VSTR, std::string("FAIL"));
        }

        return UniValue(UniValue::VSTR, std::string("PASS"));
    }

    return UniValue(UniValue::VSTR, std::string("FAIL"));
}

UniValue checksignature(const JSONRPCRequest& request)
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR});

    if (request.fHelp || request.params.size() != 2)
    throw std::runtime_error(
        "checksignature \"txid\" \"path to the file\" \n"
        "\nChecks user data file signature against the signature in a blockchain.\n"

        "\nArguments:\n"
        "1. \"txid\"                        (string, required) A hex-encoded transaction id string\n"
        "2. \"path to the file\"            (string, required) A path to the file\n"

        "\nResult:\n"
        "\"string\"                         (string) PASS or FAIL\n"


        "\nExamples:\n"
        + HelpExampleCli("checksignature", "\"txid\" \"path to the file\"")
        + HelpExampleRpc("checksignature", "\"txid\" \"path to the file\"")
    );


    std::string txid=request.params[0].get_str();
    std::vector<char> OPreturnData=getOPreturnData(txid, request);
    std::string OPreturnDataStr=byte2str(reinterpret_cast<unsigned char*>(OPreturnData.data()), OPreturnData.size());
    std::transform(OPreturnDataStr.begin(), OPreturnDataStr.end(), OPreturnDataStr.begin(), ::toupper);

    if(!request.params[1].isNull())
    {
        std::string filePath=request.params[1].get_str();
        std::vector<char> binaryData;

        FileReader<char> fileReader(filePath);
        fileReader.read(binaryData);

        if(binaryData.size()>maxDataSize)
        {
            throw std::runtime_error(strprintf("data size is grater than %d bytes", maxDataSize));
        }

        std::string dataHash=computeHash(binaryData.data(), binaryData.size());
        if(dataHash.compare(OPreturnDataStr))
        {
            return UniValue(UniValue::VSTR, std::string("FAIL"));
        }

        return UniValue(UniValue::VSTR, std::string("PASS"));
    }

    return UniValue(UniValue::VSTR, std::string("FAIL"));
}

static UniValue gettoraddresses(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "gettoraddresses ( count )\n"
            "\nReturn known tor proxy addresses\n"
            "\nArguments:\n"
            "1. \"count\"    (numeric, optional) How many addresses to return. (default = all)\n"
            "\nExamples:\n"
            + HelpExampleCli("gettoraddresses", "1")
            + HelpExampleRpc("getnodeaddresses", "1")
        );
    }

    pwallet->BlockUntilSyncedToCurrentChain();
    EnsureWalletIsUnlocked(pwallet);

    int count = -1;
    if (!request.params[0].isNull()) {
        count = request.params[0].get_int();
        if (count <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Address count out of range");
        }
    }

    //TODO: how to return sorted items based on reputation
    std::map<std::string, TorProxyNode> vAddr = pwallet->vProxyNodes;
    UniValue ret(UniValue::VARR);

    if (count < 0)
        count = vAddr.size();

    std::map<std::string, TorProxyNode>::iterator it = vAddr.begin();
    for (int i=0; i<count; ++i) {
        ret.push_back(it->second.toUniValueObj());
        ++it;
    }

    return ret;
}

UniValue torbroadcastyourself(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
    {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "torbroadcastyourself" //TODO
        );
    }

    EnsureWalletIsUnlocked(pwallet);
    EnsureMsgWalletIsUnlocked(pwallet);

    //CREATE message, normal message with fee
    //add new tag for tor broadcast
    //send message
    const std::string torNodeStr = pwallet->myOwnProxyService.toString();
    std::vector<unsigned char> msg;
    msg.reserve(PROXY_MESSAGE_MARKER.length() + torNodeStr.length());
    msg.insert(msg.end(), PROXY_MESSAGE_MARKER.begin(), PROXY_MESSAGE_MARKER.end());
    msg.insert(msg.end(), torNodeStr.begin(), torNodeStr.end());

    CCoinControl coin_control;
    UniValue txid = setOPreturnData(msg, coin_control, request);
    return txid;
}


static const CRPCCommand commands[] =
{ //  category              name                            actor (function)            argNames
  //  --------------------- ------------------------        -----------------------     ----------
    { "blockstamp",         "storemessage",                	&storemessage,             {"message", "replaceable", "conf_target", "estimate_mode"} },
    { "blockstamp",         "retrievemessage",             	&retrievemessage,          {"txid"} },
    { "blockstamp",         "retrievedata",             	&retrievedata,             {"txid"} },
    { "blockstamp",         "storesignature",             	&storesignature,           {"file_path", "replaceable", "conf_target", "estimate_mode"} },
    { "blockstamp",         "storedata",             		&storedata,          	   {"file_path", "replaceable", "conf_target", "estimate_mode"} },
    { "blockstamp",         "checkmessage",             	&checkmessage,             {"txid", "message"} },
    { "blockstamp",         "checkdata",             		&checkdata,          	   {"txid", "file_path"} },
    { "blockstamp",         "checksignature",             	&checksignature,           {"txid", "file_path"} },
    { "blockstamp",         "gettoraddresses",              &gettoraddresses,          {"count"} },
    { "blockstamp",         "torbroadcastyourself",         &torbroadcastyourself,     {} },
};

void RegisterDataRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
