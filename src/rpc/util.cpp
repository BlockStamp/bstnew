// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/client.h>
#include <key_io.h>
#include <keystore.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <wallet/wallet.h>
#include <data/retrievedatatxs.h>
#include <utilmoneystr.h>
#include <consensus/validation.h>
#include <validation.h>
#include <net.h>
#include <wallet/rpcwallet.h>
#include <messages/message_encryption.h>
#include <internal_miner.h>

#include <boost/algorithm/string.hpp>

// Converts a hex string to a public key if possible
CPubKey HexToPubKey(const std::string& hex_in)
{
    if (!IsHex(hex_in)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    CPubKey vchPubKey(ParseHex(hex_in));
    if (!vchPubKey.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    return vchPubKey;
}

// Retrieves a public key for an address from the given CKeyStore
CPubKey AddrToPubKey(CKeyStore* const keystore, const std::string& addr_in)
{
    CTxDestination dest = DecodeDestination(addr_in);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr_in);
    }
    CKeyID key = GetKeyForDestination(*keystore, dest);
    if (key.IsNull()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s does not refer to a key", addr_in));
    }
    CPubKey vchPubKey;
    if (!keystore->GetPubKey(key, vchPubKey)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("no full public key for address %s", addr_in));
    }
    if (!vchPubKey.IsFullyValid()) {
       throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet contains an invalid public key");
    }
    return vchPubKey;
}

// Creates a multisig redeemscript from a given list of public keys and number required.
CScript CreateMultisigRedeemscript(const int required, const std::vector<CPubKey>& pubkeys)
{
    // Gather public keys
    if (required < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "a multisignature address must require at least one key to redeem");
    }
    if ((int)pubkeys.size() < required) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("not enough keys supplied (got %u keys, but need at least %d to redeem)", pubkeys.size(), required));
    }
    if (pubkeys.size() > 16) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Number of keys involved in the multisignature address creation > 16\nReduce the number");
    }

    CScript result = GetScriptForMultisig(required, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, (strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE)));
    }

    return result;
}

class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    explicit DescribeAddressVisitor() {}

    UniValue operator()(const CNoDestination& dest) const
    {
        return UniValue(UniValue::VOBJ);
    }

    UniValue operator()(const CKeyID& keyID) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", false);
        obj.pushKV("iswitness", false);
        return obj;
    }

    UniValue operator()(const CScriptID& scriptID) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        obj.pushKV("iswitness", false);
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", false);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", 0);
        obj.pushKV("witness_program", HexStr(id.begin(), id.end()));
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", 0);
        obj.pushKV("witness_program", HexStr(id.begin(), id.end()));
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", (int)id.version);
        obj.pushKV("witness_program", HexStr(id.program, id.program + id.length));
        return obj;
    }
};

UniValue DescribeAddress(const CTxDestination& dest)
{
    return boost::apply_visitor(DescribeAddressVisitor(), dest);
}

UniValue callRPC(std::string args)
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

std::vector<char> getOPreturnData(const std::string& txid, const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* pwallet=nullptr;
    if(wallet!=nullptr)
    {
        pwallet=wallet.get();
    }

    RetrieveDataTxs retrieveDataTxs(txid, pwallet);
    return retrieveDataTxs.getTxData();
}

UniValue setOPreturnData(const std::vector<unsigned char>& data, CCoinControl& coin_control, const JSONRPCRequest& request)
{
    UniValue res(UniValue::VARR);

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if(wallet==nullptr)
    {
        throw std::runtime_error(std::string("No wallet found"));
    }
    CWallet* const pwallet=wallet.get();

    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    CAmount curBalance = pwallet->GetBalance();

    CRecipient recipient;
    recipient.scriptPubKey << OP_RETURN << data;
    recipient.nAmount=0;
    recipient.fSubtractFeeFromAmount=false;

    std::vector<CRecipient> vecSend;
    vecSend.push_back(recipient);

    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    int nChangePosInOut=1;
    std::string strFailReason;
    CTransactionRef tx;

    EnsureWalletIsUnlocked(pwallet);

    if(!pwallet->CreateTransaction(vecSend, nullptr, tx, reservekey, nFeeRequired, nChangePosInOut, strFailReason, coin_control))
    {
        if (nFeeRequired > curBalance)
        {
            strFailReason = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        }
        throw std::runtime_error(std::string("CreateTransaction failed with reason: ")+strFailReason);
    }

    CValidationState state;
    if(!pwallet->CommitTransaction(tx, {}, {}, reservekey, g_connman.get(), state))
    {
        throw std::runtime_error(std::string("CommitTransaction failed with reason: ")+FormatStateMessage(state));
    }

    std::string txid=tx->GetHash().GetHex();
    return UniValue(UniValue::VSTR, txid);
}

CTransactionRef CreateMsgTx(CWallet * const pwallet, const std::vector<unsigned char>& data, int numThreads)
{
    CMutableTransaction txNew;

    assert((int)data.size() > ENCR_MARKER_SIZE);
    CScript scriptPubKey;
    std::vector<unsigned char> extData;
    extData.insert(extData.end(), ENCR_FREE_MARKER.begin(), ENCR_FREE_MARKER.end());
    extData.insert(extData.end(), data.begin() + ENCR_MARKER_SIZE, data.end()); // skip default ENCR_MARKER tag (already added).
    extData.insert(extData.end(), 12, 0); // placehoder for additional data info (block and nonce).
    scriptPubKey << OP_RETURN << extData;

    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetMsg();

    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKey;
    txNew.vout[0].nValue = 0;

    printf("Hash before: %s\n", txNew.GetHash().GetHex().c_str());
    int64_t nStart = GetTime();
    internal_miner::ExtNonce extNonce{};
    internal_miner::Miner(*pwallet, numThreads).mineTransaction(txNew, extNonce);

    if (extNonce.isNull()) {
        LogPrintf("Could not mine transaction. Possible shutdown request or transaction cancelled.\n");
        return nullptr;
    }

    LogPrintf("\nDuration: %ld seconds\n\n", GetTime() - nStart);

    CTransactionRef tx = MakeTransactionRef(std::move(txNew));
    assert(!tx->IsCoinBase());
    assert(tx->IsMsgTx());

//    if (!pwallet->CreateTransaction(/*vecSend, withInput,*/ tx/*, reservekey, nFeeRequired, nChangePosRet, strError, coin_control*/)) {
//        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > curBalance)
//            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
//        throw JSONRPCError(RPC_WALLET_ERROR, strError);
//    }
    CReserveKey reservekey(pwallet);

    CValidationState state;
    if (!pwallet->CommitTransaction(tx, {}, {}, reservekey, g_connman.get(), state)) {
        std::string strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    return tx;
}

