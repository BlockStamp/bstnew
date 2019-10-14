// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_UTIL_H
#define BITCOIN_RPC_UTIL_H

#include <pubkey.h>
#include <script/standard.h>
#include <univalue.h>

#include <boost/variant/static_visitor.hpp>

#include <string>
#include <vector>

class CKeyStore;
class CPubKey;
class CScript;
class CCoinControl;
class JSONRPCRequest;

CPubKey HexToPubKey(const std::string& hex_in);
CPubKey AddrToPubKey(CKeyStore* const keystore, const std::string& addr_in);
CScript CreateMultisigRedeemscript(const int required, const std::vector<CPubKey>& pubkeys);
UniValue DescribeAddress(const CTxDestination& dest);
std::vector<char> getOPreturnData(const std::string& txid, const JSONRPCRequest &request);
UniValue setOPreturnData(const std::vector<unsigned char>& data, CCoinControl& coin_control, const JSONRPCRequest& request);

UniValue callRPC(std::string args);

#endif // BITCOIN_RPC_UTIL_H
