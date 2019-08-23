// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DATAUTILS_H
#define DATAUTILS_H

#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>

#include <univalue.h>

extern const std::string gpgMarker;

void hex2ascii(const std::string& in, std::string& out);
std::string byte2str(const unsigned char* binaryData, size_t size);
void hex2bin(std::vector<char>& binaryData, const std::string& hexstr);
void hex2bin(std::vector<unsigned char>& binaryData, const std::string& hexstr);
std::string computeChange(const UniValue& inputs, double fee);
std::string double2str(double val);
void reverseEndianess(std::string& str);

template<typename T, typename Q>
void type2array(T in, std::vector<Q>& array)
{
    array.resize(sizeof(T));
    memcpy(array.data(), reinterpret_cast<Q*>(&in), sizeof(T));
}

template<typename T, typename Q>
void array2type(const std::vector<Q>& array, T& in)
{
    memcpy(reinterpret_cast<Q*>(&in), array.data(), sizeof(T));
}

template<typename T, typename Q>
void array2typeRev(const std::vector<Q>& array, T& in)
{
    std::vector<Q> a=array;
    std::reverse(a.begin(), a.end());
    memcpy(reinterpret_cast<Q*>(&in), a.data(), sizeof(T));
}

template< typename T >
std::string int2hex( T i )
{
    std::stringstream stream;
    stream << std::setfill ('0') << std::setw(sizeof(T)*2) << std::hex << i;
    return stream.str();
}
#endif
