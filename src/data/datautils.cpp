// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sstream>
#include <iomanip>

#include <data/datautils.h>

const std::string gpgMarker = "GPG";

static unsigned char hexval(unsigned char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    else throw std::runtime_error("hexval decoding failed");
}

void hex2ascii(const std::string& in, std::string& out)
{
    out.clear();
    out.reserve(in.length() / 2);
    for (std::string::const_iterator p = in.begin(); p != in.end(); p++)
    {
       unsigned char c = hexval(*p);
       p++;
       if (p == in.end()) break;
       c = (c << 4) + hexval(*p);
       out.push_back(c);
    }
}

std::string byte2str(const unsigned char* binaryData, size_t size)
{
	const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B','C','D','E','F'};
	std::string str;
	for (size_t i = 0; i < size; ++i) 
	{
		const unsigned char ch = binaryData[i];
		str.append(&hex[(ch  & 0xF0) >> 4], 1);
		str.append(&hex[ch & 0xF], 1);
	}
	return str;
}

void hex2bin(std::vector<char>& binaryData, const std::string& hexstr)
{
    char hex_byte[3];
    char *ep;

    hex_byte[2] = '\0';
    int i=0;
    size_t len=hexstr.length();
    for(size_t j=0; j<len; j+=2, i++) 
    {
        if(!hexstr[1]) 
        {
            throw std::runtime_error("hex2bin str truncated");
        }
        hex_byte[0] = hexstr[j];
        hex_byte[1] = hexstr[j+1];
        binaryData[i] = static_cast<char>(strtol(hex_byte, &ep, 16));
        if(*ep) 
        {
            throw std::runtime_error("hex2bin failed");
        }
    }
}

void hex2bin(std::vector<unsigned char>& binaryData, const std::string& hexstr)
{
    char hex_byte[3];
    char *ep;

    hex_byte[2] = '\0';
    int i=0;
    size_t len=hexstr.length();
    for(size_t j=0; j<len; j+=2, i++) 
    {
        if(!hexstr[1]) 
        {
            throw std::runtime_error("hex2bin str truncated");
        }
        hex_byte[0] = hexstr[j];
        hex_byte[1] = hexstr[j+1];
        binaryData[i] = static_cast<unsigned char>(strtol(hex_byte, &ep, 16));
        if(*ep) 
        {
            throw std::runtime_error("hex2bin failed");
        }
    }
}

std::string double2str(double val)
{
    std::ostringstream strs;
    strs << std::setprecision(9) << val;
    return strs.str();
}

std::string computeChange(const UniValue& inputs, double fee)
{
    double amount=0.0;
    for(size_t i=0; i<inputs.size(); ++i)
    {
        amount+=inputs[i][std::string("amount")].get_real();
    }

    return double2str(amount-fee);
}

void reverseEndianess(std::string& str)
{
	std::string tmp=str;
	size_t length=str.length();
	if(length%2)
	{
        throw std::runtime_error("reverseEndianess input must have even length");
	}
	for(size_t i=0; i<length; i+=2)
	{
		tmp[i]=str[length-i-2];
		tmp[i+1]=str[length-i-1];
	}
	str.swap(tmp);
}
