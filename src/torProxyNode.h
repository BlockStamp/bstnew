#ifndef TOR_PROXY_NODE_H
#define TOR_PROXY_NODE_H

#include <string>
#include <stdint.h>

#include "amount.h"
#include "univalue.h"

#if defined(_WIN32) || defined(_WIN64)
    const char* const PYTHON_PATH = "python/python.exe";
    const char* const TOR_PATH = "";
#endif

#ifdef __APPLE__
    const char* const PYTHON_PATH = "";
    const char* const TOR_PATH = "";
#endif

#if defined(__unix) || defined(__linux)
    const char* const PYTHON_PATH = "./python/bin/python3";
    const char* const TOR_PATH = "./tor/bin/tor";
#endif

extern const std::string PROXY_MESSAGE_MARKER;

class TorProxyNode
{
public:
    std::string onion_address;
    std::string bst_address;
    uint32_t reputation{0};
    CAmount payment{0};
    CAmount fee{0};
    uint32_t txns_count{0};

    TorProxyNode();
    TorProxyNode(const std::string& onionAddress, const std::string& bstAddress);

    void fromString(const std::string& data);
    std::string toString() const;
    UniValue toUniValueObj() const;

    bool operator==(const TorProxyNode& node) const
    {
        return (node.onion_address == onion_address);
    }
    bool operator<(const TorProxyNode& node) const
    {
        return (reputation > node.reputation);
    }
};

#endif // TOR_PROXY_NODE_H
