#ifndef TOR_PROXY_NODE_H
#define TOR_PROXY_NODE_H

#include <string>
#include <sstream>
#include <stdint.h>
#include <serialize.h>
#include <boost/algorithm/string.hpp>

const char* const TOR_DATA_DELIMITER = "\n";

struct TorProxyNode
{
    std::string onion_address;
    std::string bst_address;
    uint32_t reputation;
    void fromString(const std::string& data)
    {
        std::size_t current, previous;
        current = data.find(TOR_DATA_DELIMITER);
        if (current == std::string::npos)
            throw std::runtime_error("incorrect data");
        onion_address = data.substr(0, current);
        previous = current+1;

        current = data.find(TOR_DATA_DELIMITER, previous);
        if (current == std::string::npos)
            throw std::runtime_error("incorrect data");
        bst_address = data.substr(previous, current - previous);
        previous = current+1;

        reputation = std::stoi(data.substr(previous));
    }
    std::string toString() const
    {
        std::stringstream ss{};
        ss << onion_address << "\n" << bst_address << "\n" << reputation;
        return ss.str();
    }
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
