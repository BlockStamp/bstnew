#include <torProxyNode.h>

#include <sstream>
#include <serialize.h>
#include <boost/algorithm/string.hpp>

const std::string PROXY_MESSAGE_MARKER = "TORPROXY";

const char* const TOR_DATA_DELIMITER = "\n";
const unsigned int NO_OF_VARS = 6;

TorProxyNode::TorProxyNode()
    : onion_address(""), bst_address("") {}

TorProxyNode::TorProxyNode(const std::string& onionAddress, const std::string& bstAddress)
    : onion_address(onionAddress), bst_address(bstAddress) {}


void TorProxyNode::fromString(const std::string& data)
{
    std::vector<std::string> lines;
    boost::split(lines, data, boost::is_any_of(TOR_DATA_DELIMITER));
    if (lines.size() < NO_OF_VARS)
        throw std::runtime_error("incorrect data");

    onion_address = lines[0];
    bst_address = lines[1];
    reputation = std::stoul(lines[2]);
    payment = std::stoi(lines[3]);
    fee = std::stoi(lines[4]);
    txns_count = std::stoul(lines[5]);
}

std::string TorProxyNode::toString() const
{
    std::stringstream ss{};
    ss << onion_address << TOR_DATA_DELIMITER
       << bst_address << TOR_DATA_DELIMITER
       << reputation << TOR_DATA_DELIMITER
       << payment << TOR_DATA_DELIMITER
       << fee << TOR_DATA_DELIMITER
       << txns_count << TOR_DATA_DELIMITER;
    return ss.str();
}

UniValue TorProxyNode::toUniValueObj() const
{
    UniValue obj(UniValue::VARR);
    obj.push_back(onion_address);
    obj.push_back(bst_address);
    obj.push_back((int)reputation);
    obj.push_back(payment);
    obj.push_back(fee);
    obj.push_back((int)txns_count);
    return obj;
}
