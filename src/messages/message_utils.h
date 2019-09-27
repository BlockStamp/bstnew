#ifndef MESSAGE_UTILS_H
#define MESSAGE_UTILS_H

#include <string>
#include <vector>

bool checkRSApublicKey(const std::string& rsaPublicKey);

bool checkRSAprivateKey(const std::string& rsaPrivateKey);

void decryptMessageAndSplit(std::vector<char>& opReturnData,
                            const std::string &privateKey,
                            std::string& from,
                            std::string& subject,
                            std::string& body);

#endif
