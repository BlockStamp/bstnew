#ifndef MESSAGE_ENCRYPTION_H
#define MESSAGE_ENCRYPTION_H

#include <string>
#include <vector>
#include <utility>

const int ENCR_MARKER_SIZE = 8;
const std::string ENCR_MARKER = "MESSAGE:";
const std::string MSG_RECOGNIZE_TAG = "MSG"; //< message prefix to recognize after decode

std::vector<unsigned char> createEncryptedMessage(const unsigned char *data, std::size_t dataLength, const char *publicRsaKey);
std::vector<unsigned char> createDecryptedMessage(unsigned char* encryptedData, int dataLength, const char* privateRsaKey);

bool generateKeysPair(std::string &publicRsaKey, std::string &privateRsaKey);

#endif
