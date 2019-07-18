#ifndef MESSAGE_ENCRYPTION_H
#define MESSAGE_ENCRYPTION_H

#include <vector>
#include <utility>

std::vector<unsigned char> createEncryptedMessage(const unsigned char *data, std::size_t dataLength, const char *publicRsaKey);
std::vector<unsigned char> createDecryptedMessage(unsigned char* encryptedData, int dataLength, const char* privateRsaKey);

#endif
