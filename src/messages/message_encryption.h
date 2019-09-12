#ifndef MESSAGE_ENCRYPTION_H
#define MESSAGE_ENCRYPTION_H

#include <string>
#include <vector>
#include <utility>

extern const int ENCR_MARKER_SIZE;
extern const std::string ENCR_MARKER;
extern const std::string MSG_RECOGNIZE_TAG;
extern const char MSG_DELIMITER;

extern const size_t PUBLIC_RSA_KEY_LEN;
extern const size_t PRIVATE_RSA_KEY_LEN;

std::vector<unsigned char> createEncryptedMessage(const unsigned char *data, std::size_t dataLength, const char *publicRsaKey);
std::vector<unsigned char> createDecryptedMessage(unsigned char* encryptedData, int dataLength, const char* privateRsaKey);

bool generateKeysPair(std::string &publicRsaKey, std::string &privateRsaKey);
bool matchRSAKeys(const std::string& publicKey, const std::string& privateKey);

#endif
