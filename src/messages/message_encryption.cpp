#include "message_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

const size_t AES_256_KEY_LENGTH = 256;
const size_t AES_256_KEY_LENGTH_IN_BYTES = AES_256_KEY_LENGTH/8;
const size_t AES_256_IV_LENGTH_IN_BYTES = 16;
const size_t RSA_ENCRYPTION_SIZE = 256;

void generateRandomKey(unsigned char* key) {
    const int result = RAND_bytes(key, AES_256_KEY_LENGTH_IN_BYTES);
    if (result != 1) {
        throw std::runtime_error("Could not create random key");
    }
}

void generateRandomIv(unsigned char* iv) {
    const int result = RAND_bytes(iv, AES_256_IV_LENGTH_IN_BYTES);
    if (result != 1) {
        throw std::runtime_error("Could not create random iv");
    }
}

void encryptMessageWithAES(
    const unsigned char* dataToEncrypt,
    int plainTextLength,
    unsigned char* key,
    unsigned char* iv,
    unsigned char* encryptedData) {

    AES_KEY encKey;
    AES_set_encrypt_key(key, AES_256_KEY_LENGTH, &encKey);

    unsigned char mixedIv[AES_256_IV_LENGTH_IN_BYTES];
    memcpy(mixedIv, iv, AES_256_IV_LENGTH_IN_BYTES);

    AES_cbc_encrypt(dataToEncrypt, encryptedData, plainTextLength, &encKey, mixedIv, AES_ENCRYPT);
}

//Note: publicRSAKey must be null terminated
void storeEncryptedMessage(unsigned char* data, size_t dataLength, char* publicRSAKey) {

    unsigned char aesKey[AES_256_KEY_LENGTH_IN_BYTES];
    generateRandomKey(aesKey);

    unsigned char aesIv[AES_256_IV_LENGTH_IN_BYTES];
    generateRandomIv(aesIv);

    const size_t sizeAfterEncryption = dataLength + AES_BLOCK_SIZE - (dataLength % AES_BLOCK_SIZE);
    unsigned char encryptedMessageWithAES[sizeAfterEncryption];
    encryptMessageWithAES(
        data,
        dataLength,
        aesKey,
        aesIv,
        encryptedMessageWithAES);
}
