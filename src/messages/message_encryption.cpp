#include "message_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <cstring>

namespace {

const size_t AES_256_KEY_LENGTH = 256;
const size_t AES_256_KEY_LENGTH_IN_BYTES = AES_256_KEY_LENGTH/8;
const size_t AES_256_IV_LENGTH_IN_BYTES = 16;
const size_t RSA_ENCRYPTION_SIZE = 256; /* RSA with key 2048 bit long assumed */
const int padding = RSA_PKCS1_OAEP_PADDING;

void generateRandomKey(unsigned char* key)
{
    const int result = RAND_bytes(key, AES_256_KEY_LENGTH_IN_BYTES);
    if (result != 1) {
        throw std::runtime_error("Could not create random key for message encryption");
    }
}

void generateRandomIv(unsigned char* iv)
{
    const int result = RAND_bytes(iv, AES_256_IV_LENGTH_IN_BYTES);
    if (result != 1) {
        throw std::runtime_error("Could not create random iv for message encryption");
    }
}

void encryptMessageWithAES(
    const unsigned char* dataToEncrypt,
    size_t dataLength,
    unsigned char* key,
    unsigned char* iv,
    unsigned char* encryptedData)
{

    AES_KEY encKey;
    AES_set_encrypt_key(key, AES_256_KEY_LENGTH, &encKey);

    unsigned char mixedIv[AES_256_IV_LENGTH_IN_BYTES];
    memcpy(mixedIv, iv, AES_256_IV_LENGTH_IN_BYTES);

    AES_cbc_encrypt(dataToEncrypt, encryptedData, dataLength, &encKey, mixedIv, AES_ENCRYPT);
}

void encryptWithRSA(unsigned char* data, int data_len, const char* rsaKey, unsigned char* encrypted)
{
    BIO* keybio = BIO_new_mem_buf(rsaKey, -1);
    if (keybio == nullptr) {
        throw std::runtime_error("Failed to create key BIO for message encryption");
    }

    RSA* rsa = nullptr;
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, nullptr, nullptr);
    if (rsa == nullptr) {
        throw std::runtime_error("Failed to create key RSA for message encryption");
    }

    const int encrypteLength = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    if (encrypteLength == -1) {
        throw std::runtime_error("Failed to encrypt with RSA key");
    }
}

std::pair<std::unique_ptr<unsigned char[]>, size_t> combineData(
    unsigned char* encryptedKey,
    unsigned char* iv,
    unsigned char* encryptedMsg,
    size_t sizeAfterEncryption)
{
    const size_t totalDataSize = RSA_ENCRYPTION_SIZE + AES_256_IV_LENGTH_IN_BYTES + sizeAfterEncryption;
    std::unique_ptr<unsigned char[]> totalData(new unsigned char[totalDataSize]);
    unsigned char* data = totalData.get();

    memcpy(data, encryptedKey, RSA_ENCRYPTION_SIZE);
    data += RSA_ENCRYPTION_SIZE;

    memcpy(data, iv, AES_256_IV_LENGTH_IN_BYTES);
    data += AES_256_IV_LENGTH_IN_BYTES;

    memcpy(data, encryptedMsg, sizeAfterEncryption);
    return std::make_pair(std::move(totalData), totalDataSize);
}
}

//Note: publicRSAKey must be null terminated
std::pair<std::unique_ptr<unsigned char[]>, size_t> createEncryptedMessage(
    const unsigned char* data,
    const size_t dataLength,
    const char* publicRSAKey)
{
    unsigned char aesKey[AES_256_KEY_LENGTH_IN_BYTES];
    generateRandomKey(aesKey);

    unsigned char aesIv[AES_256_IV_LENGTH_IN_BYTES];
    generateRandomIv(aesIv);

    const size_t sizeAfterEncryption = dataLength + AES_BLOCK_SIZE - (dataLength % AES_BLOCK_SIZE);
    std::unique_ptr<unsigned char[]> encryptedMessageWithAES(new unsigned char[sizeAfterEncryption]);
    encryptMessageWithAES(data, dataLength, aesKey, aesIv, encryptedMessageWithAES.get());

    unsigned char encryptedKeyDataWithRSA[RSA_ENCRYPTION_SIZE];
    encryptWithRSA(aesKey, AES_256_KEY_LENGTH_IN_BYTES, publicRSAKey, encryptedKeyDataWithRSA);

    return combineData(encryptedKeyDataWithRSA, aesIv, encryptedMessageWithAES.get(), sizeAfterEncryption);
}
