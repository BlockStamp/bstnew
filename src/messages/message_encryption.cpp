#include "message_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <cstring>
#include <memory>

namespace {

const size_t AES_256_KEY_LENGTH = 256;
const size_t AES_256_KEY_LENGTH_BYTES = AES_256_KEY_LENGTH/8;
const size_t AES_256_IV_LENGTH_BYTES = 16;
const int padding = RSA_PKCS1_OAEP_PADDING;

void generateRandomKey(unsigned char* key)
{
    const int result = RAND_bytes(key, AES_256_KEY_LENGTH_BYTES);
    if (result != 1) {
        throw std::runtime_error("Could not create random key for message encryption");
    }
}

void generateRandomIv(unsigned char* iv)
{
    const int result = RAND_bytes(iv, AES_256_IV_LENGTH_BYTES);
    if (result != 1) {
        throw std::runtime_error("Could not create random iv for message encryption");
    }
}

std::pair<std::unique_ptr<unsigned char[]>, std::size_t> encryptWithAES(
    const unsigned char* data,
    std::size_t dataLength,
    unsigned char* key,
    unsigned char* iv)
{
    AES_KEY encKey;
    const int result = AES_set_encrypt_key(key, AES_256_KEY_LENGTH, &encKey);
    if (result != 0) {
        throw std::runtime_error("Failed to set key for encryption");
    }

    unsigned char mixedIv[AES_256_IV_LENGTH_BYTES];
    memcpy(mixedIv, iv, AES_256_IV_LENGTH_BYTES);

    const size_t encryptedSize = dataLength + AES_BLOCK_SIZE - (dataLength % AES_BLOCK_SIZE);
    std::unique_ptr<unsigned char[]> encryptedData(new unsigned char[encryptedSize]);
    AES_cbc_encrypt(data, encryptedData.get(), dataLength, &encKey, mixedIv, AES_ENCRYPT);

    return std::make_pair(std::move(encryptedData), encryptedSize);
}

std::pair<std::unique_ptr<unsigned char[]>, std::size_t> encryptWithRsa(
    unsigned char* data,
    int dataLength,
    const char* rsaKey)
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

    const int encryptedSize = RSA_size(rsa);
    std::unique_ptr<unsigned char[]> encryptedData(new unsigned char[encryptedSize]);

    const int encrypteLength = RSA_public_encrypt(dataLength, data, encryptedData.get(), rsa, padding);
    if (encrypteLength == -1 || encrypteLength != encryptedSize) {
        throw std::runtime_error("Failed to encrypt with RSA key");
    }

    return std::make_pair(std::move(encryptedData), encryptedSize);
}
}

//Note: publicRSAKey must be null terminated
std::vector<unsigned char> createEncryptedMessage(
    const unsigned char* data,
    std::size_t dataLength,
    const char* publicRsaKey)
{
    unsigned char aesKey[AES_256_KEY_LENGTH_BYTES];
    generateRandomKey(aesKey);

    unsigned char aesIv[AES_256_IV_LENGTH_BYTES];
    generateRandomIv(aesIv);

    std::unique_ptr<unsigned char[]> encryptedMsg;
    std::size_t encryptedMsgSize;
    std::tie(encryptedMsg, encryptedMsgSize) = encryptWithAES(data, dataLength, aesKey, aesIv);

    std::unique_ptr<unsigned char[]> encryptedKey;
    std::size_t encryptedKeySize;
    std::tie(encryptedKey, encryptedKeySize) = encryptWithRsa(aesKey, AES_256_KEY_LENGTH_BYTES, publicRsaKey);

    std::vector<unsigned char> result;
    result.reserve(encryptedKeySize + AES_256_IV_LENGTH_BYTES + encryptedMsgSize);
    result.insert(result.end(), encryptedKey.get(), encryptedKey.get()+encryptedKeySize);
    result.insert(result.end(), aesIv, aesIv+AES_256_IV_LENGTH_BYTES);
    result.insert(result.end(), encryptedMsg.get(), encryptedMsg.get()+encryptedMsgSize);

    return result;
}
