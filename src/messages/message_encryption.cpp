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

//std::pair<std::unique_ptr<unsigned char[]>, std::size_t> encryptWithAES(
//    const unsigned char* data,
//    std::size_t dataLength,
//    unsigned char* key,
//    unsigned char* iv)
//{
//    AES_KEY encKey;
//    const int result = AES_set_encrypt_key(key, AES_256_KEY_LENGTH, &encKey);
//    if (result != 0) {
//        throw std::runtime_error("Failed to set key for encryption");
//    }

//    unsigned char mixedIv[AES_256_IV_LENGTH_BYTES];
//    memcpy(mixedIv, iv, AES_256_IV_LENGTH_BYTES);

//    const size_t encryptedSize = dataLength + AES_BLOCK_SIZE - (dataLength % AES_BLOCK_SIZE);
//    std::unique_ptr<unsigned char[]> encryptedData(new unsigned char[encryptedSize]);
//    AES_cbc_encrypt(data, encryptedData.get(), dataLength, &encKey, mixedIv, AES_ENCRYPT);

//    return std::make_pair(std::move(encryptedData), encryptedSize);
//}

std::pair<std::unique_ptr<unsigned char[]>, std::size_t> encryptWithAES(
    const unsigned char* data,
    std::size_t dataLength,
    unsigned char* key,
    unsigned char* iv)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        throw std::runtime_error("Failed to encrypt data");
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        throw std::runtime_error("Failed to encrypt data");
    }

    const size_t encryptedSize = dataLength + AES_BLOCK_SIZE - (dataLength % AES_BLOCK_SIZE);
    std::unique_ptr<unsigned char[]> encryptedData(new unsigned char[encryptedSize]);

    if(1 != EVP_EncryptUpdate(ctx, encryptedData.get(), &len, data, dataLength)) {
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, encryptedData.get() + len, &len)) {
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    if (ciphertext_len != encryptedSize) {
        std::runtime_error("Failed to encrypt data");
    }

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

    // seeding needed?
    const int encrypteLength = RSA_public_encrypt(dataLength, data, encryptedData.get(), rsa, padding);
    if (encrypteLength == -1 || encrypteLength != encryptedSize) {
        throw std::runtime_error("Failed to encrypt with RSA key");
    }

    return std::make_pair(std::move(encryptedData), encryptedSize);
}
}

//Note: publicRsaKey must be null terminated
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

int decryptKey(unsigned char* encryptedData, int dataLength, const char* rsaKey, unsigned char* decryptedKey)
{
    BIO* keybio = BIO_new_mem_buf(rsaKey, -1);
    if (keybio == nullptr) {
        throw std::runtime_error("Failed to create BIO");
    }

    RSA* rsa = nullptr;
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, nullptr, nullptr);
    if (rsa == nullptr) {
        throw std::runtime_error("Failed to create RSA");
    }

    const int rsaSize = RSA_size(rsa);
    if (dataLength < rsaSize) {
        throw std::runtime_error("Failed to decrypt message");
    }

    const int result = RSA_private_decrypt(rsaSize, encryptedData, decryptedKey, rsa, padding);
    if (result == -1 || result != AES_256_KEY_LENGTH_BYTES) {
        throw std::runtime_error("Failed to decrypt message");
    }

    return rsaSize;
}

int readIv(unsigned char* data, size_t dataLength, unsigned char* iv) {
    if (dataLength < AES_256_IV_LENGTH_BYTES) {
        throw std::runtime_error("Failed to decrypt message");
    }

    memcpy(iv, data, AES_256_IV_LENGTH_BYTES);
    return AES_256_IV_LENGTH_BYTES;
}

std::vector<unsigned char> decryptData(
    unsigned char* encryptedData,
    int dataLength,
    unsigned char* key,
    unsigned char* iv)
{
    if (dataLength <= 0 || dataLength % AES_BLOCK_SIZE != 0) {
        throw std::runtime_error("Failed to decrypt message");
    }

    EVP_CIPHER_CTX* ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))  {
        throw std::runtime_error("Failed to decrypt message");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        throw std::runtime_error("Failed to decrypt message");
    }

    std::vector<unsigned char> decryptedData;
    decryptedData.resize(dataLength);

    int len;
    if (1 != EVP_DecryptUpdate(ctx, decryptedData.data(), &len, encryptedData, dataLength)) {
        throw std::runtime_error("Failed to decrypt message");
    }
    int totalLength = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len)) {
        throw std::runtime_error("Failed to decrypt message");
    }
    totalLength += len;

    EVP_CIPHER_CTX_free(ctx); // what if exception if thrown

    decryptedData.resize(totalLength);
    return decryptedData;
}

//Note: privateRsaKey must be null terminated
std::vector<unsigned char> createDecryptedMessage(
    unsigned char* encryptedData,
    int dataLength,
    const char* privateRsaKey)
{
    unsigned char aesKey[AES_256_KEY_LENGTH_BYTES];
    const int encKeyLen = decryptKey(encryptedData, dataLength, privateRsaKey, aesKey);
    encryptedData += encKeyLen;
    dataLength -= encKeyLen;

    unsigned char aesIv[AES_256_IV_LENGTH_BYTES];
    const int ivLen = readIv(encryptedData, dataLength, aesIv);
    encryptedData += ivLen;
    dataLength -= ivLen;

    return decryptData(encryptedData, dataLength, aesKey, aesIv);
}
