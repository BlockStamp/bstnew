#include "message_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <cstring>
#include <memory>

const int ENCR_MARKER_SIZE = 8;
const std::string ENCR_MARKER = "MESSAGE:";
const std::string MSG_RECOGNIZE_TAG = "MSG"; //< message prefix to recognize after decode
const char MSG_DELIMITER = '\0';

namespace {
using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

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
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    if(1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv)) {
        throw std::runtime_error("Failed to encrypt data");
    }

    const size_t encryptedSize = dataLength + AES_BLOCK_SIZE - (dataLength % AES_BLOCK_SIZE);
    std::unique_ptr<unsigned char[]> encryptedData(new unsigned char[encryptedSize]);

    int len;
    if(1 != EVP_EncryptUpdate(ctx.get(), encryptedData.get(), &len, data, dataLength)) {
        throw std::runtime_error("Failed to encrypt data");
    }
    int totalLength = len;

    if(1 != EVP_EncryptFinal_ex(ctx.get(), encryptedData.get() + len, &len)) {
        throw std::runtime_error("Failed to encrypt data");
    }
    totalLength += len;

    if (totalLength != encryptedSize) {
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
    result.reserve(ENCR_MARKER_SIZE + encryptedKeySize + AES_256_IV_LENGTH_BYTES + encryptedMsgSize);
    result.insert(result.end(), ENCR_MARKER.begin(), ENCR_MARKER.end());
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

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv)) {
        throw std::runtime_error("Failed to decrypt message");
    }

    std::vector<unsigned char> decryptedData;
    decryptedData.resize(dataLength);

    int len;
    if (1 != EVP_DecryptUpdate(ctx.get(), decryptedData.data(), &len, encryptedData, dataLength)) {
        throw std::runtime_error("Failed to decrypt message");
    }
    int totalLength = len;

    if (1 != EVP_DecryptFinal_ex(ctx.get(), decryptedData.data() + len, &len)) {
        throw std::runtime_error("Failed to decrypt message");
    }
    totalLength += len;

    decryptedData.resize(totalLength);

    std::string recognizeTag(decryptedData.begin(), decryptedData.begin()+MSG_RECOGNIZE_TAG.length());
    if (recognizeTag.compare(MSG_RECOGNIZE_TAG) != 0) {
        throw std::runtime_error("Failed to decrypt message");
    }

    decryptedData.erase(decryptedData.begin(), decryptedData.begin()+MSG_RECOGNIZE_TAG.length());

    return decryptedData;
}

void checkMessageMarker(unsigned char* data, int dataLength)
{
    if (dataLength < ENCR_MARKER_SIZE ||
        std::string(data, data+ENCR_MARKER_SIZE) != ENCR_MARKER)
    {
        throw std::runtime_error("Failed to decrypt message");
    }
}

//Note: privateRsaKey must be null terminated
std::vector<unsigned char> createDecryptedMessage(
    unsigned char* encryptedData,
    int dataLength,
    const char* privateRsaKey)
{
    checkMessageMarker(encryptedData, dataLength);
    encryptedData += ENCR_MARKER_SIZE;
    dataLength -= ENCR_MARKER_SIZE;

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

bool generateKeysPair(std::string& publicRsaKey, std::string& privateRsaKey)
{
    size_t privateKeyLength;
    size_t publicKeyLength;

    char *privateKey = nullptr;
    char *publicKey = nullptr;

    BIGNUM *bignum = nullptr;
    RSA *rsa = nullptr;
    unsigned long e = RSA_F4;
    int bits = 2048;
    BIO *bp_public = nullptr, *bp_private = nullptr;
    EVP_PKEY* evp_pkey = nullptr;

    int rv = 0;

    bignum = BN_new();
    rv = BN_set_word(bignum, e);
    if (rv == 1) // generate new key
    {
        evp_pkey = EVP_PKEY_new();
        rsa = RSA_new();
        EVP_PKEY_assign_RSA(evp_pkey, rsa);
        rv = RSA_generate_key_ex(rsa, bits, bignum, nullptr);
    }

    if (rv == 1) // save public key
    {
        bp_public = BIO_new(BIO_s_mem());
        rv = PEM_write_bio_PUBKEY(bp_public, evp_pkey);
    }

    if (rv == 1) // save private key
    {
        bp_private = BIO_new(BIO_s_mem());
        rv = PEM_write_bio_RSAPrivateKey(bp_private, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    }

    publicKeyLength = BIO_pending(bp_public);
    privateKeyLength = BIO_pending(bp_private);

    publicKey = new char[publicKeyLength + 1];
    privateKey = new char[privateKeyLength + 1];

    BIO_read(bp_public, publicKey, publicKeyLength);
    BIO_read(bp_private, privateKey, privateKeyLength);

    publicKey[publicKeyLength] = '\0';
    privateKey[privateKeyLength] = '\0';

    publicRsaKey = publicKey;
    privateRsaKey = privateKey;

    delete publicKey;
    delete privateKey;

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(rsa);
    BN_free(bignum);

    return (rv == 1);

}
