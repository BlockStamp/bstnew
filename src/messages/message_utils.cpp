#include "message_utils.h"

#include "logging.h"


static bool is_base64(unsigned char c) {
    return (isalnum(c) || (c=='+') || (c=='/'));
}

//TODO: Consider using openssl for key validation
bool checkRSApublicKey(const std::string& rsaPublicKey) {
    const std::string keyBeg = "-----BEGIN PUBLIC KEY-----";
    const std::string keyEnd = "-----END PUBLIC KEY-----";

    auto posbeg = rsaPublicKey.find(keyBeg);
    if (posbeg != 0) {
        return false;
    }

    auto posend = rsaPublicKey.find(keyEnd);
    if (posend != rsaPublicKey.length() - keyEnd.length()) {
        return false;
    }

    std::size_t encodingLength = 0;
    for(size_t i = keyBeg.length(); i < posend; ++i)
    {
        if (is_base64(rsaPublicKey[i]))
        {
            ++encodingLength;
        }
    }

//    // RSA 1024
//    if (encodingLength == 216) {
//        return true;
//    }

    // RSA 2048
    if (encodingLength == 392) {
        return true;
    }

//    // RSA 4096
//    if (encodingLength == 736) {
//        return true;
//    }

    LogPrintf("Incorrect length of public key: %u\n", encodingLength);
    return false;
}

bool checkRSAprivateKey(const std::string& rsaPrivateKey)
{
    const std::string keyBeg = "-----BEGIN RSA PRIVATE KEY-----";
    const std::string keyEnd = "-----END RSA PRIVATE KEY-----";

    auto posbeg = rsaPrivateKey.find(keyBeg);
    if (posbeg != 0) {
        LogPrintf("Incorrect private key header\n");
        return false;
    }

    auto posend = rsaPrivateKey.find(keyEnd);
    if (posend != rsaPrivateKey.length() - keyEnd.length()) {
        LogPrintf("Incorrect private key footer\n");
        return false;
    }

    return true;

//    std::size_t encodingLength = 0;
//    for(size_t i = keyBeg.length(); i < posend; ++i)
//    {
//        if (is_base64(rsaPrivateKey[i]))
//        {
//            ++encodingLength;
//        }
//    }
//    if (encodingLength == 1590) {
//        LogPrintf("Incorrect length of private key: %u\n", encodingLength);
//        return false;
//    }

}
