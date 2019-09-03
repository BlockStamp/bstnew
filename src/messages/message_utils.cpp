#include "message_utils.h"

//TODO: Consider using openssl for key validation
bool checkRSApublicKey(const std::string& rsaPublicKey) {
    const std::string keyBeg = "-----BEGIN PUBLIC KEY-----";
    const std::string keyEnd = "-----END PUBLIC KEY-----";

    auto posbeg = rsaPublicKey.find(keyBeg);
    if (posbeg != 0) {
        return false;
    }

    auto posend = rsaPublicKey.find(keyEnd);
    if (posend == std::string::npos) {
        return false;
    }

    std::size_t encodingLength = 0;
    for(size_t i = keyBeg.length(); i < posend; ++i)
    {
        if (rsaPublicKey[i] != '\n' && rsaPublicKey[i] != ' ')
        {
            ++encodingLength;
        }
    }

//    // RSA 1024
//    if (encodingLength == 216) {
//        return true;
//    }

    //TODO: Consider enabling other key lengths

    // RSA 2048
    if (encodingLength == 392) {
        return true;
    }

//    // RSA 4096
//    if (encodingLength == 736) {
//        return true;
//    }

    return false;
}
