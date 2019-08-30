#include "message_utils.h"

//TODO: Consider using openssl for key validation
bool checkRSApublicKey(const std::string& rsaPublicKey) {
    const std::string keyBeg = "-----BEGIN PUBLIC KEY-----\n";
    const std::string keyEnd = "-----END PUBLIC KEY-----";

    auto posbeg = rsaPublicKey.find(keyBeg);
    if (posbeg != 0) {
        return false;
    }

    auto posend = rsaPublicKey.find(keyEnd);
    if (posend == std::string::npos) {
        return false;
    }
    std::size_t encodingLength = posend - keyBeg.length();

//    // RSA 1024
//    if (encodingLength == 220) {
//        return true;
//    }

    //TODO: Consider enabling other key lengths

    // RSA 2048
    if (encodingLength == 399) {
        return true;
    }

//    // RSA 4096
//    if (encodingLength == 748) {
//        return true;
//    }

    return false;
}
