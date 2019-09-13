// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/crypter.h>

#include <crypto/aes.h>
#include <crypto/sha512.h>
#include <script/script.h>
#include <script/standard.h>
#include <messages/message_encryption.h>
#include <util.h>
#include <random.h>

#include <string>
#include <vector>
#include <algorithm>

int CCrypter::BytesToKeySHA512AES(const std::vector<unsigned char>& chSalt, const SecureString& strKeyData, int count, unsigned char *key,unsigned char *iv) const
{
    // This mimics the behavior of openssl's EVP_BytesToKey with an aes256cbc
    // cipher and sha512 message digest. Because sha512's output size (64b) is
    // greater than the aes256 block size (16b) + aes256 key size (32b),
    // there's no need to process more than once (D_0).

    if(!count || !key || !iv)
        return 0;

    unsigned char buf[CSHA512::OUTPUT_SIZE];
    CSHA512 di;

    di.Write((const unsigned char*)strKeyData.c_str(), strKeyData.size());
    di.Write(chSalt.data(), chSalt.size());
    di.Finalize(buf);

    for(int i = 0; i != count - 1; i++)
        di.Reset().Write(buf, sizeof(buf)).Finalize(buf);

    memcpy(key, buf, WALLET_CRYPTO_KEY_SIZE);
    memcpy(iv, buf + WALLET_CRYPTO_KEY_SIZE, WALLET_CRYPTO_IV_SIZE);
    memory_cleanse(buf, sizeof(buf));
    return WALLET_CRYPTO_KEY_SIZE;
}

bool CCrypter::SetKeyFromPassphrase(const SecureString& strKeyData, const std::vector<unsigned char>& chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
    if (nDerivationMethod == 0)
        i = BytesToKeySHA512AES(chSalt, strKeyData, nRounds, vchKey.data(), vchIV.data());

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(vchKey.data(), vchKey.size());
        memory_cleanse(vchIV.data(), vchIV.size());
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial& chNewKey, const std::vector<unsigned char>& chNewIV)
{
    if (chNewKey.size() != WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != WALLET_CRYPTO_IV_SIZE)
        return false;

    memcpy(vchKey.data(), chNewKey.data(), chNewKey.size());
    memcpy(vchIV.data(), chNewIV.data(), chNewIV.size());

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char> &vchCiphertext) const
{
    if (!fKeySet)
        return false;

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCKSIZE bytes
    vchCiphertext.resize(vchPlaintext.size() + AES_BLOCKSIZE);

    AES256CBCEncrypt enc(vchKey.data(), vchIV.data(), true);
    size_t nLen = enc.Encrypt(&vchPlaintext[0], vchPlaintext.size(), vchCiphertext.data());
    if(nLen < vchPlaintext.size())
        return false;
    vchCiphertext.resize(nLen);

    return true;
}

bool CCrypter::Decrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext) const
{
    if (!fKeySet)
        return false;

    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = vchCiphertext.size();

    vchPlaintext.resize(nLen);

    AES256CBCDecrypt dec(vchKey.data(), vchIV.data(), true);
    nLen = dec.Decrypt(vchCiphertext.data(), vchCiphertext.size(), &vchPlaintext[0]);
    if(nLen == 0)
        return false;
    vchPlaintext.resize(nLen);
    return true;
}


static bool EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial &vchPlaintext, const uint256& nIV, std::vector<unsigned char> &vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(chIV.data(), &nIV, WALLET_CRYPTO_IV_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt(*((const CKeyingMaterial*)&vchPlaintext), vchCiphertext);
}

static bool EncryptMessengerSecret(
    const CKeyingMaterial& vMasterKey,
    const CKeyingMaterial &vchPlaintext,
    const std::vector<unsigned char> msgIV,
    std::vector<unsigned char> &vchCiphertext)
{
    ///TODO: Review this implementation
    CCrypter cKeyCrypter;
    if(!cKeyCrypter.SetKey(vMasterKey, msgIV))
        return false;
    return cKeyCrypter.Encrypt(*((const CKeyingMaterial*)&vchPlaintext), vchCiphertext);
}

static bool DecryptSecret(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCiphertext, const uint256& nIV, CKeyingMaterial& vchPlaintext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(chIV.data(), &nIV, WALLET_CRYPTO_IV_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}

static bool DecryptMessengerSecret(
    const CKeyingMaterial& vMasterKey,
    const std::vector<unsigned char>& cryptedKeys,
    const std::vector<unsigned char>& msgIV,
    CKeyingMaterial& vchPlaintext)
{
    CCrypter cKeyCrypter;
    if(!cKeyCrypter.SetKey(vMasterKey, msgIV))
        return false;
    return cKeyCrypter.Decrypt(cryptedKeys, *((CKeyingMaterial*)&vchPlaintext));
}

static bool AssignMessengerKeys(
    const CKeyingMaterial& plaintextKeys,
    MessengerKey& privMsgKey,
    MessengerKey& pubMsgKey)
{
    const std::string privBeg = "-----BEGIN RSA PRIVATE KEY-----";
    const std::string privEnd = "-----END RSA PRIVATE KEY-----";

    auto posBeg = std::search(plaintextKeys.begin(), plaintextKeys.end(), privBeg.begin(), privBeg.end());
    if (posBeg != plaintextKeys.begin()) {
        return false;
    }
    auto posEnd = std::search(posBeg+privBeg.size(), plaintextKeys.end(), privEnd.begin(), privEnd.end());
    if (posEnd == plaintextKeys.end()) {
        return false;
    }
    posEnd += privEnd.size();
    privMsgKey.assign(posBeg, posEnd);


    const std::string pubBeg = "-----BEGIN PUBLIC KEY-----";
    const std::string pubEnd = "-----END PUBLIC KEY-----";

    posBeg = std::search(posEnd, plaintextKeys.end(), pubBeg.begin(), pubBeg.end());
    if (posBeg == plaintextKeys.end()) {
        return false;
    }
    posEnd = std::search(posBeg + pubBeg.size(), plaintextKeys.end(), pubEnd.begin(), pubEnd.end());
    if (posEnd == plaintextKeys.end()) {
        return false;
    }
    posEnd += pubEnd.size();
    pubMsgKey.assign(posBeg, posEnd);

    return true;
}

static bool DecryptMessengerKeys(
    const CKeyingMaterial& vMasterKey,
    const std::vector<unsigned char>& cryptedKey,
    const std::vector<unsigned char>& msgIv,
    MessengerKey& privMsgKey,
    MessengerKey& pubMsgKey)
{
    ///TODO: review this implementation

    CKeyingMaterial plaintextKeys;
    if(!DecryptMessengerSecret(vMasterKey, cryptedKey, msgIv, plaintextKeys)) {
         return false;
    }

    if(!AssignMessengerKeys(plaintextKeys, privMsgKey, pubMsgKey)) {
        return false;
    }

    return matchRSAKeys(std::string(pubMsgKey.begin(), pubMsgKey.end()),
                        std::string(privMsgKey.begin(), privMsgKey.end()));
}

static bool DecryptKey(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCryptedSecret, const CPubKey& vchPubKey, CKey& key)
{
    CKeyingMaterial vchSecret;
    if(!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
        return false;

    if (vchSecret.size() != 32)
        return false;

    key.Set(vchSecret.begin(), vchSecret.end(), vchPubKey.IsCompressed());
    return key.VerifyPubKey(vchPubKey);
}

bool CCryptoKeyStore::SetCrypted()
{
    LOCK(cs_KeyStore);
    if (fUseCrypto)
        return true;
    if (!mapKeys.empty())
        return false;
    fUseCrypto = true;
    return true;
}

bool CCryptoKeyStore::SetMsgCrypted()
{
    ///TODO: Review
    LOCK(cs_KeyStore);
    if (fMsgUseCrypto)
        return true;

    if (!messengerPrivateKey.empty() || !messengerPrivateKey.empty())
        return false;
    fMsgUseCrypto = true;
    return true;
}

bool CCryptoKeyStore::IsLocked() const
{
    if (!IsCrypted()) {
        return false;
    }
    LOCK(cs_KeyStore);
    return vMasterKey.empty();
}

bool CCryptoKeyStore::Lock()
{
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
    }

    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::IsMsgLocked() const
{
    ///TODO: Review implementation
    if (!IsMsgCrypted()) {
        return false;
    }
    LOCK(cs_KeyStore);
    return vMessengerMasterKey.empty();
}

bool CCryptoKeyStore::MsgLock()
{
    if (!SetMsgCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMessengerMasterKey.clear();
    }

    NotifyMessengerStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        bool keyPass = false;
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(vMasterKeyIn, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            assert(false);
        }
        if (keyFail || !keyPass)
            return false;
        vMasterKey = vMasterKeyIn;
        fDecryptionThoroughlyChecked = true;
    }
    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::MsgUnlock(const CKeyingMaterial& vMasterKeyIn)
{
    ///TODO: Review this implementation
    {
        LOCK(cs_KeyStore);
        if (!SetMsgCrypted())
            return false;

        MessengerKey privMsgKey, pubMsgKey;
        if (!DecryptMessengerKeys(vMasterKeyIn, cryptedMessengerKeys, messengerKeyIV, privMsgKey, pubMsgKey))
        {
            LogPrintf("The messenger wallet is probably corrupted\n");
            assert(false);
        }

        vMessengerMasterKey = vMasterKeyIn;
    }

    NotifyMessengerStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::AddKeyPubKey(key, pubkey);
    }

    if (IsLocked()) {
        return false;
    }

    std::vector<unsigned char> vchCryptedSecret;
    CKeyingMaterial vchSecret(key.begin(), key.end());
    if (!EncryptSecret(vMasterKey, vchSecret, pubkey.GetHash(), vchCryptedSecret)) {
        return false;
    }

    if (!AddCryptedKey(pubkey, vchCryptedSecret)) {
        return false;
    }
    return true;
}


bool CCryptoKeyStore::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    if (!SetCrypted()) {
        return false;
    }

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool CCryptoKeyStore::SetMessengerKeys(const MessengerKey &privKey, const MessengerKey &pubKey)
{
    LOCK(cs_KeyStore);
    if (!IsMsgCrypted()) {
        return CBasicKeyStore::SetMessengerKeys(privKey, pubKey);
    }

    if (IsMsgLocked()) {
        return false;
    }

    ///TODO: Implement the rest of this function like  CCryptoKeyStore::AddKeyPubKey
    return true;
}

bool CCryptoKeyStore::AddMessengerCryptedKey(
    const std::vector<unsigned char> &cryptedPrivKey,
    const std::vector<unsigned char> &iv)
{
    LOCK(cs_KeyStore);
    if (!SetMsgCrypted()) {
        return false;
    }

    cryptedMessengerKeys = cryptedPrivKey;
    messengerKeyIV = iv;
    return true;
}

bool CCryptoKeyStore::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::HaveKey(address);
    }
    return mapCryptedKeys.count(address) > 0;
}

bool CCryptoKeyStore::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return DecryptKey(vMasterKey, vchCryptedSecret, vchPubKey, keyOut);
    }
    return false;
}

bool CCryptoKeyStore::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted())
        return CBasicKeyStore::GetPubKey(address, vchPubKeyOut);

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return CBasicKeyStore::GetPubKey(address, vchPubKeyOut);
}

bool CCryptoKeyStore::GetMessengerKeys(std::string& privMsgKeyStr, std::string& pubMsgKeyStr) const
{
    LOCK(cs_KeyStore);
    if (!IsMsgCrypted()) {
        std::cout << "Messenger not encrypted - getting keys from memory\n";
        return CBasicKeyStore::GetMessengerKeys(privMsgKeyStr, pubMsgKeyStr);
    }

    MessengerKey privMsgKey, pubMsgKey;
    if (!DecryptMessengerKeys(vMasterKey, cryptedMessengerKeys, messengerKeyIV, privMsgKey, pubMsgKey)) {
        std::cout << "Messenger encrypted, but not unlocked - no keys\n";
        return false;
    }

    privMsgKeyStr.assign(privMsgKey.begin(), privMsgKey.end());
    pubMsgKeyStr.assign(pubMsgKey.begin(), pubMsgKey.end());

    std::cout << "Messenger encrypted - decrypted keys correctly\n";
    return true;
}

std::set<CKeyID> CCryptoKeyStore::GetKeys() const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::GetKeys();
    }
    std::set<CKeyID> set_address;
    for (const auto& mi : mapCryptedKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

bool CCryptoKeyStore::EncryptKeys(CKeyingMaterial& vMasterKeyIn)
{
    LOCK(cs_KeyStore);
    if (!mapCryptedKeys.empty() || IsCrypted())
        return false;

    fUseCrypto = true;
    for (const KeyMap::value_type& mKey : mapKeys)
    {
        const CKey &key = mKey.second;
        CPubKey vchPubKey = key.GetPubKey();
        CKeyingMaterial vchSecret(key.begin(), key.end());
        std::vector<unsigned char> vchCryptedSecret;
        if (!EncryptSecret(vMasterKeyIn, vchSecret, vchPubKey.GetHash(), vchCryptedSecret))
            return false;
        if (!AddCryptedKey(vchPubKey, vchCryptedSecret))
            return false;
    }
    mapKeys.clear();
    return true;
}

bool CCryptoKeyStore::EncryptMessengerKeys(CKeyingMaterial& vMasterKeyIn)
{
    ///TODO: Implement
    LOCK(cs_KeyStore);
    if (!cryptedMessengerKeys.empty() || !messengerKeyIV.empty() || IsMsgCrypted()) {
        return false;
    }

    fMsgUseCrypto = true;

    CKeyingMaterial messengerKeyData(messengerPrivateKey.begin(), messengerPrivateKey.end());
    messengerKeyData.insert(messengerKeyData.end(), messengerPublicKey.begin(), messengerPublicKey.end());

    std::vector<unsigned char> msgIV(WALLET_CRYPTO_IV_SIZE);
    GetStrongRandBytes(&msgIV[0], WALLET_CRYPTO_IV_SIZE);

    std::vector<unsigned char> cryptedMessengerSecret;
    if (!EncryptMessengerSecret(vMasterKeyIn, messengerKeyData, msgIV, cryptedMessengerSecret)) {
        return false;
    }
    if (!AddMessengerCryptedKey(cryptedMessengerSecret, msgIV)) {
        return false;
    }

    messengerPrivateKey.clear();
    messengerPublicKey.clear();
    return true;
}
