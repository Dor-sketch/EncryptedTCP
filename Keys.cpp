#include "Keys.hpp"

#include <iomanip>  // for setfill ETC
#include <iostream>

std::string RSAPrivateWrapper::getPrivateKeyString() const
{
    return private_key_;
}

std::string RSAPrivateWrapper::getPublicKeyString() const
{
    return public_key_;
}

RSAPrivateWrapper::RSAPrivateWrapper()
    : public_key_(""),
      private_key_(""),
      _rng(std::make_unique<CryptoPP::AutoSeededRandomPool>()),
      _privateKey(std::make_unique<CryptoPP::RSA::PrivateKey>())
{
    _privateKey->Initialize(*_rng, BITS);  // Dereference the unique_ptr
    public_key_ = getPublicKey();
    private_key_ = getPrivateKey();
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string &public_key,
                                     const std::string &private_key)
    : public_key_(public_key), private_key_(private_key)
{
}

RSAPrivateWrapper::RSAPrivateWrapper(const char *key, unsigned int length)
{
    CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(key),
                              length, true);
    _privateKey->Load(ss);
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string &key)
{
    CryptoPP::StringSource ss(key, true);
    _privateKey->Load(ss);
}

RSAPrivateWrapper::~RSAPrivateWrapper()
{
    delete _privateKey.release();
    delete _rng.release();
}

std::string RSAPrivateWrapper::getPrivateKey() const
{
    std::string key;
    CryptoPP::StringSink ss(key);
    _privateKey->Save(ss);
    return key;
}

char *RSAPrivateWrapper::getPrivateKey(char *keyout, unsigned int length) const
{
    CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte *>(keyout), length);
    _privateKey->Save(as);
    return keyout;
}

std::string RSAPrivateWrapper::getPublicKey() const
{
    CryptoPP::RSAFunction publicKey(*_privateKey);
    std::string key;
    CryptoPP::StringSink ss(key);
    publicKey.Save(ss);
    return key;
}

char *RSAPrivateWrapper::getPublicKey(char *keyout, unsigned int length) const
{
    CryptoPP::RSAFunction publicKey(*_privateKey);
    CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte *>(keyout), length);
    publicKey.Save(as);
    return keyout;
}

#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/rsa.h>

#include <stdexcept>

CryptoPP::RSA::PrivateKey loadPrivateKeyFromBase64(const std::string &base64Key)
{
    CryptoPP::RSA::PrivateKey privateKey;

    // Remove the PEM-like header and footer, decode from Base64
    std::string keyStr = base64Key;
    CryptoPP::StringSource ss(keyStr, true, new CryptoPP::Base64Decoder);

    // Load private key
    privateKey.BERDecodePrivateKey(ss, false,
                                   static_cast<size_t>(ss.MaxRetrievable()));
    if (!privateKey.Validate(CryptoPP::NullRNG(), 3))
    {
        throw std::runtime_error("Failed to load private key from base64");
    }

    return privateKey;
}

#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

std::string decryptAESKey(const CryptoPP::RSA::PrivateKey &privateKey,
                          const std::string &encryptedKeyHex)
{
    CryptoPP::AutoSeededRandomPool rng;

    std::vector<unsigned char> encryptedKey;
    for (size_t i = 0; i < encryptedKeyHex.size(); i += 2)
    {
        std::string byteString = encryptedKeyHex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(
            std::strtol(byteString.c_str(), nullptr, 16));
        encryptedKey.push_back(byte);
    }

    std::string decrypted;
    try
    {
        CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);
        CryptoPP::StringSource(
            encryptedKey.data(), encryptedKey.size(), true,
            new CryptoPP::PK_DecryptorFilter(
                rng, d, new CryptoPP::StringSink(decrypted)));
    }
    catch (const CryptoPP::Exception &e)
    {
        throw std::runtime_error("Failed to decrypt AES key");
    }

    return decrypted;
}
