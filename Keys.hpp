#pragma once
// TODO:: Refractor this module
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <memory>
#include <string>

class Base64Wrapper
{
public:
    static std::string encode(const std::string &str);
    static std::string decode(const std::string &str);

private:
    static std::string base64_encode(const unsigned char *buffer,
                                     size_t length);
};

class RSAPrivateWrapper
{
public:
    static const unsigned int BITS = 1024;

    RSAPrivateWrapper();
    RSAPrivateWrapper(const std::string &public_key,
                      const std::string &private_key);
    RSAPrivateWrapper(const char *key, unsigned int length);
    explicit RSAPrivateWrapper(const std::string &key);
    ~RSAPrivateWrapper();

    std::string getPublicKeyString() const;
    std::string getPrivateKeyString() const;
    void loadPrivateKey(const std::string &key);
    void loadPublicKey(const std::string &key);
    std::string getPrivateKey() const;
    char *getPrivateKey(char *keyout, unsigned int length) const;
    std::string getPublicKey() const;
    char *getPublicKey(char *keyout, unsigned int length) const;
    std::string decrypt(const std::string &cipher);
    std::string decrypt(const char *cipher, unsigned int length);

private:
    std::string public_key_;
    std::string private_key_;  // stored in priv.key file
    std::unique_ptr<CryptoPP::AutoSeededRandomPool> _rng;
    std::unique_ptr<CryptoPP::RSA::PrivateKey> _privateKey;

    // Disallow copy and assignment
    RSAPrivateWrapper(const RSAPrivateWrapper &rsaprivate) = delete;
    RSAPrivateWrapper &operator=(const RSAPrivateWrapper &rsaprivate) = delete;
};
