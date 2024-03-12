# pragma once

#include <cryptopp/aes.h>
#include <cryptopp/crc.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

#include <tuple>

using CryptoPP::byte;

class FileEncryptor
{
public:
    FileEncryptor(const std::string &keyHex, const std::string &inputFileName);
    void decryptToFile(const std::string &cipherText,
                       const std::string &outputFileName);
    std::string decryptString(const std::string &encryptedContent);
    std::tuple<std::string, uint32_t> encryptAndComputeCRC();

private:
    CryptoPP::byte key_[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv_[CryptoPP::AES::BLOCKSIZE];
    std::string inputFileName_;

    std::string decryptToString(const std::string &cipherText, const byte *key,
                                const byte *iv);

};
